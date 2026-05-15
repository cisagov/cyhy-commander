#!/usr/bin/env python

"""Imports Nessus XML scan results into the database.

Parses Nessus v2 XML produced by vulnerability scans, stores VulnScanDoc
records, manages vulnerability tickets, and transitions host state.

Requirements: FR-1.4, MR-2.8, AC-5.3
"""

# Standard Python Libraries
import logging
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import Any

# Third-party libraries
import netaddr  # type: ignore[import-untyped]

# cyhy-db models and enums
from cyhy_db.models import HostDoc, VulnScanDoc
from cyhy_db.models.enum import Protocol
from cyhy_logging import CYHY_ROOT_LOGGER
from defusedxml.sax import parse  # type: ignore[import-untyped]

# Local modules
from .. import db_ops
from ..ticket_manager import VulnTicketManager

# Local nessus handler
from .nessus_handler import NessusV2ContentHander

UNKNOWN_OWNER = "UNKNOWN"


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _range_string_to_list(port_range_string: str) -> list[int]:
    """Convert a port range string (e.g. '1-1024,8080') to a list of ints.

    Args:
        port_range_string: A comma-separated list of port numbers or ranges
            (e.g. '22,80,443,1000-2000').

    Returns:
        A sorted list of integer port numbers.
    """
    ports: list[int] = []
    for part in port_range_string.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start = int(start_str.strip())
            end = int(end_str.strip())
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(ports)


class NessusImporter:
    """Parses Nessus XML output and stores results in the database."""

    SOURCE = "nessus"

    def __init__(self, manual_scan: bool = False):
        """Create an importer to handle one Nessus file.

        Args:
            manual_scan: When set to True, hosts will not be transitioned
                to the next stage/status, and scan times are assumed to be now.
        """
        self.__logger = logging.getLogger(
            CYHY_ROOT_LOGGER + ".commander.nessus_importer"
        )
        self.__ticket_manager = VulnTicketManager()
        self.manual_scan = manual_scan

        # State tracked during SAX parsing (current host context)
        self._current_ip: netaddr.IPAddress | None = None
        self._current_ip_time: datetime | None = None

        # Collected parsed data for async processing
        # Each entry: dict with all parsedHost fields plus "_ip_str"
        self._parsed_hosts: list[dict[str, Any]] = []
        # Each entry: dict with all parsedReport fields plus "_ip_str" and "_end_time"
        self._parsed_reports: list[dict[str, Any]] = []

        # Targets collected from the policy section
        self._targets: netaddr.IPSet | None = None

    def _targets_callback(self, targets_string: str) -> None:
        """SAX callback: collect the list of scanned targets."""
        targets = targets_string.split(",")
        self._targets = netaddr.IPSet()
        for t in targets:
            # If any targets are a hostname and an IP address (e.g.
            # "foo.gov[192.168.1.1]"), extract the IP address.
            if "[" in t:
                parts = t.strip().split("[")
                if len(parts) == 2 and parts[1].endswith("]"):
                    t = parts[1][:-1]
                else:
                    self.__logger.warning(
                        "Skipping malformed target: '%s'", t.strip()
                    )
                    continue
            self._targets.add(netaddr.IPAddress(t))
        self.__logger.debug(
            "Found %d targets in Nessus file", len(self._targets)
        )

    def _plugin_set_callback(self, plugin_set_string: str) -> None:
        """SAX callback: collect the set of plugin IDs used in this scan."""
        string_list = plugin_set_string.split(";")
        if string_list[-1] == "":
            # list ends with ; creating a non-int empty string
            string_list.pop()
        plugin_set = {int(s) for s in string_list}
        self.__logger.debug(
            "Found %d plugin_ids in Nessus file", len(plugin_set)
        )

    def _port_range_callback(self, port_range_string: str) -> None:
        """SAX callback: collect the set of ports scanned."""
        if port_range_string == "default":
            # Match the base policy value found in /extras/policy.xml
            port_range_string = "1-65535"
        ports = set(_range_string_to_list(port_range_string))
        self.__logger.debug("Found %d ports in Nessus file", len(ports))

    def _host_callback(self, parsedHost: dict[str, Any]) -> None:
        """SAX callback: collect parsed host metadata and set current IP context."""
        # Some fragile hosts don't list their host_ip; fall back to name.
        if "host_ip" in parsedHost:
            ip = netaddr.IPAddress(parsedHost["host_ip"])
            del parsedHost["host_ip"]
        else:
            try:
                ip = netaddr.IPAddress(parsedHost["name"])
            except netaddr.AddrFormatError:
                # When parsedHost['name'] is not a valid IP (see CYHY-113)
                self.__logger.warning(
                    "Skipping vulnerability reports; invalid host IP detected: %s",
                    parsedHost["name"],
                )
                self._current_ip = None
                return

        self._current_ip = ip
        parsedHost["ip"] = ip
        parsedHost["_ip_str"] = str(ip)

        if not self.manual_scan:
            # Use the host's end_time as the scan time
            self._current_ip_time = parsedHost.get("end_time")

        self._parsed_hosts.append(parsedHost)

    def _report_callback(self, parsedReport: dict[str, Any]) -> None:
        """SAX callback: collect parsed vulnerability report, tagged with current IP."""
        # Not storing severity 0 reports
        if parsedReport["severity"] == 0:
            return
        if self._current_ip is None:
            self.__logger.warning(
                "No current IP; skipping vulnerability report: %s",
                parsedReport.get("plugin_name", "unknown"),
            )
            return
        # Tag the report with the current IP and scan time so we can
        # associate it with the correct host during async processing.
        parsedReport["_ip_str"] = str(self._current_ip)
        parsedReport["_scan_time"] = self._current_ip_time
        self._parsed_reports.append(parsedReport)

    def _end_callback(self) -> None:
        """SAX callback: end of parse (no-op; async processing done in process())."""
        pass

    async def process(self, filename: str, gzipped: bool = False) -> None:
        """Import a Nessus file into the database.

        Parses the Nessus XML synchronously (SAX is blocking), then processes
        all collected hosts and reports asynchronously.

        Args:
            filename: Path to the Nessus XML file.
            gzipped: If True, the file is gzip-compressed.
        """
        # Reset state for this parse run
        self._targets = None
        self._current_ip = None
        self._current_ip_time = None
        self._parsed_hosts = []
        self._parsed_reports = []

        if self.manual_scan:
            # For manual scan imports, assume current time for all hosts
            self._current_ip_time = _utcnow()

        self.__logger.debug("Starting processing of %s", filename)

        # Create handler with synchronous collection callbacks
        handler = NessusV2ContentHander(
            self._host_callback,
            self._report_callback,
            self._targets_callback,
            self._plugin_set_callback,
            self._port_range_callback,
            self._end_callback,
        )

        # Parse Nessus data synchronously (SAX is blocking)
        if gzipped:
            import gzip

            with gzip.open(filename, "r") as f:
                parse(f, handler)
        else:
            with open(filename) as f:
                parse(f, handler)

        # Now process all collected data asynchronously
        await self._process_hosts()

    async def _process_hosts(self) -> None:
        """Process all parsed hosts and their vulnerability reports asynchronously."""
        if self._targets is None:
            self.__logger.warning(
                "No targets found in Nessus file; nothing to process."
            )
            return

        # Build a lookup from IP string → parsed host metadata
        host_meta: dict[str, dict[str, Any]] = {}
        for ph in self._parsed_hosts:
            ip_str = ph.get("_ip_str")
            if ip_str:
                host_meta[ip_str] = ph

        # Group reports by IP address
        reports_by_ip: dict[str, list[dict[str, Any]]] = {}
        for report in self._parsed_reports:
            ip_str = report.get("_ip_str")
            if ip_str:
                reports_by_ip.setdefault(ip_str, []).append(report)

        # Process each target IP
        for target_ip in self._targets:
            ip_str = str(target_ip)
            ip_addr = IPv4Address(ip_str)

            # Look up the HostDoc to get owner
            host_doc = await HostDoc.find_one(HostDoc.ip == ip_addr)
            if host_doc:
                owner = host_doc.owner
            else:
                owner = UNKNOWN_OWNER
                self.__logger.warning(
                    "No HostDoc found for IP %s; using owner=%s",
                    ip_str,
                    UNKNOWN_OWNER,
                    extra={"host": ip_str, "stage": "VULNSCAN"},
                )

            # Determine scan time for this host
            parsed_host = host_meta.get(ip_str)
            if self.manual_scan:
                scan_time = self._current_ip_time or _utcnow()
            elif parsed_host and "end_time" in parsed_host:
                scan_time = parsed_host["end_time"]
            else:
                scan_time = _utcnow()

            # Clear previous latest flags for this IP before storing new docs
            await VulnScanDoc.reset_latest_flag_by_ip(ip_str)

            # Store VulnScanDoc records for each detected vulnerability
            vuln_docs: list[VulnScanDoc] = []
            for report in reports_by_ip.get(ip_str, []):
                vuln_doc = await self._store_vuln_report(
                    report=report,
                    ip_addr=ip_addr,
                    owner=owner,
                    scan_time=scan_time,
                )
                if vuln_doc is not None:
                    vuln_docs.append(vuln_doc)

            # Process vulnerability tickets for this host
            await self.__ticket_manager.process_tickets(
                ip=ip_str,
                detected_vulns=vuln_docs,
            )

            # Transition host state or reschedule
            if self.manual_scan:
                # For manual scans, update priority and reschedule without
                # transitioning stage/status
                if host_doc is not None:
                    from ..scheduler import DefaultScheduler

                    _scheduler = DefaultScheduler()
                    await _scheduler.schedule_host(host_doc)
                    await host_doc.save()
            else:
                # Move host out of RUNNING status (vulnscan complete, host is up)
                await db_ops.transition_host(
                    ip=ip_str,
                    up=True,
                    reason="vuln-scan-complete",
                )

        self.__logger.debug(
            "Completed Nessus import: %d targets, %d reports processed.",
            len(self._targets),
            len(self._parsed_reports),
            extra={"stage": "VULNSCAN"},
        )

    async def _store_vuln_report(
        self,
        report: dict[str, Any],
        ip_addr: IPv4Address,
        owner: str,
        scan_time: datetime,
    ) -> VulnScanDoc | None:
        """Create and save a VulnScanDoc from a parsed Nessus report.

        Args:
            report: The parsed report dict from NessusV2ContentHander.
            ip_addr: The IPv4Address of the scanned host.
            owner: The owner string for this host.
            scan_time: The datetime of the scan.

        Returns:
            The saved VulnScanDoc, or None if the report could not be stored.
        """
        # Resolve protocol enum
        protocol_str = report.get("protocol", "tcp").lower()
        try:
            protocol = Protocol(protocol_str)
        except ValueError:
            protocol = Protocol.TCP

        # Build VulnScanDoc with direct field assignment from parsedReport.
        # Fields required by VulnScanDoc that may be absent in the XML get
        # sensible defaults.
        try:
            vuln_doc = VulnScanDoc(
                ip=ip_addr,
                ip_int=int(ip_addr),
                owner=owner,
                source=NessusImporter.SOURCE,
                time=scan_time,
                latest=True,
                # VulnScanDoc-specific fields from parsedReport
                cvss_base_score=float(report.get("cvss_base_score", 0.0)),
                cvss_vector=report.get("cvss_vector", ""),
                description=report.get("description", ""),
                fname=report.get("fname", ""),
                plugin_family=report.get("plugin_family", ""),
                plugin_id=int(report.get("plugin_id", 0)),
                plugin_modification_date=report.get(
                    "plugin_modification_date", scan_time
                ),
                plugin_name=report.get("plugin_name", ""),
                plugin_publication_date=report.get(
                    "plugin_publication_date", scan_time
                ),
                plugin_type=report.get("plugin_type", ""),
                port=int(report.get("port", 0)),
                protocol=protocol,
                risk_factor=report.get("risk_factor", ""),
                service=report.get("service", ""),
                severity=int(report.get("severity", 0)),
                solution=report.get("solution", ""),
                synopsis=report.get("synopsis", ""),
            )
            await vuln_doc.save()
            return vuln_doc
        except Exception as e:
            self.__logger.error(
                "Failed to store VulnScanDoc for ip=%s plugin_id=%s: %s",
                ip_addr,
                report.get("plugin_id"),
                e,
                extra={"host": str(ip_addr), "stage": "VULNSCAN"},
            )
            return None
