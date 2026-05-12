#!/usr/bin/env python

"""Imports nmap XML output into the database.

Parses nmap XML produced by netscans and portscans, stores HostScanDoc and
PortScanDoc records, manages port/host tickets, and transitions host state.

Requirements: FR-1.4, MR-2.8, AC-5.1, AC-5.2
"""

# Standard Python Libraries
import logging
from ipaddress import IPv4Address
from xml.sax import parse

# Third-party libraries
import netaddr

# cyhy-db models and enums
from cyhy_db.models import HostDoc, HostScanDoc, PortScanDoc, VulnScanDoc
from cyhy_db.models.enum import Protocol, Stage

# Local modules
from .. import db_ops
from ..ticket_manager import IPPortTicketManager, IPTicketManager

# Local nmap handler
from .nmap_handler import NmapContentHandler

UNKNOWN_OWNER = "UNKNOWN"
DEFAULT_OWNER = "FEDERAL"

RISKY_SERVICES_SOURCE_ID = 1  # Identifier for "risky service" tickets
# Pulled from https://svn.nmap.org/nmap/nmap-services
RISKY_SERVICES = [
    "ftp",
    "irc",
    "kerberos",
    "kerberos-adm",
    "kerberos-sec",
    "kerberos_master",
    "klogin",
    "kpasswd5",
    "kpasswd",
    "krb_prop",
    "krbupdate",
    "kshell",
    "ldap",
    "microsoft-ds",
    "ms-sql-s",
    "ms-wbt-server",
    "msrpc",
    "netbios-dgm",
    "netbios-ns",
    "netbios-ssn",
    "sql-net",
    "sqlnet",
    "sqlsrv",
    "telnet",
]


class NmapImporter(object):
    SOURCE = "nmap"

    def __init__(self, stage=Stage.PORTSCAN):
        self.__logger = logging.getLogger(__name__)
        if stage in (Stage.NETSCAN1, Stage.NETSCAN2):
            self.__ticket_manager = IPTicketManager()
        elif stage == Stage.PORTSCAN:
            self.__ticket_manager = IPPortTicketManager()
        else:
            raise ValueError(f"Unsupported stage for NmapImporter: {stage}")
        self.__stage = stage
        # Parsed hosts collected during SAX parsing for async processing
        self.__parsed_hosts: list[dict] = []
        self.__parse_ended: bool = False

    def __host_callback(self, parsed_host):
        """SAX callback: collect parsed host data for async processing."""
        self.__parsed_hosts.append(parsed_host)

    def __end_callback(self):
        """SAX callback: mark end of parse."""
        self.__parse_ended = True

    async def process(self, nmap_filename, target_filename):
        """Import nmap files created from netscans and portscans."""
        # Reset state for this parse run
        self.__parsed_hosts = []
        self.__parse_ended = False

        # Create handler with synchronous collection callbacks
        handler = NmapContentHandler(self.__host_callback, self.__end_callback)

        # Parse nmap data synchronously (SAX is blocking)
        with open(nmap_filename, "rb") as f:
            # Sometimes the first line of the nmap output is not xml
            first_line = f.readline()
            if first_line.startswith(b"<?xml"):
                f.seek(0)
            parse(f, handler)

        # Now process all collected hosts asynchronously
        if self.__stage in (Stage.NETSCAN1, Stage.NETSCAN2):
            await self.__process_netscan_hosts()
        elif self.__stage == Stage.PORTSCAN:
            await self.__process_portscan_hosts()

    async def __process_netscan_hosts(self):
        """Process all parsed hosts from a netscan asynchronously."""
        ips_to_reset_latest: list[str] = []

        for parsed_host in self.__parsed_hosts:
            ip = netaddr.IPAddress(parsed_host["addr"])
            ip_str = str(ip)
            up = parsed_host["state"] == "up"

            if not up:
                # Since the host is down, clear latest flags for all previous
                # scan documents; tickets will be closed below.
                ips_to_reset_latest.append(ip_str)

            await db_ops.transition_host(
                ip=ip_str,
                up=up,
                reason=parsed_host["state_reason"],
            )

        # Clear latest flags for down hosts
        if ips_to_reset_latest:
            await HostScanDoc.reset_latest_flag_by_ip(ips_to_reset_latest)
            await PortScanDoc.reset_latest_flag_by_ip(ips_to_reset_latest)
            await VulnScanDoc.reset_latest_flag_by_ip(ips_to_reset_latest)

            # Close host-level tickets for all down hosts
            for ip_str in ips_to_reset_latest:
                await self.__ticket_manager.process_tickets(
                    ip=ip_str,
                    is_up=False,
                )

    async def __process_portscan_hosts(self):
        """Process all parsed hosts from a portscan asynchronously."""
        for parsed_host in self.__parsed_hosts:
            ip = parsed_host["addr"]
            ip_str = str(ip)

            # Clear previous latest flags as we are about to create new docs
            await HostScanDoc.reset_latest_flag_by_ip(ip_str)
            await PortScanDoc.reset_latest_flag_by_ip(ip_str)

            open_port_docs = await self.__store_port_details(parsed_host)
            await self.__store_os_details(parsed_host)

            has_at_least_one_open_port = len(open_port_docs) > 0

            await db_ops.transition_host(
                ip=ip_str,
                up=True,
                reason="syn-ack",
                has_open_ports=has_at_least_one_open_port,
            )

            # Process port tickets for this host (full scan)
            await self.__ticket_manager.process_tickets(
                ip=ip_str,
                open_ports=open_port_docs,
                is_full_scan=True,
            )

    async def __store_port_details(self, parsed_host) -> list[PortScanDoc]:
        """Store PortScanDoc records for each open port on the host.

        Returns a list of PortScanDoc objects for open ports.
        """
        ip = parsed_host["addr"]
        ip_addr = IPv4Address(str(ip))

        host_doc = await HostDoc.find_one(HostDoc.ip == ip_addr)
        if host_doc:
            ip_owner = host_doc.owner
        else:
            self.__logger.warning("No HostDoc found for IP %s", str(ip))
            ip_owner = UNKNOWN_OWNER

        open_port_docs: list[PortScanDoc] = []

        for port, details in parsed_host["ports"].items():
            if details["state"] != "open":  # only storing open ports
                continue
            if details.get("service", {}).get("name") == "tcpwrapped":
                # tcpwrapped services are "silent", not really open ports
                # see https://secwiki.org/w/FAQ_tcpwrapped
                details["state"] = "silent"
            else:
                # Resolve protocol enum
                protocol_str = details.get("protocol", "tcp").lower()
                try:
                    protocol = Protocol(protocol_str)
                except ValueError:
                    protocol = Protocol.TCP

                port_doc = PortScanDoc(
                    ip=ip_addr,
                    ip_int=int(ip_addr),
                    owner=ip_owner,
                    source=NmapImporter.SOURCE,
                    time=parsed_host["endtime"],
                    latest=True,
                    port=int(port),
                    protocol=protocol,
                    state=details["state"],
                    reason=details.get("reason", ""),
                    service=details.get("service", {}),
                )
                await port_doc.save()
                open_port_docs.append(port_doc)

                # Check for risky services
                if details.get("service", {}).get("name") in RISKY_SERVICES:
                    if ip_owner not in (DEFAULT_OWNER, UNKNOWN_OWNER):
                        self.__logger.info(
                            "Potentially risky service detected: %s on %s:%d",
                            details["service"]["name"],
                            str(ip_addr),
                            int(port),
                        )

        return open_port_docs

    async def __store_os_details(self, parsed_host):
        """Store a HostScanDoc record for the host's OS detection results."""
        ip = parsed_host["addr"]
        ip_addr = IPv4Address(str(ip))

        host_doc = await HostDoc.find_one(HostDoc.ip == ip_addr)
        if host_doc:
            ip_owner = host_doc.owner
        else:
            ip_owner = UNKNOWN_OWNER

        if "os" in parsed_host:
            os_data = parsed_host["os"]
            accuracy = int(os_data.get("accuracy", 0))
            name = os_data.get("name", "unknown")
            line = int(os_data.get("line", 0))
            classes = os_data.get("classes", [])
        else:
            accuracy = 0
            name = "unknown"
            line = 0
            classes = []

        host_scan = HostScanDoc(
            ip=ip_addr,
            ip_int=int(ip_addr),
            owner=ip_owner,
            source=NmapImporter.SOURCE,
            time=parsed_host["endtime"],
            latest=True,
            accuracy=accuracy,
            name=name,
            line=line,
            classes=classes,
        )
        await host_scan.save()
