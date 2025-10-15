#!/usr/bin/env python

# built-in python libraries
import logging
from xml.sax import parse

# third-party libraries (install with pip)
import netaddr

# local libraries
from cyhy.core import DEFAULT_OWNER, STAGE, UNKNOWN_OWNER
from cyhy.db import CHDatabase, IPPortTicketManager, IPTicketManager
from cyhy.util import util
from nmap_handler import NmapContentHandler

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

"""
Imports nmap xml output into the database
"""


class NmapImporter(object):
    SOURCE = "nmap"

    def __init__(self, db, stage=STAGE.PORTSCAN):
        self.__logger = logging.getLogger(__name__)
        if stage in (STAGE.NETSCAN1, STAGE.NETSCAN2):
            self.handler = NmapContentHandler(
                self.__netscan_host_callback, self.__end_callback
            )
            self.__ticket_manager = IPTicketManager(db)
        elif stage == STAGE.PORTSCAN:
            self.handler = NmapContentHandler(
                self.__portscan_host_callback, self.__end_callback
            )
            self.__ticket_manager = IPPortTicketManager(
                db, ["tcp"]
            )  # Nmap is only scanning TCP ports; don't close non-TCP ports.
            self.__ticket_manager.ports = xrange(
                1, 65536
            )  # A PORTSCAN is all ports.  Don't consider port 0 in scope.
        elif stage == STAGE.BASESCAN:
            self.handler = NmapContentHandler(
                self.__baseline_host_callback, self.__end_callback
            )
            self.__ticket_manager = None
        self.__db = db
        self.__ch_db = CHDatabase(db)
        self.__ips_to_reset_latest = []

    def process(self, nmap_filename, target_filename):
        """Imports nmap files created from netscans and portscans"""
        # import target ips
        ips = netaddr.IPSet()
        with open(target_filename) as f:
            for ip_line in f:
                self.__ticket_manager.ips.add(ip_line)
        # parse nmap data
        f = open(nmap_filename, "rb")
        # sometimes the first line of the nmap output is not xml
        firstLine = f.readline()
        if firstLine.startswith("<?xml"):
            f.seek(0)
        parse(f, self.handler)
        f.close()

    def __store_port_details(self, parsed_host):
        has_at_least_one_open_port = False
        ip = parsed_host["addr"]
        host_doc = self.__db.HostDoc.get_by_ip(ip)
        if host_doc:
            ip_owner = host_doc.get("owner", UNKNOWN_OWNER)
        else:
            ip_owner = None
        for (port, details) in parsed_host["ports"].items():
            if details["state"] != "open":  # only storing open ports
                continue
            if (
                details.get("service", {}).get("name") == "tcpwrapped"
            ):  # see https://secwiki.org/w/FAQ_tcpwrapped
                details[
                    "state"
                ] = "silent"  # tcpwrapped services are "silent", not really open ports
            else:
                has_at_least_one_open_port = True
                self.__ticket_manager.port_open(ip, port)
            details["port"] = port
            details["time"] = parsed_host["endtime"]
            details["source"] = NmapImporter.SOURCE
            details["latest"] = True

            if host_doc and host_doc.get("hostnames"):
                # Create a PortScanDoc for each hostname/owner combination
                for h in host_doc["hostnames"]:
                    report = self.__db.PortScanDoc()
                    util.copy_attrs(details, report)
                    report["owner"] = h.get("owner", UNKNOWN_OWNER)
                    report["hostname"] = h["hostname"]
                    report.ip = ip  # sets ip and ip_int
                    report.save()
                    if details.get("service", {}).get("name") in RISKY_SERVICES:
                        report["source_id"] = RISKY_SERVICES_SOURCE_ID
                        report[
                            "name"
                        ] = "Potentially Risky Service Detected: {}".format(
                            details["service"]["name"]
                        )
                        report["service"] = details["service"]["name"]
                        # Open a ticket for this hostname/owner combination
                        self.__ticket_manager.open_ticket(
                            report, "potentially risky service detected"
                        )
            else:
                # There are no hostnames in the HostDoc, so create a single
                # PortScanDoc with no hostname that is owned by the IP owner
                report = self.__db.PortScanDoc()
                util.copy_attrs(details, report)
                report["owner"] = ip_owner
                report["hostname"] = None
                report.ip = ip  # sets ip and ip_int
                report.save()
                if details.get("service", {}).get("name") in RISKY_SERVICES:
                    # If IP owner is known and is not the default owner, open a
                    # ticket
                    if ip_owner is not None and ip_owner not in [
                        DEFAULT_OWNER,
                        UNKNOWN_OWNER,
                    ]:
                        report["source_id"] = RISKY_SERVICES_SOURCE_ID
                        report[
                            "name"
                        ] = "Potentially Risky Service Detected: {}".format(
                            details["service"]["name"]
                        )
                        report["service"] = details["service"]["name"]
                        self.__ticket_manager.open_ticket(
                            report, "potentially risky service detected"
                        )
        return has_at_least_one_open_port

    def __store_os_details(self, parsed_host):
        details = dict()
        if parsed_host.has_key("os"):
            util.copy_attrs(parsed_host["os"], details)
            details["line"] = int(details["line"])
            details["accuracy"] = int(details["accuracy"])
        else:
            details["accuracy"] = 0
            details["name"] = "unknown"
        details["time"] = parsed_host["endtime"]
        details["source"] = NmapImporter.SOURCE
        details["latest"] = True

        ip = parsed_host["addr"]
        host_doc = self.__db.HostDoc.get_by_ip(ip)
        if host_doc and host_doc.get("hostnames"):
            # Create a HostScanDoc for each hostname/owner combination
            for h in host_doc["hostnames"]:
                host = self.__db.HostScanDoc()
                util.copy_attrs(details, host)
                host["owner"] = h.get("owner", UNKNOWN_OWNER)
                host["hostname"] = h["hostname"]
                host.ip = ip  # sets ip and ip_int
                host.save()
        else:
            # There are no hostnames in the HostDoc, so create a single
            # HostScanDoc and use the hostname nmap found (if any)
            host = self.__db.HostScanDoc()
            util.copy_attrs(details, host)
            if host_doc:
                host["owner"] = host_doc.get("owner", UNKNOWN_OWNER)
            else:
                host["owner"] = UNKNOWN_OWNER
            host["hostname"] = parsed_host.get("hostname", None)
            host.ip = ip  # sets ip and ip_int
            host.save()

    def __baseline_host_callback(self, parsed_host):
        self.__store_port_details(parsed_host)
        self.__store_os_details(parsed_host)
        ip = parsed_host["addr"]
        up = parsed_host["state"] == "up"
        self.__ch_db.transition_host(ip, up=up, reason=parsed_host["state_reason"])

    def __netscan_host_callback(self, parsed_host):
        ip = netaddr.IPAddress(parsed_host["addr"])
        up = parsed_host["state"] == "up"
        if up:
            # mark ip as up so that the correct tickets can be closed later
            self.__ticket_manager.ip_up(ip)
        else:
            # since the host is down, clear latest flags for all previous scan documents
            self.__ips_to_reset_latest.append(ip)
            # tickets will be closed at the end of the parse
        self.__ch_db.transition_host(ip, up=up, reason=parsed_host["state_reason"])

    def __portscan_host_callback(self, parsed_host):
        ip = parsed_host["addr"]
        # clear previous latest flags as we are about to create new docs
        self.__db.HostScanDoc.reset_latest_flag_by_ip(ip)
        self.__db.PortScanDoc.reset_latest_flag_by_ip(ip)
        has_at_least_one_open_port = self.__store_port_details(parsed_host)
        self.__store_os_details(parsed_host)
        self.__ch_db.transition_host(ip, has_open_ports=has_at_least_one_open_port)

    def __end_callback(self):
        # clear the latest flags compiled from __netscan_host_callback down
        self.__db.HostScanDoc.reset_latest_flag_by_ip(self.__ips_to_reset_latest)
        self.__db.PortScanDoc.reset_latest_flag_by_ip(self.__ips_to_reset_latest)
        self.__db.VulnScanDoc.reset_latest_flag_by_ip(self.__ips_to_reset_latest)
        # tell the ticket manager to close what needs to be closed
        self.__ticket_manager.close_tickets()
        self.__ticket_manager.clear_vuln_latest_flags()
