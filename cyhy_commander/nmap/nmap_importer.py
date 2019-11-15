#!/usr/bin/env python

from nmap_handler import NmapContentHander
from xml.sax import parse
import netaddr
from cyhy.core import STAGE
from cyhy.db import CHDatabase, IPPortTicketManager, IPTicketManager
from cyhy.util import util

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
        if stage in (STAGE.NETSCAN1, STAGE.NETSCAN2):
            self.handler = NmapContentHander(
                self.__netscan_host_callback, self.__end_callback
            )
            self.__ticket_manager = IPTicketManager(db)
        elif stage == STAGE.PORTSCAN:
            self.handler = NmapContentHander(
                self.__portscan_host_callback, self.__end_callback
            )
            self.__ticket_manager = IPPortTicketManager(
                db, ["tcp"]
            )  # Nmap is only scanning TCP ports; don't close non-TCP ports.
            self.__ticket_manager.ports = xrange(
                1, 65536
            )  # A PORTSCAN is all ports.  Don't consider port 0 in scope.
        elif stage == STAGE.BASESCAN:
            self.handler = NmapContentHander(
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
        time = parsed_host["endtime"]
        ip_owner = self.__db.HostDoc.get_owner_of_ip(ip)
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
            details["ip"] = ip
            details["ip_int"] = long(ip)
            details["port"] = port
            details["time"] = time
            details["source"] = NmapImporter.SOURCE
            details["owner"] = ip_owner
            details["latest"] = True
            report = self.__db.PortScanDoc()
            util.copy_attrs(details, report)
            report.save()
        return has_at_least_one_open_port

    def __store_os_details(self, parsed_host):
        host = self.__db.HostScanDoc()
        if parsed_host.has_key("os"):
            util.copy_attrs(parsed_host["os"], host)
            host["line"] = int(host["line"])
            host["accuracy"] = int(host["accuracy"])
        else:
            host["accuracy"] = 0
            host["name"] = "unknown"
        ip = parsed_host["addr"]
        hostname = parsed_host.get("hostname", None)
        ip_owner = self.__db.HostDoc.get_owner_of_ip(ip)
        host["owner"] = ip_owner
        time = parsed_host["endtime"]
        host.ip = ip  # sets ip and ip_int
        host["hostname"] = hostname
        host["time"] = time
        host["source"] = NmapImporter.SOURCE
        host["latest"] = True
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
