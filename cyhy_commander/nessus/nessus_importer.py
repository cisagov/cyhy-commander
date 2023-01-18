#!/usr/bin/env python

from nessus_handler import NessusV2ContentHander
from xml.sax import parse
from bson.errors import InvalidDocument
import netaddr
import gzip
import logging
from cyhy.core import UNKNOWN_OWNER
from cyhy.db import CHDatabase, VulnTicketManager
from cyhy.util import util


"""
Imports scan-requests into the database.
This importer should handle the import of only one nessus file."""


class NessusImporter(object):
    SOURCE = "nessus"

    def __init__(self, db, manual_scan=False):
        """Create an importer to handle one Nessus file.

        Args:
            manual_scan: When set to True, hosts will not be transitioned
            to the next stage/status, and scan times are assumed to be now.

        """
        self.__logger = logging.getLogger(__name__)
        self.handler = NessusV2ContentHander(
            self.host_callback,
            self.report_callback,
            self.targets_callback,
            self.plugin_set_callback,
            self.port_range_callback,
            self.end_callback,
        )
        self.__db = db
        self.__ch_db = CHDatabase(db)
        self.current_host_owner = None
        self.current_hostname = None
        self.current_ip = None
        self.current_ip_int = None
        self.current_ip_time = None
        self.targets = None
        self.ticket_manager = VulnTicketManager(
            db, NessusImporter.SOURCE, manual_scan=manual_scan
        )
        self.attempted_to_clear_latest_flags = False
        self.manual_scan = manual_scan

    def process(self, filename, gzipped=False):
        self.__logger.debug("Starting processing of %s" % filename)
        if self.manual_scan:
            # if we are doing a manual scan import we have to assume a current time
            self.current_ip_time = util.utcnow()
        if gzipped:
            f = gzip.open(filename, "r")
        else:
            f = open(filename, "r")
        parse(f, self.handler)
        f.close()

    def __try_to_clear_latest_flags(self):
        # Once the ticket manager has all its information,
        # it can clear the previous latest flags
        if self.ticket_manager.ready_to_clear_vuln_latest_flags():
            self.__logger.debug(
                'Ticket manager IS READY to clear VulnScan "latest" flags'
            )
            self.ticket_manager.clear_vuln_latest_flags()
            self.attempted_to_clear_latest_flags = True
        else:
            self.__logger.debug(
                'Ticket manager IS NOT READY to clear VulnScan "latest" flags'
            )

    def targets_callback(self, targets_string):
        """list of targets read from the policy section
        clear latest flags, and change host state
        this is done here since all target do not necessarily
        generate reports and host callbacks"""
        targets = targets_string.split(",")
        self.targets = netaddr.IPSet(netaddr.IPAddress(i) for i in targets)
        self.__logger.debug("Found %d targets in Nessus file" % len(self.targets))
        self.ticket_manager.ips = self.targets
        self.__try_to_clear_latest_flags()

    def plugin_set_callback(self, plugin_set_string):
        string_list = plugin_set_string.split(";")
        if (
            string_list[-1] == ""
        ):  # this list ends with a ; creating a non-int empty string
            string_list.pop()
        plugin_set = set(int(s) for s in string_list)
        self.__logger.debug("Found %d plugin_ids in Nessus file" % len(plugin_set))
        self.ticket_manager.source_ids = plugin_set
        self.__try_to_clear_latest_flags()

    def port_range_callback(self, port_range_string):
        # The base policy port range was used
        if port_range_string == "default":
            # Match the base policy value found in /extras/policy.xml
            port_range_string = "1-65535"
        ports = set(util.range_string_to_list(port_range_string))
        self.__logger.debug("Found %d ports in Nessus file" % len(ports))
        self.ticket_manager.ports = ports
        self.__try_to_clear_latest_flags()

    def host_callback(self, parsedHost):
        # some fragile hosts don't list their host_ip
        # fallback to name
        if parsedHost.has_key("host_ip"):
            self.current_ip = netaddr.IPAddress(parsedHost["host_ip"])
            del parsedHost["host_ip"]
        else:
            try:
                self.current_ip = netaddr.IPAddress(parsedHost["name"])
            except netaddr.AddrFormatError:
                # When parsedHost['name'] is not a valid IP (see CYHY-113 in Jira)
                self.current_ip = None
                self.__logger.warning(
                    "Skipping vulnerability reports; invalid host IP detected: %s"
                    % parsedHost["name"]
                )
                return

        # look for a hostname; we can't trust parsedHost["name"] alone, since
        # that can contain the IP address or some other user-supplied string
        if parsedHost.get("host_fqdn") == parsedHost["name"]:
            self.current_hostname = parsedHost["host_fqdn"]
        else:
            self.current_hostname = None

        parsedHost["ip"] = self.current_ip
        self.current_ip_int = int(self.current_ip)
        self.current_host_owner = self.__db.HostDoc.get_owner_of_ip(
            self.current_ip_int, self.current_hostname
        )

        if not self.manual_scan:
            # only change the time if we are not doing a manual scan import
            self.current_ip_time = parsedHost["end_time"]
        if self.current_host_owner is None:
            self.current_host_owner = UNKNOWN_OWNER
            if self.current_hostname:
                self.__logger.warning(
                    "Could not find owner for %s - %s (%d)"
                    % (
                        self.current_hostname,
                        self.current_ip,
                        self.current_ip_int,
                    )
                )
            else:
                self.__logger.warning(
                    "Could not find owner for %s (%d)"
                    % (self.current_ip, self.current_ip_int)
                )

        # Nessus host docs are not stored as we already have better data from nmap

    def report_callback(self, parsedReport):
        # not storing severity 0 reports or reports with invalid IPs
        if parsedReport["severity"] == 0:
            return
        if self.current_ip is None:
            self.__logger.warning(
                "No current IP; skipping vulnerability report: %s"
                % parsedReport["plugin_name"]
            )
            return
        report = self.__db.VulnScanDoc()
        util.copy_attrs(parsedReport, report)

        report.ip = self.current_ip  # sets ip and ip_int
        report["hostname"] = self.current_hostname
        report["latest"] = True
        report["owner"] = self.current_host_owner
        report["source"] = NessusImporter.SOURCE
        report["time"] = self.current_ip_time

        try:
            report.save()
        except InvalidDocument as e:
            util.pretty_bail(e, parsedReport)

        self.ticket_manager.open_ticket(report, "vulnerability detected")

    def end_callback(self):
        for ip in self.targets:
            if self.manual_scan:
                # update host priority and reschedule host
                self.__ch_db.update_host_priority_and_reschedule(ip)
            else:
                # move host out of RUNNING status
                self.__ch_db.transition_host(ip)
        self.ticket_manager.close_tickets()
        if not self.attempted_to_clear_latest_flags:
            self.__logger.warning(
                'Reached end of Nessus import but did not clear "latest" flags'
            )
            self.__logger.warning(
                "Ticket manager state counts: %d ips, %d ports, %d source_ids"
                % (
                    len(self.ticket_manager.ips),
                    len(self.ticket_manager.ports),
                    len(self.ticket_manager.source_ids),
                )
            )
        else:
            self.__logger.debug(
                "Reached end of Nessus import, VulnScan latest flags were cleared."
            )
