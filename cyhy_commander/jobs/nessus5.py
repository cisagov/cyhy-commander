#!/usr/bin/env python

import sys
from urllib import urlencode
from urllib2 import Request, urlopen, HTTPError
from random import randint
from xml.parsers.expat import ExpatError
import re
import datetime
import copy
import glob
import time
import logging

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

DEBUG = False
LOGIN = "/login"
POLICY_LIST = "/policy/list"
POLICY_COPY = "/policy/copy"
POLICY_EDIT = "/policy/edit"
POLICY_DELETE = "/policy/delete"
SCAN_NEW = "/scan/new"
REPORT_LIST = "/report/list"
REPORT_DOWNLOAD = "/file/report/download"
REPORT_DELETE = "/report/delete"
OK_STATUS = "OK"
ERROR_STATUS = "ERROR"
COMPLETED_STATUS = "completed"
RUNNING_STATUS = "running"
TARGET_FILE_GLOB = "*.txt"
PORTS_FILE_GLOB = "ports"
ROOT_NODES = set(["seq", "status", "contents"])

LOGGER_FORMAT = "%(asctime)-15s %(levelname)s %(message)s"
LOGGER_LEVEL = logging.INFO
LOGGER = None  # initialized in setup_logging()

# Plugin multi-value tags
PLUGIN_MULTI_VAL = ["bid", "xref", "cve"]

if DEBUG:
    import urllib2

    handler = urllib2.HTTPSHandler(debuglevel=1)
    opener = urllib2.build_opener(handler)
    urllib2.install_opener(opener)


def setup_logging():
    global LOGGER
    LOGGER = logging.getLogger(__name__)
    LOGGER.setLevel(LOGGER_LEVEL)
    handler = logging.StreamHandler(sys.stderr)
    LOGGER.addHandler(handler)
    formatter = logging.Formatter(LOGGER_FORMAT)
    handler.setFormatter(formatter)


class NessusController(object):
    def __init__(self, nessus_url):
        self.url = nessus_url
        self.token = None

    def __make_request(self, target, params=None):
        if params is None:
            params = dict()

        # Add the standard seq random number to the POST data
        params["seq"] = randint(10000, 99999)

        # Encode the params
        data = urlencode(params)

        # Create the POST request with data, or a GET request without
        if data is not None:
            req = Request(self.url + target, data)
        else:
            req = Request(self.url + target)

        # Now let's see if we have already logged in, if so, we need to have that token
        if self.token is not None:
            req.add_header("Cookie", "token=%s" % self.token)

        # Send the request, getting the response
        response = urlopen(req)

        # Read the response
        response_stream = response.read()

        return response_stream

    def __parse_reply_start(self, xml_string):
        # Parse xml
        try:
            xml = ET.fromstring(xml_string)  # reply element is root
        except ExpatError:
            return (0, "Cannot parse XML", {})

        # Make sure it looks like what we expect it to be
        if set([t.tag for t in xml.getchildren()]) != ROOT_NODES:
            return (0, "XML not formatted correctly", xml)

        # Get seq and status
        seq = xml.findtext("seq")
        status = xml.findtext("status")
        return (seq, status, xml)

    def __parse_reply_kv(self, xml_string, search_path, key, value):
        seq, status, xml = self.__parse_reply_start(xml_string)

        d = {}
        if search_path:
            for x in xml.findall(search_path):
                d[x.findtext(key)] = x.findtext(value)

        return (seq, status, d)

    def __parse_reply_single(self, xml_string, search_path):
        seq, status, xml = self.__parse_reply_start(xml_string)
        value = xml.findtext(search_path)
        return (seq, status, value)

    def __status_ok(self, status):
        if status == ERROR_STATUS:
            return False
        elif status == OK_STATUS:
            return True
        else:
            raise Exception("Unknown status returned:", status)

    def find_policy(self, policy_name):
        """Attempts to grab the policy ID for a name"""
        policies = self.policy_list()
        for k, v in policies.iteritems():
            if v == policy_name:
                return k

    def login(self, username, password):
        response = self.__make_request(LOGIN, {"login": username, "password": password})
        seq, status, v = self.__parse_reply_single(response, "contents/token")
        if self.__status_ok(status):
            self.token = v
            return self.token
        else:
            raise Warning("Login failed")

    def policy_list(self):
        response = self.__make_request(POLICY_LIST)
        seq, status, d = self.__parse_reply_kv(
            response, "contents/policies/policy", "policyID", "policyName"
        )
        if self.__status_ok(status):
            return d
        else:
            raise Warning("Policy list failed")

    def policy_copy(self, policy_id):
        response = self.__make_request(POLICY_COPY, {"policy_id": policy_id})
        seq, status, v = self.__parse_reply_single(response, "contents/policy/policyID")
        if self.__status_ok(status):
            return v
        else:
            raise Warning("Policy copy failed")

    def policy_edit(self, policy_id, policy_name, changes):
        args = copy.copy(changes)
        args["policy_id"] = policy_id
        args["policy_name"] = policy_name
        args["policy_shared"] = "no"  # new requirement that broke all of this
        response = self.__make_request(POLICY_EDIT, args)
        seq, status, v = self.__parse_reply_single(response, "contents/policy/policyID")
        if self.__status_ok(status):
            return v
        else:
            raise Warning("Policy edit failed")

    def policy_delete(self, policy_id):
        response = self.__make_request(POLICY_DELETE, {"policy_id": policy_id})
        seq, status, v = self.__parse_reply_single(response, "contents/policyID")
        if self.__status_ok(status):
            return v
        else:
            raise Warning("Policy delete failed")

    def scan_new(self, targets, policy_id, scan_name):
        response = self.__make_request(
            SCAN_NEW,
            {"target": targets, "policy_id": policy_id, "scan_name": scan_name},
        )
        seq, status, v = self.__parse_reply_single(response, "contents/scan/uuid")
        if self.__status_ok(status):
            return v
        else:
            raise Warning("Scan creation failed")

    def report_list(self):
        response = self.__make_request(REPORT_LIST)
        seq, status, v = self.__parse_reply_kv(
            response, "contents/reports/report", "name", "status"
        )
        if self.__status_ok(status):
            return v
        else:
            raise Warning("Report list failed")

    def scan_running(self, uuid):
        scans = self.report_list()
        if not scans.has_key(uuid):
            raise Warning("No scan found matching UUID")
        return scans[uuid] == RUNNING_STATUS

    def report_download(self, uuid):
        response = self.__make_request(REPORT_DOWNLOAD, {"report": uuid})
        return response

    def report_delete(self, uuid):
        response = self.__make_request(REPORT_DELETE, {"report": uuid})
        seq, status, v = self.__parse_reply_single(response, "contents/report/name")
        if self.__status_ok(status):
            return v
        else:
            raise Warning("Report deletion failed")


def getPolicyChanges(ports):
    return {
        "safe_checks": "yes",
        "stop_scan_on_disconnect": "yes",
        "slice_network_addresses": "yes",
        "unscanned_closed": "yes",
        "reduce_connections_on_congestion": "yes",
        "use_kernel_congestion_detection": "yes",
        "max_hosts": "40",
        "plugin_selection.family.Denial of Service": "disabled",
        "plugin_selection.family.Port scanners": "mixed",  # UDP/TCP Scanners disabled
        "plugin_selection.individual_plugin.34220": "enabled",  # WMI Scanner
        "plugin_selection.individual_plugin.14274": "enabled",  # SNMP Scanner
        "plugin_selection.individual_plugin.14272": "enabled",  # SSH Scanner
        "plugin_selection.individual_plugin.10180": "enabled",  # PING Scanner
        "plugin_selection.individual_plugin.11219": "enabled",  # SYN Scanner
        "port_range": ports,
        "max_simult_tcp_sessions": "20",
        "host.max_simult_tcp_sessions": "15",
    }


def main():
    USER = "cap-scanner"
    PASSWORD = "***REMOVED***"
    URL = "https://localhost:8834"
    BASE_POLICY_NAME = "cyhy-base"
    COPIED_POLICY_NAME = "Copy of %s" % (BASE_POLICY_NAME)
    NOW = datetime.datetime.now().isoformat()
    setup_logging()

    LOGGER.info("Nessus job starting")

    # find targets file
    LOGGER.info("Searching for targets file")
    possible_targets_files = glob.glob(TARGET_FILE_GLOB)
    assert len(possible_targets_files) > 0, (
        "No target file names matched: %s" % TARGET_FILE_GLOB
    )
    # pick the first one
    targets_file = possible_targets_files[0]
    LOGGER.info("Using target file: %s" % targets_file)
    job_root_name = targets_file.rsplit(".", 1)[0]

    # find ports file
    LOGGER.info("Searching for ports file")
    possible_ports_file = glob.glob(PORTS_FILE_GLOB)
    assert len(possible_ports_file) > 0, (
        "No ports file names matched: %s" % PORTS_FILE_GLOB
    )
    # pick the first one
    ports_file = possible_ports_file[0]
    LOGGER.info("Using ports file: %s" % ports_file)

    # read in targets and ports
    with open(targets_file, "r") as f:
        targets = f.readlines()

    with open(ports_file, "r") as f:
        ports = f.readline().strip()

    # connect to nessus
    LOGGER.info("Connecting to Nessus server at: %s" % URL)
    controller = NessusController(URL)
    token = controller.login(USER, PASSWORD)
    assert token != None, "Unable to login to Nessus server: %s" % URL
    LOGGER.info("Successfully logged into Nessus server")

    # copy the base policy
    LOGGER.info("Searching for base policy: %s" % BASE_POLICY_NAME)
    policy_id = controller.find_policy(BASE_POLICY_NAME)
    assert policy_id != None, 'Could not find policy "%s"' % (BASE_POLICY_NAME)
    new_policy_id = controller.policy_copy(policy_id)
    assert new_policy_id != None, "No copied policy id returned"
    assert (
        new_policy_id != policy_id
    ), "Policy copy has the same id as the source policy"
    LOGGER.info("Copied base policy to: %s" % new_policy_id)

    # modify the policy copy with our changes
    LOGGER.info("Modifying policy copy")
    policy_changes = getPolicyChanges(ports)
    new_policy_name = job_root_name + " Policy"
    result = controller.policy_edit(new_policy_id, new_policy_name, policy_changes)
    assert result, "No result returned when editing policy"
    LOGGER.info("Policy modifications applied. Policy now named: %s" % new_policy_name)

    # start a scan with our new policy
    targets_string = ",".join(targets)
    new_scan_name = job_root_name + " Scan"
    LOGGER.info("Starting scan: %s" % new_scan_name)
    scan_uuid = controller.scan_new(targets_string, new_policy_id, new_scan_name)
    assert scan_uuid, "New scan UUID was None"
    LOGGER.info("Scan successfully started.  UUID: %s" % scan_uuid)

    # wait for the scan to complete
    while controller.scan_running(scan_uuid):
        LOGGER.info("Waiting for scan to complete")
        scan_found = True
        time.sleep(10)
    assert scan_found, "Scan was never seen: %s" % (scan_uuid)
    LOGGER.info("Scan completed")

    # download report and send the stdout
    LOGGER.info("Downloading report")
    report = controller.report_download(scan_uuid)
    assert report, "Downloaded report was empty: %s" % scan_uuid
    LOGGER.info("Report downloaded successfully")
    print report

    # delete report
    LOGGER.info("Deleting report: %s" % scan_uuid)
    result = controller.report_delete(scan_uuid)
    assert result == scan_uuid, "Delete result did not match scan_uuid: %s" % scan_uuid
    LOGGER.info("Report deleted successfully")

    # delete policy
    LOGGER.info("Deleting policy: %s" % new_policy_id)
    result = controller.policy_delete(new_policy_id)
    assert result == new_policy_id, (
        "Expected policy delete to return the deleted policy id: %s != %s"
        % (result, policy_id)
    )
    LOGGER.info("Policy deleted")

    # great success!
    LOGGER.info("Job completed. (GREAT SUCCESS!)")
    sys.exit(0)


if __name__ == "__main__":
    main()
