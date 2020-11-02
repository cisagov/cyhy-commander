#!/usr/bin/env python3

# Standard Python Libraries
import copy
import glob
import json
import logging
import sys
import time

# Third-Party Libraries
import requests

USER = "cap-scanner"
PASSWORD = "***REMOVED***"
URL = "https://localhost:8834"
BASE_POLICY_NAME = "cyhy-base"

DEBUG = False
LOGIN = "/session"
POLICY_BASE = "/policies"
POLICY_COPY = "/policies/{policy_id}/copy"
POLICY_DETAILS = "/policies/{policy_id}"
POLICY_EDIT = "/policies/{policy_id}"
POLICY_DELETE = "/policies/{policy_id}"
SCAN_BASE = "/scans"
SCAN_LAUNCH = "/scans/{scan_id}/launch"
SCAN_DETAILS = "/scans/{scan_id}"
SCAN_DELETE = "/scans/{scan_id}"
REPORT_EXPORT = "/scans/{scan_id}/export"
REPORT_DOWNLOAD = "/scans/{scan_id}/export/{report_file_id}/download"
REPORT_STATUS = "/scans/{scan_id}/export/{file_id}/status"
OK_STATUS = 200
NOT_FOUND_STATUS = 404
INVALID_CREDS_STATUS = 401
SCAN_RUNNING_STATUS = "running"
SCAN_PROCESSING_STATUS = "processing"
SCAN_COMPLETED_STATUS = "completed"
REPORT_READY_STATUS = "ready"
TARGET_FILE_GLOB = "*.txt"
PORTS_FILE_GLOB = "ports"

LOGGER_FORMAT = "%(asctime)-15s %(levelname)s %(message)s"
LOGGER_LEVEL = logging.INFO
LOGGER = None  # initialized in setup_logging()

# Seconds between polling requests to see if a running scan has finished
WAIT_TIME_SEC = 10
# Would be nice to get this working
VERIFY_SSL = False
# Number of times to retry a failed request before giving up
FAILED_REQUEST_MAX_RETRIES = 3
# Seconds to wait between failed request retries
FAILED_REQUEST_RETRY_WAIT_SEC = 30

if DEBUG:
    # Standard Python Libraries
    import http.client

    http.client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


def setup_logging():
    global LOGGER
    logging.captureWarnings(True)  # Added to capture InsecureRequestWarnings
    LOGGER = logging.getLogger(__name__)
    LOGGER.setLevel(LOGGER_LEVEL)
    handler = logging.StreamHandler(sys.stderr)
    LOGGER.addHandler(handler)
    formatter = logging.Formatter(LOGGER_FORMAT)
    handler.setFormatter(formatter)


def error_exit(message):
    print(message, file=sys.stderr)
    sys.exit(1)


class NessusController:
    def __init__(self, nessus_url):
        self.url = nessus_url
        self.token = None

    def __make_request(self, target, method, payload=None):
        num_retries = 0
        if payload:
            payload = json.dumps(payload)

        while num_retries < FAILED_REQUEST_MAX_RETRIES:
            if num_retries > 0:
                LOGGER.warning(
                    "Waiting {!r} seconds...".format(FAILED_REQUEST_RETRY_WAIT_SEC)
                )
                time.sleep(FAILED_REQUEST_RETRY_WAIT_SEC)

            headers = {
                "Content-Type": "application/json; charset=UTF-8"
            }  # Send everything as json content

            # If we aren't logged in (don't have a session token) and we aren't already attempting to login, then try to login
            if self.token is None and target != LOGIN:
                LOGGER.info("Attempting to login to Nessus server")
                self.__make_request(
                    LOGIN, "POST", {"username": USER, "password": PASSWORD}
                )

            # If we are already logged in, add the token to the headers
            if self.token:
                headers["X-Cookie"] = "token={!s}".format(self.token)

            if method == "GET":
                response = requests.get(
                    self.url + target,
                    headers=headers,
                    params=payload,
                    verify=VERIFY_SSL,
                )
            elif method == "POST":
                response = requests.post(
                    self.url + target, headers=headers, data=payload, verify=VERIFY_SSL
                )
            elif method == "PUT":
                response = requests.put(
                    self.url + target, headers=headers, data=payload, verify=VERIFY_SSL
                )
            elif method == "DELETE":
                response = requests.delete(
                    self.url + target, headers=headers, verify=VERIFY_SSL
                )

            if response.status_code == OK_STATUS:
                if target == LOGIN and method == "POST":
                    LOGGER.info("Successfully logged into Nessus server")
                    self.token = response.json().get(
                        "token"
                    )  # Store the token if we just logged in
                return response

            LOGGER.warning(
                "Request failed ({!r} {!r}, attempt #{!r}); response={!r}".format(
                    method, self.url + target, num_retries + 1, response.text
                )
            )
            if self.token and response.status_code == INVALID_CREDS_STATUS:
                LOGGER.warning(
                    "Invalid credentials error; Nessus session probably expired."
                )
                LOGGER.warning(
                    "Attempting to establish new Nessus session (username: {!r})".format(
                        USER
                    )
                )
                self.token = None  # Clear token to force re-login on next loop
                # Don't increment num_retries here; upcoming re-login request will have it's own num_retries counter
            else:
                num_retries += 1

        # while loop has reached FAILED_REQUEST_MAX_RETRIES
        LOGGER.critical("Maximum retry attempts reached without success.")
        sys.exit(num_retries)

    def find_policy(self, policy_name):
        """Attempt to grab the policy ID for a name."""
        policies = self.policy_list()
        if policies.get("policies"):
            for policy in policies["policies"]:
                if policy["name"] == policy_name:
                    return policy
            # If no matching policy name is found, return None
            return None

        raise Warning("No policies found in list")

    def policy_list(self):
        response = self.__make_request(POLICY_BASE, "GET")
        if response.status_code == OK_STATUS and response.json().get("policies"):
            return response.json()

        raise Warning("Policy list failed; response={!r}".format(response.text))

    def policy_details(self, policy_id):
        response = self.__make_request(
            POLICY_DETAILS.format(policy_id=policy_id), "GET"
        )
        if response.status_code == OK_STATUS and response.json().get("uuid"):
            return response.json()

        raise Warning("Get policy details failed; response={!r}".format(response.text))

    def policy_create(self, policy_details):
        response = self.__make_request(POLICY_BASE, "POST", policy_details)
        if response.status_code == OK_STATUS and response.json().get("policy_id"):
            return response.json()

        raise Warning("Policy creation failed; response={!r}".format(response.text))

    def policy_copy(self, policy_id):
        response = self.__make_request(POLICY_COPY.format(policy_id=policy_id), "POST")
        if response.status_code == OK_STATUS and response.json().get("id"):
            return response.json()

        raise Warning("Policy copy failed; response={!r}".format(response.text))

    def policy_edit(self, policy_id, policy_details):
        response = self.__make_request(
            POLICY_EDIT.format(policy_id=policy_id), "PUT", policy_details
        )
        if response.status_code == OK_STATUS:
            return response

        raise Warning("Policy edit failed; response={!r}".format(response.text))

    def policy_delete(self, policy_id):
        response = self.__make_request(
            POLICY_DELETE.format(policy_id=policy_id), "DELETE"
        )
        if response.status_code == OK_STATUS:
            return response

        raise Warning("Policy delete failed; response={!r}".format(response.text))

    def scan_new(self, targets, policy_id, scan_name, template_uuid):
        scan_details = dict()
        scan_details["uuid"] = template_uuid
        scan_details["settings"] = dict()
        scan_details["settings"]["name"] = scan_name
        scan_details["settings"]["policy_id"] = policy_id
        scan_details["settings"]["text_targets"] = targets
        scan_details["settings"]["enabled"] = "true"
        response = self.__make_request(SCAN_BASE, "POST", scan_details)
        if response.status_code == OK_STATUS and response.json().get("scan"):
            return response.json()

        raise Warning("Scan creation failed; response={!r}".format(response.text))

    def scan_launch(self, scan_id):
        response = self.__make_request(SCAN_LAUNCH.format(scan_id=scan_id), "POST")
        if response.status_code == OK_STATUS and response.json().get("scan_uuid"):
            return response.json()

        raise Warning("Scan launch failed; response={!r}".format(response.text))

    def scan_details(self, scan_id):
        response = self.__make_request(SCAN_DETAILS.format(scan_id=scan_id), "GET")
        if response.status_code == OK_STATUS and response.json().get("info"):
            return response.json()

        if response.status_code == NOT_FOUND_STATUS:
            raise Warning(
                "Scan id {!r} not found; response={!r}".format(scan_id, response.text)
            )

        raise Warning(
            "Get scan details failed; response={!r}".format(response.text)
        )

    def scan_status(self, scan_id):
        scan_details = self.scan_details(scan_id)
        return scan_details["info"]["status"]

    def scan_delete(self, scan_id):
        response = self.__make_request(SCAN_DELETE.format(scan_id=scan_id), "DELETE")
        if response.status_code == OK_STATUS:
            return response

        raise Warning("Scan delete failed; response={!r}".format(response.text))

    def report_ready(self, scan_id, file_id):
        response = self.__make_request(
            REPORT_STATUS.format(scan_id=scan_id, file_id=file_id), "GET"
        )
        if response.status_code == OK_STATUS and response.json().get("status"):
            return response.json().get("status") == REPORT_READY_STATUS

        raise Warning("Unable to retrieve report: response={!r}".format(response.text))

    def report_download(self, scan_id):
        response = self.__make_request(
            REPORT_EXPORT.format(scan_id=scan_id), "POST", {"format": "nessus"}
        )
        if response.status_code == OK_STATUS and response.json().get("file"):
            report_file_id = response.json()["file"]
            while not self.report_ready(scan_id, report_file_id):
                LOGGER.info("Waiting for report to be ready for download")
                time.sleep(WAIT_TIME_SEC)
            LOGGER.info("Report ready for download")
            response = self.__make_request(
                REPORT_DOWNLOAD.format(scan_id=scan_id, report_file_id=report_file_id),
                "GET",
            )
            if response.status_code == OK_STATUS:
                return response.text

            raise Warning(
                "Scan report download failed; response={!r}".format(response.text)
            )

        raise Warning("Scan report export failed; response={!r}".format(response.text))

    def destroy_session(self):
        response = self.__make_request(LOGIN, "DELETE")
        if response.status_code == OK_STATUS:
            return response

        raise Warning("Session destruction failed; response={!r}".format(response.text))


def main():
    setup_logging()
    LOGGER.info("Nessus job starting")

    # find targets file
    LOGGER.info("Searching for targets file")
    possible_targets_files = glob.glob(TARGET_FILE_GLOB)
    if not possible_targets_files:
        error_exit("No target file names matched: {!s}".format(TARGET_FILE_GLOB))
    # pick the first one
    targets_file = possible_targets_files[0]
    LOGGER.info("Using target file: {!s}".format(targets_file))
    job_root_name = targets_file.rsplit(".", 1)[0]

    # find ports file
    LOGGER.info("Searching for ports file")
    possible_ports_file = glob.glob(PORTS_FILE_GLOB)
    if not possible_ports_file:
        error_exit("No ports file names matched: {!s}".format(PORTS_FILE_GLOB))
    # pick the first one
    ports_file = possible_ports_file[0]
    LOGGER.info("Using ports file: {!s}".format(ports_file))

    # read in targets and ports
    with open(targets_file, "r") as f:
        targets = f.readlines()

    with open(ports_file, "r") as f:
        ports = f.readline().strip()

    LOGGER.info("Instantiating Nessus controller at: {!s}".format(URL))
    controller = NessusController(URL)

    # Find the base policy by name
    LOGGER.info("Searching for base policy: {!r}".format(BASE_POLICY_NAME))
    base_policy = controller.find_policy(BASE_POLICY_NAME)
    if base_policy is None:
        error_exit("Could not find policy {!r}".format(BASE_POLICY_NAME))

    # get base policy details
    LOGGER.info("Getting details for '{name}' policy".format(**base_policy))
    base_policy_details = controller.policy_details(base_policy["id"])

    # copy details of base policy into new policy and modify them
    new_policy_details = copy.copy(base_policy_details)
    new_policy_name = job_root_name + " Policy"
    new_policy_details["settings"]["name"] = new_policy_name
    new_policy_details["settings"]["portscan_range"] = ports

    # create new policy
    LOGGER.info("Creating new policy based on base policy")
    new_policy = controller.policy_create(new_policy_details)
    if new_policy.get("policy_id") is None:
        error_exit("No new policy id returned")
    if new_policy["policy_id"] == base_policy["id"]:
        error_exit(
            "New policy has the same id as the source policy: {policy_id}".format(
                **new_policy
            )
        )
    new_policy_id = new_policy["policy_id"]
    LOGGER.info(
        "Created new policy: '{policy_name}' (id: {policy_id})".format(**new_policy)
    )

    # create a scan with our new policy
    targets_string = ",".join(targets)
    new_scan_name = job_root_name + " Scan"
    LOGGER.info("Creating new scan: {!r}".format(new_scan_name))
    new_scan = controller.scan_new(
        targets_string, new_policy_id, new_scan_name, new_policy_details["uuid"]
    )
    if not new_scan.get("scan", {}).get("uuid"):
        error_exit("New scan was not created")
    new_scan_id = new_scan["scan"]["id"]
    LOGGER.info(
        "Scan successfully created.  Name: '{name}'  id: {id}  UUID: {uuid}".format(
            **new_scan["scan"]
        )
    )

    # launch our new scan
    LOGGER.info("Launching scan: {!r}".format(new_scan_name))
    scan_launch_response = controller.scan_launch(new_scan_id)
    if not scan_launch_response.get("scan_uuid"):
        error_exit("New scan was not launched")
    LOGGER.info(
        'Scan launched successfully.  scan_uuid: "{scan_uuid}"'.format(
            **scan_launch_response
        )
    )

    # wait for the scan to complete
    scan_status = controller.scan_status(new_scan_id)
    while scan_status in [SCAN_RUNNING_STATUS, SCAN_PROCESSING_STATUS]:
        LOGGER.info(
            "Waiting for scan to complete (current status: {})".format(scan_status)
        )
        scan_found = True
        time.sleep(WAIT_TIME_SEC)
        scan_status = controller.scan_status(new_scan_id)
    if not scan_found:
        error_exit("Scan was never seen. id: {!r}".format(new_scan_id))

    scan_details_response = controller.scan_details(new_scan_id)
    if scan_details_response["info"].get("status") == SCAN_COMPLETED_STATUS:
        LOGGER.info("Scan completed")
    else:
        raise Warning(
            "Scan id {!r} stopped running with status {!r}".format(
                new_scan_id, scan_details_response["info"].get("status")
            )
        )

    # download report and send to stdout
    LOGGER.info("Downloading report")
    report = controller.report_download(new_scan_id)
    if not report:
        error_exit("Downloaded report was empty for scan id: {!r}".format(new_scan_id))
    LOGGER.info("Report downloaded successfully")
    print(report)

    # delete scan
    LOGGER.info("Deleting scan id: {!r}".format(new_scan_id))
    result = controller.scan_delete(new_scan_id)
    if not result:
        error_exit("No result returned when deleting scan")
    LOGGER.info("Scan deleted successfully")

    # delete policy
    LOGGER.info("Deleting policy id: {!r}".format(new_policy_id))
    result = controller.policy_delete(new_policy_id)
    if not result:
        error_exit("No result returned when deleting policy")
    LOGGER.info("Policy deleted successfully")

    # destroy session
    LOGGER.info("Destroying session")
    result = controller.destroy_session()
    if not result:
        error_exit("Session not properly destroyed")
    LOGGER.info("Session destroyed successfully")

    # great success!
    LOGGER.info("Job completed. (GREAT SUCCESS!)")
    sys.exit(0)


if __name__ == "__main__":
    main()
