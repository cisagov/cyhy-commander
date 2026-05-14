"""SAX content handler for parsing nmap XML output."""

import datetime
from xml.sax import ContentHandler, SAXNotRecognizedException

import netaddr


def copy_attrs(source, dest, skip=None):
    """Copy attributes from source to dest, skipping keys in skip list."""
    if skip is None:
        skip = []
    for k, v in source.items():
        if k in skip:
            continue
        dest[k] = v


class NmapContentHandler(ContentHandler):
    """SAX handler that parses an nmap XML report into structured callbacks."""

    def __init__(self, host_callback, end_callback):
        """Initialize the handler with host and end callback functions."""
        ContentHandler.__init__(self)
        self.host_callback = host_callback
        self.end_callback = end_callback
        self.isNmapFile = False
        self.currentHost = None
        self.currentPort = None
        self.cpeTarget = None
        self.chars = ""
        self.xmloutputversion = None
        self.taskStartTime = None
        self.taskEndTime = None
        self.first_osmatch_done_for_host = (
            False  # only capture the first osmatch element
        )

    def startElement(self, name, attrs):
        """Handle the opening of an XML element."""
        # clear characters buffer
        self.chars = ""
        if not self.isNmapFile:
            if name == "nmaprun":
                self.isNmapFile = True
                self.xmloutputversion = attrs["xmloutputversion"]
            else:
                raise SAXNotRecognizedException(
                    "XML does not look like Nmap data."
                )
        elif name == "host":
            self.first_osmatch_done_for_host = False
            self.currentHost = {"ports": {}}
            if "starttime" in attrs:
                self.currentHost["starttime"] = (
                    datetime.datetime.utcfromtimestamp(int(attrs["starttime"]))
                )
                self.currentHost["endtime"] = (
                    datetime.datetime.utcfromtimestamp(int(attrs["endtime"]))
                )
            else:
                self.currentHost["starttime"] = self.taskStartTime
                self.currentHost["endtime"] = self.taskEndTime
        elif name == "status":
            self.currentHost["state"] = attrs["state"]
            self.currentHost["state_reason"] = attrs["reason"]
        elif name == "address" and attrs["addrtype"] != "mac":
            self.currentHost["addr"] = netaddr.IPAddress(attrs["addr"])
        elif name == "hostname":
            self.currentHost["hostname"] = attrs[
                "name"
            ]  # can be multiple, only storing last
        elif name == "port":
            portid = int(attrs["portid"])
            self.currentPort = self.currentHost["ports"][portid] = {}
            self.currentPort["protocol"] = attrs["protocol"]
        elif name == "state":
            self.currentPort["state"] = attrs["state"]
            self.currentPort["reason"] = attrs["reason"]
        elif name == "service":
            # service information varies, grab most of it
            service = self.currentPort["service"] = {}
            self.cpeTarget = service
            copy_attrs(attrs, service, ["servicefp"])
        elif (
            name == "osmatch"
            and self.xmloutputversion in ["1.04", "1.05"]
            and not self.first_osmatch_done_for_host
        ):
            os = self.currentHost["os"] = {"classes": []}
            copy_attrs(attrs, os)
        elif (
            name == "osclass"
            and self.xmloutputversion in ["1.04", "1.05"]
            and not self.first_osmatch_done_for_host
        ):
            clazz = {}
            copy_attrs(attrs, clazz)
            self.currentHost["os"]["classes"].append(clazz)
            self.cpeTarget = clazz
        elif name == "taskbegin":
            # save start time for hosts that don't have a time reported
            if "time" in attrs:
                self.taskStartTime = datetime.datetime.utcfromtimestamp(
                    int(attrs["time"])
                )
        elif name == "taskend":
            # save end time for hosts that don't have a time reported
            if "time" in attrs:
                self.taskEndTime = datetime.datetime.utcfromtimestamp(
                    int(attrs["time"])
                )

    def endElement(self, name):
        """Handle the closing of an XML element."""
        if name == "cpe" and not self.first_osmatch_done_for_host:
            if "cpe" not in self.cpeTarget:
                self.cpeTarget["cpe"] = []
            self.cpeTarget["cpe"].append(self.chars)
        elif name == "host":
            self.host_callback(self.currentHost)
        elif name == "nmaprun":
            self.end_callback()
        elif name == "osmatch":
            # we only want to parse the most likely match
            # which is the first match.  So after that is
            # parsed, we set this flag, and ignore the
            # remaining osmatch elements
            self.first_osmatch_done_for_host = True

    def characters(self, content):
        """Accumulate character data between XML tags."""
        self.chars += content
