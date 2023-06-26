from xml.sax import ContentHandler, parse, SAXNotRecognizedException
from xml.parsers.expat import ExpatError
import datetime
import netaddr
from cyhy.util import copy_attrs


class NmapContentHandler(ContentHandler):
    def __init__(self, host_callback, end_callback):
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
            False
        )  # only capture the first osmatch element

    def startElement(self, name, attrs):
        # clear characters buffer
        self.chars = ""
        if not self.isNmapFile:
            if name == "nmaprun":
                self.isNmapFile = True
                self.xmloutputversion = attrs["xmloutputversion"]
            else:
                raise SAXNotRecognizedException("XML does not look like Nmap data.")
        elif name == "host":
            self.first_osmatch_done_for_host = False
            self.currentHost = {"ports": {}}
            if attrs.has_key("starttime"):
                self.currentHost["starttime"] = datetime.datetime.utcfromtimestamp(
                    int(attrs["starttime"])
                )
                self.currentHost["endtime"] = datetime.datetime.utcfromtimestamp(
                    int(attrs["endtime"])
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
            and self.xmloutputversion == "1.04"
            and not self.first_osmatch_done_for_host
        ):
            os = self.currentHost["os"] = {"classes": []}
            copy_attrs(attrs, os)
        elif (
            name == "osclass"
            and self.xmloutputversion == "1.04"
            and not self.first_osmatch_done_for_host
        ):
            clazz = {}
            copy_attrs(attrs, clazz)
            self.currentHost["os"]["classes"].append(clazz)
            self.cpeTarget = clazz
        elif name == "taskbegin":
            # save start time for hosts that don't have a time reported
            if attrs.has_key("time"):
                self.taskStartTime = datetime.datetime.utcfromtimestamp(
                    int(attrs["time"])
                )
        elif name == "taskend":
            # save end time for hosts that don't have a time reported
            if attrs.has_key("time"):
                self.taskEndTime = datetime.datetime.utcfromtimestamp(
                    int(attrs["time"])
                )

    def endElement(self, name):
        if name == "cpe" and not self.first_osmatch_done_for_host:
            if not self.cpeTarget.has_key("cpe"):
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
        self.chars += content
