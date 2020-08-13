from xml.sax import ContentHandler, parse, SAXNotRecognizedException
from xml.parsers.expat import ExpatError
import gzip
from datetime import datetime
from dateutil import tz

PROPS_DATE_FORMAT = "%a %b %d %H:%M:%S %Y"
REPORT_DATE_FORMAT = "%Y/%m/%d"
BANNED_PLUGIN_IDS = [
    11219,  # Nessus SYN scanner
    19506,  # Nessus Scan Information
    10287,  # Traceroute information
]


class NessusV2ContentHander(ContentHandler):
    # TODO: too many params, make an interface or default implementation to extend for callers
    def __init__(
        self,
        host_callback,
        report_callback,
        targets_callback,
        plugin_set_callback,
        port_range_callback,
        end_callback,
    ):
        ContentHandler.__init__(self)
        self.host_callback = host_callback
        self.report_callback = report_callback
        self.targets_callback = targets_callback
        self.plugin_set_callback = plugin_set_callback
        self.port_range_callback = port_range_callback
        self.end_callback = end_callback
        self.scan_name = None
        self.host = None
        self.report = None
        self.modeStack = []  # [[name, attrs], ...]
        self.chars = ""
        self.last_pref_name = None

    def push_mode(self, name, attrs):
        self.modeStack.append((name, attrs))

    def pop_mode(self):
        return self.modeStack.pop()

    def get_mode(self):
        if len(self.modeStack):
            return self.modeStack[-1][0]
        else:
            return None

    def startElement(self, name, attrs):
        # clear characters buffer
        self.chars = ""
        if len(self.modeStack) == 0:
            if name == "NessusClientData_v2":
                self.push_mode(name, attrs)
            else:
                raise SAXNotRecognizedException(
                    "XML does not look like Nessus v2 data."
                )
        else:
            mode = self.get_mode()
            if mode == "NessusClientData_v2":
                self.push_mode(name, attrs)  # Policy or Report
                if name == "Policy":
                    pass
                if name == "Report":
                    self.scan_name = attrs["name"]
            elif mode == "Policy":
                if name == "Preferences":
                    self.push_mode(name, attrs)
            elif mode == "Preferences":
                if name == "ServerPreferences":
                    self.push_mode(name, attrs)
            elif mode == "ServerPreferences":
                if name == "preference":
                    self.push_mode(name, attrs)
            elif mode == "preference":
                self.push_mode(name, attrs)  # name or value elements
            elif mode == "Report":
                if name == "ReportHost":
                    self.push_mode(name, attrs)
                    self.host = {"name": attrs["name"]}  # TODO get a NessusHostDoc here
            elif mode == "ReportHost":
                if name == "HostProperties":
                    self.push_mode(name, attrs)
                    # properties are gathered in tag element endings
                if name == "ReportItem":
                    self.push_mode(name, attrs)
                    self.report = {}
                    self.report["port"] = int(attrs["port"])
                    self.report["service"] = attrs["svc_name"]
                    self.report["protocol"] = attrs["protocol"]
                    self.report["severity"] = int(attrs["severity"])
                    self.report["plugin_id"] = int(attrs["pluginID"])
                    self.report["plugin_name"] = attrs["pluginName"]
                    self.report["plugin_family"] = attrs["pluginFamily"]
            elif mode == "HostProperties":
                if name == "tag":
                    self.push_mode(name, attrs)
            elif mode == "ReportItem":
                # all report item contents added on element endings
                self.push_mode(name, attrs)

    def endElement(self, name):
        if name == self.get_mode():
            (skip, attrs) = self.pop_mode()
        else:
            return
        mode = self.get_mode()
        # tag content captured on element end
        if mode == "HostProperties" and name == "tag":
            tagName = attrs["name"]
            tagValue = self.chars
            if tagName == "HOST_START":
                tagName = "start_time"
                tagValue = datetime.strptime(tagValue, PROPS_DATE_FORMAT).replace(
                    tzinfo=tz.tzutc()
                )  # All times/dates assumed to be UTC
            elif tagName == "HOST_END":
                tagName = "end_time"
                tagValue = datetime.strptime(tagValue, PROPS_DATE_FORMAT).replace(
                    tzinfo=tz.tzutc()
                )
            else:
                tagName = tagName.replace("-", "_")
            self.host[tagName] = tagValue
        elif mode == "ReportItem":
            tagValue = self.chars
            if name.endswith("date"):
                tagValue = datetime.strptime(tagValue, REPORT_DATE_FORMAT).replace(
                    tzinfo=tz.tzutc()
                )
            elif name.endswith("score"):
                tagValue = float(tagValue)
            self.report[name] = tagValue
        elif mode == "ReportHost" and name == "ReportItem":
            # capture report if the report is worthy
            if self.report["plugin_id"] not in BANNED_PLUGIN_IDS:
                self.report_callback(self.report)
        elif (
            name == "HostProperties"
        ):  # call back here so other reports will have an IP
            self.host_callback(self.host)
        elif mode == "preference":
            if name == "name":
                self.last_pref_name = self.chars
            elif name == "value":
                if self.last_pref_name == "TARGET":  # found list of scanned IPs
                    # not all targets produce reports, so we need to use this list
                    # of IP addresses to change the host's stage/status
                    self.targets_callback(self.chars)
                elif (
                    self.last_pref_name == "plugin_set"
                ):  # list of plugins separated by ;
                    self.plugin_set_callback(self.chars)
                elif (
                    self.last_pref_name == "port_range"
                ):  # list of port ranges separated by ,
                    self.port_range_callback(self.chars)

        elif name == "NessusClientData_v2":
            self.end_callback()

    def characters(self, content):
        self.chars += content
