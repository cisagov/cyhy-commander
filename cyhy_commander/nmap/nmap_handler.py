"""SAX content handler for parsing nmap XML output."""

import datetime
from typing import Any
from xml.sax import ContentHandler, SAXNotRecognizedException  # nosec B406

import netaddr  # type: ignore[import-untyped]


def copy_attrs(
    source: dict[str, Any], dest: dict[str, Any], skip: list[str] | None = None
) -> None:
    """Copy attributes from source to dest, skipping keys in skip list."""
    if skip is None:
        skip = []
    for k, v in source.items():
        if k in skip:
            continue
        dest[k] = v


class NmapContentHandler(ContentHandler):
    """SAX handler that parses an nmap XML report into structured callbacks."""

    def __init__(
        self,
        host_callback: Any,
        end_callback: Any,
    ) -> None:
        """Initialize the handler with host and end callback functions."""
        ContentHandler.__init__(self)
        self.host_callback = host_callback
        self.end_callback = end_callback
        self.isNmapFile = False
        self.currentHost: dict[str, Any] | None = None
        self.currentPort: dict[str, Any] | None = None
        self.cpeTarget: dict[str, Any] | None = None
        self.chars = ""
        self.xmloutputversion: str | None = None
        self.taskStartTime: datetime.datetime | None = None
        self.taskEndTime: datetime.datetime | None = None
        self.first_osmatch_done_for_host = (
            False  # only capture the first osmatch element
        )

    def startElement(self, name: str, attrs: Any) -> None:
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
        elif name == "status" and self.currentHost is not None:
            self.currentHost["state"] = attrs["state"]
            self.currentHost["state_reason"] = attrs["reason"]
        elif (
            name == "address"
            and attrs["addrtype"] != "mac"
            and self.currentHost is not None
        ):
            self.currentHost["addr"] = netaddr.IPAddress(attrs["addr"])
        elif name == "hostname" and self.currentHost is not None:
            self.currentHost["hostname"] = attrs[
                "name"
            ]  # can be multiple, only storing last
        elif name == "port" and self.currentHost is not None:
            portid = int(attrs["portid"])
            port: dict[str, Any] = {}
            self.currentHost["ports"][portid] = port
            self.currentPort = port
            self.currentPort["protocol"] = attrs["protocol"]
        elif name == "state" and self.currentPort is not None:
            self.currentPort["state"] = attrs["state"]
            self.currentPort["reason"] = attrs["reason"]
        elif name == "service" and self.currentPort is not None:
            # service information varies, grab most of it
            service: dict[str, Any] = {}
            self.currentPort["service"] = service
            self.cpeTarget = service
            copy_attrs(attrs, service, ["servicefp"])
        elif (
            name == "osmatch"
            and self.xmloutputversion in ["1.04", "1.05"]
            and not self.first_osmatch_done_for_host
            and self.currentHost is not None
        ):
            os: dict[str, Any] = {"classes": []}
            self.currentHost["os"] = os
            copy_attrs(attrs, os)
        elif (
            name == "osclass"
            and self.xmloutputversion in ["1.04", "1.05"]
            and not self.first_osmatch_done_for_host
            and self.currentHost is not None
        ):
            clazz: dict[str, Any] = {}
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

    def endElement(self, name: str) -> None:
        """Handle the closing of an XML element."""
        if (
            name == "cpe"
            and not self.first_osmatch_done_for_host
            and self.cpeTarget is not None
        ):
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

    def characters(self, content: str) -> None:
        """Accumulate character data between XML tags."""
        self.chars += content
