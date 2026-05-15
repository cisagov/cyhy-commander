"""Unit tests for NmapContentHandler SAX parsing."""

import io
from xml.sax import parseString  # nosec B406

import pytest

from cyhy_commander.nmap.nmap_handler import NmapContentHandler

# Minimal nmap XML with one host up, one port open
NMAP_XML_ONE_HOST_UP = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" xmloutputversion="1.05" start="1700000000">
<taskbegin task="SYN Stealth Scan" time="1700000000"/>
<taskend task="SYN Stealth Scan" time="1700000060"/>
<host starttime="1700000001" endtime="1700000010">
<status state="up" reason="syn-ack"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostname name="host1.example.com"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" method="probed" conf="10"/>
</port>
</ports>
</host>
</nmaprun>
"""

NMAP_XML_HOST_DOWN = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" xmloutputversion="1.05" start="1700000000">
<taskbegin task="Ping Scan" time="1700000000"/>
<taskend task="Ping Scan" time="1700000060"/>
<host starttime="1700000001" endtime="1700000010">
<status state="down" reason="no-response"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
</host>
</nmaprun>
"""

NMAP_XML_OS_DETECTION = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" xmloutputversion="1.05" start="1700000000">
<host starttime="1700000001" endtime="1700000010">
<status state="up" reason="syn-ack"/>
<address addr="192.168.1.2" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack"/>
<service name="ssh"/>
</port>
</ports>
<os>
<osmatch name="Linux 5.4" accuracy="95" line="1">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="95">
<cpe>cpe:/o:linux:linux_kernel:5.4</cpe>
</osclass>
</osmatch>
<osmatch name="Linux 4.15" accuracy="90" line="2">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="4.X" accuracy="90"/>
</osmatch>
</os>
</host>
</nmaprun>
"""

NMAP_XML_MULTIPLE_PORTS = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" xmloutputversion="1.05" start="1700000000">
<host starttime="1700000001" endtime="1700000010">
<status state="up" reason="syn-ack"/>
<address addr="192.168.1.3" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack"/>
<service name="ssh"/>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http"/>
</port>
<port protocol="tcp" portid="443">
<state state="closed" reason="reset"/>
<service name="https"/>
</port>
</ports>
</host>
</nmaprun>
"""


class TestNmapContentHandler:
    """Tests for NmapContentHandler SAX parsing."""

    def _parse(self, xml_str):
        hosts = []
        end_called = []

        def host_cb(host):
            hosts.append(host)

        def end_cb():
            end_called.append(True)

        handler = NmapContentHandler(host_cb, end_cb)
        parseString(xml_str.encode(), handler)
        return hosts, end_called

    def test_one_host_up_one_port_open(self):
        hosts, end_called = self._parse(NMAP_XML_ONE_HOST_UP)
        assert len(hosts) == 1
        assert len(end_called) == 1
        host = hosts[0]
        assert host["state"] == "up"
        assert host["state_reason"] == "syn-ack"
        assert str(host["addr"]) == "192.168.1.1"
        assert host["hostname"] == "host1.example.com"
        assert 80 in host["ports"]
        port = host["ports"][80]
        assert port["state"] == "open"
        assert port["protocol"] == "tcp"
        assert port["service"]["name"] == "http"

    def test_host_down(self):
        hosts, _ = self._parse(NMAP_XML_HOST_DOWN)
        assert len(hosts) == 1
        host = hosts[0]
        assert host["state"] == "down"
        assert host["state_reason"] == "no-response"
        assert str(host["addr"]) == "10.0.0.1"
        assert host["ports"] == {}

    def test_os_detection(self):
        hosts, _ = self._parse(NMAP_XML_OS_DETECTION)
        assert len(hosts) == 1
        host = hosts[0]
        assert "os" in host
        os_info = host["os"]
        assert os_info["name"] == "Linux 5.4"
        assert os_info["accuracy"] == "95"
        assert len(os_info["classes"]) == 1  # only first osmatch
        clazz = os_info["classes"][0]
        assert clazz["vendor"] == "Linux"
        assert "cpe" in clazz
        assert "cpe:/o:linux:linux_kernel:5.4" in clazz["cpe"]

    def test_multiple_ports(self):
        hosts, _ = self._parse(NMAP_XML_MULTIPLE_PORTS)
        assert len(hosts) == 1
        host = hosts[0]
        assert 22 in host["ports"]
        assert 80 in host["ports"]
        assert 443 in host["ports"]
        assert host["ports"][22]["state"] == "open"
        assert host["ports"][80]["state"] == "open"
        assert host["ports"][443]["state"] == "closed"

    def test_task_times_used_when_host_has_no_times(self):
        xml = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" xmloutputversion="1.05" start="1700000000">
<taskbegin task="scan" time="1700000100"/>
<taskend task="scan" time="1700000200"/>
<host>
<status state="up" reason="syn-ack"/>
<address addr="1.2.3.4" addrtype="ipv4"/>
</host>
</nmaprun>
"""
        hosts, _ = self._parse(xml)
        host = hosts[0]
        assert host["starttime"] is not None
        assert host["endtime"] is not None
