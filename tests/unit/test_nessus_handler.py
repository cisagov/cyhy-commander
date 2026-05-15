"""Unit tests for NessusV2ContentHandler SAX parsing."""

from xml.sax import parseString  # nosec B406

import pytest

from cyhy_commander.nessus.nessus_handler import NessusV2ContentHander

NESSUS_XML_ONE_HOST_ONE_FINDING = """\
<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy>
<Preferences>
<ServerPreferences>
<preference><name>TARGET</name><value>192.168.1.1</value></preference>
<preference><name>plugin_set</name><value>12345;67890;</value></preference>
<preference><name>port_range</name><value>1-1024</value></preference>
</ServerPreferences>
</Preferences>
</Policy>
<Report name="TestScan">
<ReportHost name="192.168.1.1">
<HostProperties>
<tag name="host-ip">192.168.1.1</tag>
<tag name="HOST_START">Mon Jan 01 00:00:00 2026</tag>
<tag name="HOST_END">Mon Jan 01 00:05:00 2026</tag>
</HostProperties>
<ReportItem port="443" svc_name="https" protocol="tcp" severity="3" pluginID="99999" pluginName="Test Vuln" pluginFamily="Web Servers">
<description>A test vulnerability</description>
<solution>Upgrade software</solution>
<synopsis>Test synopsis</synopsis>
<risk_factor>High</risk_factor>
<cvss_base_score>7.5</cvss_base_score>
<plugin_publication_date>2025/01/01</plugin_publication_date>
<plugin_modification_date>2025/06/01</plugin_modification_date>
</ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>
"""

NESSUS_XML_MULTIPLE_HOSTS = """\
<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy>
<Preferences>
<ServerPreferences>
<preference><name>TARGET</name><value>10.0.0.1,10.0.0.2</value></preference>
<preference><name>plugin_set</name><value>11111;</value></preference>
<preference><name>port_range</name><value>default</value></preference>
</ServerPreferences>
</Preferences>
</Policy>
<Report name="MultiScan">
<ReportHost name="10.0.0.1">
<HostProperties>
<tag name="host-ip">10.0.0.1</tag>
<tag name="HOST_START">Tue Feb 01 10:00:00 2026</tag>
<tag name="HOST_END">Tue Feb 01 10:10:00 2026</tag>
</HostProperties>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2" pluginID="11111" pluginName="SSH Vuln" pluginFamily="General">
<description>SSH issue</description>
<risk_factor>Medium</risk_factor>
<cvss_base_score>5.0</cvss_base_score>
</ReportItem>
</ReportHost>
<ReportHost name="10.0.0.2">
<HostProperties>
<tag name="host-ip">10.0.0.2</tag>
<tag name="HOST_START">Tue Feb 01 10:00:00 2026</tag>
<tag name="HOST_END">Tue Feb 01 10:10:00 2026</tag>
</HostProperties>
<ReportItem port="80" svc_name="http" protocol="tcp" severity="1" pluginID="22222" pluginName="HTTP Info" pluginFamily="Web Servers">
<description>HTTP info disclosure</description>
<risk_factor>Low</risk_factor>
<cvss_base_score>2.0</cvss_base_score>
</ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>
"""

NESSUS_XML_BANNED_PLUGIN = """\
<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy>
<Preferences>
<ServerPreferences>
<preference><name>TARGET</name><value>1.2.3.4</value></preference>
<preference><name>plugin_set</name><value>11219;</value></preference>
<preference><name>port_range</name><value>1-65535</value></preference>
</ServerPreferences>
</Preferences>
</Policy>
<Report name="BannedTest">
<ReportHost name="1.2.3.4">
<HostProperties>
<tag name="host-ip">1.2.3.4</tag>
<tag name="HOST_START">Wed Mar 01 00:00:00 2026</tag>
<tag name="HOST_END">Wed Mar 01 00:05:00 2026</tag>
</HostProperties>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="11219" pluginName="Nessus SYN scanner" pluginFamily="Port scanners">
<description>SYN scanner info</description>
</ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>
"""


class TestNessusV2ContentHandler:
    """Tests for NessusV2ContentHandler SAX parsing."""

    def _parse(self, xml_str):
        hosts = []
        reports = []
        targets = []
        plugin_sets = []
        port_ranges = []
        end_called = []

        handler = NessusV2ContentHander(
            host_callback=lambda h: hosts.append(h),
            report_callback=lambda r: reports.append(r),
            targets_callback=lambda t: targets.append(t),
            plugin_set_callback=lambda p: plugin_sets.append(p),
            port_range_callback=lambda pr: port_ranges.append(pr),
            end_callback=lambda: end_called.append(True),
        )
        parseString(xml_str.encode(), handler)
        return hosts, reports, targets, plugin_sets, port_ranges, end_called

    def test_one_host_one_finding(self):
        hosts, reports, targets, plugin_sets, port_ranges, end_called = (
            self._parse(NESSUS_XML_ONE_HOST_ONE_FINDING)
        )
        assert len(end_called) == 1
        assert len(hosts) == 1
        assert len(reports) == 1
        assert targets == ["192.168.1.1"]
        assert plugin_sets == ["12345;67890;"]
        assert port_ranges == ["1-1024"]

        host = hosts[0]
        assert host["host_ip"] == "192.168.1.1"
        assert "start_time" in host
        assert "end_time" in host

        report = reports[0]
        assert report["port"] == 443
        assert report["service"] == "https"
        assert report["protocol"] == "tcp"
        assert report["severity"] == 3
        assert report["plugin_id"] == 99999
        assert report["plugin_name"] == "Test Vuln"
        assert report["description"] == "A test vulnerability"
        assert report["cvss_base_score"] == 7.5

    def test_multiple_hosts(self):
        hosts, reports, targets, _, _, _ = self._parse(
            NESSUS_XML_MULTIPLE_HOSTS
        )
        assert len(hosts) == 2
        assert len(reports) == 2
        assert targets == ["10.0.0.1,10.0.0.2"]

        assert hosts[0]["host_ip"] == "10.0.0.1"
        assert hosts[1]["host_ip"] == "10.0.0.2"

        assert reports[0]["plugin_id"] == 11111
        assert reports[1]["plugin_id"] == 22222

    def test_banned_plugin_filtered(self):
        """Banned plugin IDs (e.g. 11219) should not produce report callbacks."""
        hosts, reports, _, _, _, _ = self._parse(NESSUS_XML_BANNED_PLUGIN)
        assert len(hosts) == 1
        assert len(reports) == 0  # banned plugin filtered out

    def test_plugin_attributes_parsed(self):
        """Plugin attributes like dates and scores are correctly typed."""
        _, reports, _, _, _, _ = self._parse(NESSUS_XML_ONE_HOST_ONE_FINDING)
        report = reports[0]
        # Dates are parsed as datetime objects
        from datetime import datetime

        assert isinstance(report["plugin_publication_date"], datetime)
        assert isinstance(report["plugin_modification_date"], datetime)
        # Score is float
        assert isinstance(report["cvss_base_score"], float)
        assert report["cvss_base_score"] == 7.5

    def test_default_port_range(self):
        """'default' port_range is passed through as-is to callback."""
        _, _, _, _, port_ranges, _ = self._parse(NESSUS_XML_MULTIPLE_HOSTS)
        assert port_ranges == ["default"]
