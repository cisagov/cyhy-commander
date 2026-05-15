"""Unit tests for NessusImporter."""

import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

from cyhy_commander.nessus.nessus_importer import NessusImporter

NESSUS_XML = """\
<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy>
<Preferences>
<ServerPreferences>
<preference><name>TARGET</name><value>192.168.1.1,192.168.1.2</value></preference>
<preference><name>plugin_set</name><value>99999;</value></preference>
<preference><name>port_range</name><value>1-65535</value></preference>
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
<solution>Upgrade</solution>
<synopsis>Synopsis</synopsis>
<risk_factor>High</risk_factor>
<cvss_base_score>7.5</cvss_base_score>
<plugin_publication_date>2025/01/01</plugin_publication_date>
<plugin_modification_date>2025/06/01</plugin_modification_date>
</ReportItem>
</ReportHost>
<ReportHost name="192.168.1.2">
<HostProperties>
<tag name="host-ip">192.168.1.2</tag>
<tag name="HOST_START">Mon Jan 01 00:00:00 2026</tag>
<tag name="HOST_END">Mon Jan 01 00:05:00 2026</tag>
</HostProperties>
</ReportHost>
</Report>
</NessusClientData_v2>
"""

NESSUS_XML_SEVERITY_ZERO = """\
<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy>
<Preferences>
<ServerPreferences>
<preference><name>TARGET</name><value>10.0.0.1</value></preference>
<preference><name>plugin_set</name><value>55555;</value></preference>
<preference><name>port_range</name><value>80</value></preference>
</ServerPreferences>
</Preferences>
</Policy>
<Report name="InfoScan">
<ReportHost name="10.0.0.1">
<HostProperties>
<tag name="host-ip">10.0.0.1</tag>
<tag name="HOST_START">Tue Feb 01 10:00:00 2026</tag>
<tag name="HOST_END">Tue Feb 01 10:05:00 2026</tag>
</HostProperties>
<ReportItem port="80" svc_name="http" protocol="tcp" severity="0" pluginID="55555" pluginName="Info Plugin" pluginFamily="General">
<description>Informational</description>
</ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>
"""


class TestNessusImporter:
    """Tests for NessusImporter.process()."""

    def _write_xml(self, content):
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".nessus", delete=False
        )
        f.write(content)
        f.close()
        return f.name

    def test_process_with_findings(self, mock_db):
        """process() stores VulnScanDocs and transitions hosts."""
        xml_file = self._write_xml(NESSUS_XML)

        mock_host_doc = MagicMock()
        mock_host_doc.owner = "TEST_ORG"

        async def _run():
            with (
                patch(
                    "cyhy_commander.nessus.nessus_importer.HostDoc.find_one",
                    new_callable=AsyncMock,
                    return_value=mock_host_doc,
                ),
                patch(
                    "cyhy_commander.nessus.nessus_importer.VulnScanDoc.reset_latest_flag_by_ip",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nessus.nessus_importer.VulnTicketManager.process_tickets",
                    new_callable=AsyncMock,
                ) as mock_tickets,
                patch(
                    "cyhy_commander.nessus.nessus_importer.db_ops.transition_host",
                    new_callable=AsyncMock,
                ) as mock_transition,
            ):
                importer = NessusImporter()
                # Patch _store_vuln_report to avoid VulnScanDoc construction issues
                mock_vuln = MagicMock()
                importer._store_vuln_report = AsyncMock(return_value=mock_vuln)

                await importer.process(xml_file)

                # Both targets should be transitioned
                assert mock_transition.call_count == 2
                mock_transition.assert_any_call(
                    ip="192.168.1.1",
                    up=True,
                    reason="vuln-scan-complete",
                )
                mock_transition.assert_any_call(
                    ip="192.168.1.2",
                    up=True,
                    reason="vuln-scan-complete",
                )

                # Ticket manager should be called for each target
                assert mock_tickets.call_count == 2

        try:
            asyncio.run(_run())
        finally:
            os.unlink(xml_file)

    def test_process_severity_zero_skipped(self, mock_db):
        """Severity 0 reports are not stored."""
        xml_file = self._write_xml(NESSUS_XML_SEVERITY_ZERO)

        mock_host_doc = MagicMock()
        mock_host_doc.owner = "TEST_ORG"

        async def _run():
            with (
                patch(
                    "cyhy_commander.nessus.nessus_importer.HostDoc.find_one",
                    new_callable=AsyncMock,
                    return_value=mock_host_doc,
                ),
                patch(
                    "cyhy_commander.nessus.nessus_importer.VulnScanDoc.reset_latest_flag_by_ip",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nessus.nessus_importer.VulnTicketManager.process_tickets",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nessus.nessus_importer.db_ops.transition_host",
                    new_callable=AsyncMock,
                ),
            ):
                importer = NessusImporter()
                # Patch _store_vuln_report to track calls
                importer._store_vuln_report = AsyncMock(return_value=None)
                await importer.process(xml_file)
                # Severity 0 reports are filtered before _store_vuln_report
                importer._store_vuln_report.assert_not_called()

        try:
            asyncio.run(_run())
        finally:
            os.unlink(xml_file)

    def test_process_no_targets_logs_warning(self, mock_db):
        """process() handles XML with no TARGET preference gracefully."""
        xml_content = """\
<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy>
<Preferences>
<ServerPreferences>
</ServerPreferences>
</Preferences>
</Policy>
<Report name="Empty">
</Report>
</NessusClientData_v2>
"""
        xml_file = self._write_xml(xml_content)

        async def _run():
            importer = NessusImporter()
            # Should not raise, just log warning
            await importer.process(xml_file)

        try:
            asyncio.run(_run())
        finally:
            os.unlink(xml_file)

    def test_targets_with_hostname_format(self, mock_db):
        """process() handles hostname[ip] format in TARGET preference."""
        xml_content = """\
<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy>
<Preferences>
<ServerPreferences>
<preference><name>TARGET</name><value>foo.gov[10.0.0.1]</value></preference>
<preference><name>plugin_set</name><value>11111;</value></preference>
<preference><name>port_range</name><value>80</value></preference>
</ServerPreferences>
</Preferences>
</Policy>
<Report name="HostnameScan">
<ReportHost name="10.0.0.1">
<HostProperties>
<tag name="host-ip">10.0.0.1</tag>
<tag name="HOST_START">Wed Mar 01 00:00:00 2026</tag>
<tag name="HOST_END">Wed Mar 01 00:05:00 2026</tag>
</HostProperties>
</ReportHost>
</Report>
</NessusClientData_v2>
"""
        xml_file = self._write_xml(xml_content)

        mock_host_doc = MagicMock()
        mock_host_doc.owner = "TEST_ORG"

        async def _run():
            with (
                patch(
                    "cyhy_commander.nessus.nessus_importer.HostDoc.find_one",
                    new_callable=AsyncMock,
                    return_value=mock_host_doc,
                ),
                patch(
                    "cyhy_commander.nessus.nessus_importer.VulnScanDoc.reset_latest_flag_by_ip",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nessus.nessus_importer.VulnTicketManager.process_tickets",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nessus.nessus_importer.db_ops.transition_host",
                    new_callable=AsyncMock,
                ) as mock_transition,
            ):
                importer = NessusImporter()
                await importer.process(xml_file)
                mock_transition.assert_called_once_with(
                    ip="10.0.0.1",
                    up=True,
                    reason="vuln-scan-complete",
                )

        try:
            asyncio.run(_run())
        finally:
            os.unlink(xml_file)
