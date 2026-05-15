"""Unit tests for NmapImporter."""

import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cyhy_db.models.enum import Stage

from cyhy_commander.nmap.nmap_importer import NmapImporter

NMAP_NETSCAN_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" xmloutputversion="1.05" start="1700000000">
<host starttime="1700000001" endtime="1700000010">
<status state="up" reason="syn-ack"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
</host>
<host starttime="1700000001" endtime="1700000010">
<status state="down" reason="no-response"/>
<address addr="192.168.1.2" addrtype="ipv4"/>
</host>
</nmaprun>
"""

NMAP_PORTSCAN_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" xmloutputversion="1.05" start="1700000000">
<host starttime="1700000001" endtime="1700000010">
<status state="up" reason="syn-ack"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack"/>
<service name="ssh" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="443">
<state state="filtered" reason="no-response"/>
<service name="https"/>
</port>
</ports>
<os>
<osmatch name="Linux 5.4" accuracy="95" line="1">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="95"/>
</osmatch>
</os>
</host>
</nmaprun>
"""


class TestNmapImporter:
    """Tests for NmapImporter.process()."""

    def _write_files(self, xml_content, target_ips):
        """Write XML and target files to temp locations."""
        xml_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False
        )
        xml_file.write(xml_content)
        xml_file.close()

        target_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        )
        for ip in target_ips:
            target_file.write(ip + "\n")
        target_file.close()

        return xml_file.name, target_file.name

    def test_process_netscan1(self, mock_db):
        """process() for NETSCAN1 transitions hosts up/down."""
        xml_file, target_file = self._write_files(
            NMAP_NETSCAN_XML, ["192.168.1.1", "192.168.1.2"]
        )

        async def _run():
            with (
                patch(
                    "cyhy_commander.nmap.nmap_importer.db_ops.transition_host",
                    new_callable=AsyncMock,
                ) as mock_transition,
                patch(
                    "cyhy_commander.nmap.nmap_importer.HostScanDoc.reset_latest_flag_by_ip",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.PortScanDoc.reset_latest_flag_by_ip",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.VulnScanDoc.reset_latest_flag_by_ip",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.IPTicketManager.process_tickets",
                    new_callable=AsyncMock,
                ),
            ):
                importer = NmapImporter(stage=Stage.NETSCAN1)
                await importer.process(xml_file, target_file)
                assert mock_transition.call_count == 2
                # First host is up
                mock_transition.assert_any_call(
                    ip="192.168.1.1", up=True, reason="syn-ack"
                )
                # Second host is down
                mock_transition.assert_any_call(
                    ip="192.168.1.2", up=False, reason="no-response"
                )

        try:
            asyncio.run(_run())
        finally:
            os.unlink(xml_file)
            os.unlink(target_file)

    def test_process_portscan(self, mock_db):
        """process() for PORTSCAN stores port details and transitions host."""
        xml_file, target_file = self._write_files(
            NMAP_PORTSCAN_XML, ["10.0.0.1"]
        )

        async def _run():
            mock_host_doc = MagicMock()
            mock_host_doc.owner = "TEST_ORG"

            with (
                patch(
                    "cyhy_commander.nmap.nmap_importer.db_ops.transition_host",
                    new_callable=AsyncMock,
                ) as mock_transition,
                patch(
                    "cyhy_commander.nmap.nmap_importer.HostScanDoc.reset_latest_flag_by_ip",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.PortScanDoc.reset_latest_flag_by_ip",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.HostDoc.find_one",
                    new_callable=AsyncMock,
                    return_value=mock_host_doc,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.PortScanDoc.save",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.HostScanDoc.save",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.IPPortTicketManager.process_tickets",
                    new_callable=AsyncMock,
                ),
            ):
                importer = NmapImporter(stage=Stage.PORTSCAN)
                await importer.process(xml_file, target_file)
                # Host should be transitioned as up with open ports
                mock_transition.assert_called_once_with(
                    ip="10.0.0.1",
                    up=True,
                    reason="syn-ack",
                    has_open_ports=True,
                )

        try:
            asyncio.run(_run())
        finally:
            os.unlink(xml_file)
            os.unlink(target_file)

    def test_invalid_stage_raises(self):
        """NmapImporter raises ValueError for unsupported stages."""
        with pytest.raises(ValueError, match="Unsupported stage"):
            NmapImporter(stage=Stage.VULNSCAN)

    def test_process_xml_without_xml_header(self, mock_db):
        """process() handles nmap output that starts with non-XML first line."""
        xml_content = (
            "Starting Nmap 7.94\n" + NMAP_NETSCAN_XML.split("\n", 1)[1]
        )
        xml_file, target_file = self._write_files(
            xml_content, ["192.168.1.1", "192.168.1.2"]
        )

        async def _run():
            with (
                patch(
                    "cyhy_commander.nmap.nmap_importer.db_ops.transition_host",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.HostScanDoc.reset_latest_flag_by_ip",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.PortScanDoc.reset_latest_flag_by_ip",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.VulnScanDoc.reset_latest_flag_by_ip",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.nmap.nmap_importer.IPTicketManager.process_tickets",
                    new_callable=AsyncMock,
                ),
            ):
                importer = NmapImporter(stage=Stage.NETSCAN1)
                await importer.process(xml_file, target_file)

        try:
            asyncio.run(_run())
        finally:
            os.unlink(xml_file)
            os.unlink(target_file)
