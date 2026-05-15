"""Unit tests for job sink classes."""

import asyncio
from unittest.mock import AsyncMock, patch

from cyhy_db.models.enum import Stage

from cyhy_commander.job_sink import NessusSink, NmapSink, NoOpSink, TryAgainSink


class TestNmapSink:
    """Tests for NmapSink."""

    def test_can_handle_matching_stage(self):
        sink = NmapSink(Stage.NETSCAN1)
        assert sink.can_handle("/path/to/netscan1-20260101T000000") is True

    def test_can_handle_non_matching_stage(self):
        sink = NmapSink(Stage.NETSCAN1)
        assert sink.can_handle("/path/to/portscan-20260101T000000") is False

    def test_can_handle_portscan(self):
        sink = NmapSink(Stage.PORTSCAN)
        assert sink.can_handle("/path/to/portscan-abc") is True

    def test_can_handle_netscan2(self):
        sink = NmapSink(Stage.NETSCAN2)
        assert sink.can_handle("/path/to/netscan2-xyz") is True
        assert sink.can_handle("/path/to/netscan1-xyz") is False

    def test_str(self):
        sink = NmapSink(Stage.NETSCAN1)
        assert "NmapSink" in str(sink)
        assert "netscan1" in str(sink)


class TestNessusSink:
    """Tests for NessusSink."""

    def test_can_handle_vulnscan(self):
        sink = NessusSink()
        assert sink.can_handle("/path/to/vulnscan-20260101") is True

    def test_can_handle_non_vulnscan(self):
        sink = NessusSink()
        assert sink.can_handle("/path/to/netscan1-20260101") is False

    def test_str(self):
        sink = NessusSink()
        assert "NessusSink" in str(sink)


class TestNoOpSink:
    """Tests for NoOpSink."""

    def test_can_handle_always_true(self):
        sink = NoOpSink()
        assert sink.can_handle("/any/path") is True
        assert sink.can_handle("/path/to/NETSCAN1-abc") is True
        assert sink.can_handle("/path/to/VULNSCAN-abc") is True

    def test_str(self):
        sink = NoOpSink()
        assert "NoOpSink" in str(sink)


class TestTryAgainSink:
    """Tests for TryAgainSink."""

    def test_can_handle_always_true(self):
        sink = TryAgainSink()
        assert sink.can_handle("/any/path") is True
        assert sink.can_handle("") is True

    def test_str(self):
        sink = TryAgainSink()
        assert "TryAgainSink" in str(sink)

    def test_handle_plain_ips(self, tmp_path, mock_db):
        """handle() processes plain IP addresses from target file."""
        sink = TryAgainSink()
        job_dir = tmp_path / "netscan1-20260101"
        job_dir.mkdir()
        target_file = job_dir / "NETSCAN1-20260101.txt"
        target_file.write_text("192.168.1.1\n192.168.1.2\n")

        async def _run():
            with patch(
                "cyhy_commander.job_sink.db_ops.transition_host",
                new_callable=AsyncMock,
            ) as mock_transition:
                await sink.handle(str(job_dir))
                assert mock_transition.call_count == 2
                mock_transition.assert_any_call(
                    "192.168.1.1",
                    up=False,
                    reason="scan-failure",
                    was_failure=True,
                )

        asyncio.run(_run())

    def test_handle_hostname_ip_format(self, tmp_path, mock_db):
        """handle() extracts IP from hostname[ip] format."""
        sink = TryAgainSink()
        job_dir = tmp_path / "vulnscan-20260101"
        job_dir.mkdir()
        target_file = job_dir / "VULNSCAN-20260101.txt"
        target_file.write_text("foo.gov[10.0.0.1]\nbar.gov[10.0.0.2]\n")

        async def _run():
            with patch(
                "cyhy_commander.job_sink.db_ops.transition_host",
                new_callable=AsyncMock,
            ) as mock_transition:
                await sink.handle(str(job_dir))
                assert mock_transition.call_count == 2
                mock_transition.assert_any_call(
                    "10.0.0.1",
                    up=False,
                    reason="scan-failure",
                    was_failure=True,
                )

        asyncio.run(_run())

    def test_handle_malformed_target_skipped(self, tmp_path, mock_db):
        """handle() skips malformed targets and logs a warning."""
        sink = TryAgainSink()
        job_dir = tmp_path / "netscan1-20260101"
        job_dir.mkdir()
        target_file = job_dir / "NETSCAN1-20260101.txt"
        target_file.write_text("bad[format[nested]\n192.168.1.1\n")

        async def _run():
            with patch(
                "cyhy_commander.job_sink.db_ops.transition_host",
                new_callable=AsyncMock,
            ) as mock_transition:
                await sink.handle(str(job_dir))
                # Only the valid IP should be processed
                assert mock_transition.call_count == 1

        asyncio.run(_run())
