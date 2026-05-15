"""Unit tests for job source classes."""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

from cyhy_commander.job_source import (
    DatabaseJobSource,
    DirectoryJobSource,
    _list_to_range_string,
)


class TestListToRangeString:
    """Tests for _list_to_range_string utility."""

    def test_empty_list(self):
        assert _list_to_range_string([]) == ""

    def test_single_port(self):
        assert _list_to_range_string([80]) == "80"

    def test_two_non_contiguous(self):
        assert _list_to_range_string([80, 443]) == "80,443"

    def test_contiguous_range(self):
        assert _list_to_range_string([80, 81, 82]) == "80-82"

    def test_mixed(self):
        assert (
            _list_to_range_string([22, 80, 443, 8000, 8001, 8002])
            == "22,80,443,8000-8002"
        )

    def test_unsorted_input(self):
        assert _list_to_range_string([443, 80, 22]) == "22,80,443"

    def test_duplicates_removed(self):
        assert _list_to_range_string([80, 80, 81, 81]) == "80-81"

    def test_single_range_at_end(self):
        assert _list_to_range_string([1, 3, 4, 5]) == "1,3-5"


class TestDirectoryJobSource:
    """Tests for DirectoryJobSource."""

    def test_creates_directory_if_missing(self, tmp_path):
        dir_path = str(tmp_path / "new_dir")
        _source = DirectoryJobSource(dir_path)  # noqa: F841
        assert os.path.exists(dir_path)

    def test_get_job_empty_dir(self, tmp_path):
        source = DirectoryJobSource(str(tmp_path))
        assert source.get_job() is None

    def test_get_job_with_jobs(self, tmp_path):
        job_dir = tmp_path / "JOB1"
        job_dir.mkdir()
        source = DirectoryJobSource(str(tmp_path))
        result = source.get_job()
        assert result is not None
        assert "JOB1" in result

    def test_str_representation(self, tmp_path):
        source = DirectoryJobSource(str(tmp_path))
        assert "DirectoryJobSource" in str(source)
        assert str(tmp_path) in str(source)


class TestDatabaseJobSource:
    """Tests for DatabaseJobSource."""

    def test_str_representation(self):
        from cyhy_db.models.enum import Stage

        source = DatabaseJobSource("/tmp/job.sh", job_type=Stage.NETSCAN1)
        assert "DatabaseJobSource" in str(source)
        assert "netscan1" in str(source).lower()

    def test_get_job_returns_none_sync(self):
        """Synchronous get_job() always returns None (async make_job is used)."""
        from cyhy_db.models.enum import Stage

        source = DatabaseJobSource("/tmp/job.sh", job_type=Stage.NETSCAN1)
        assert source.get_job() is None

    def test_make_job_no_hosts(self, mock_db):
        """make_job returns None when no READY hosts exist."""
        from cyhy_db.models.enum import Stage

        source = DatabaseJobSource("/tmp/job.sh", job_type=Stage.NETSCAN1)

        async def _run():
            with patch(
                "cyhy_commander.job_source.db_ops.fetch_ready_hosts",
                new_callable=AsyncMock,
                return_value=[],
            ):
                result = await source.make_job()
                assert result is None

        asyncio.run(_run())

    def test_make_job_with_hosts(self, mock_db, tmp_path):
        """make_job creates a job directory when hosts are available."""
        from cyhy_db.models.enum import Stage

        # Create a fake job file
        job_file = tmp_path / "netscan1.sh"
        job_file.write_text("#!/bin/bash\necho scan")

        source = DatabaseJobSource(
            str(job_file), job_type=Stage.NETSCAN1, count=2
        )

        mock_host = MagicMock()
        mock_host.ip = "192.168.1.1"

        async def _run():
            with patch(
                "cyhy_commander.job_source.db_ops.fetch_ready_hosts",
                new_callable=AsyncMock,
                return_value=[mock_host],
            ):
                result = await source.make_job()
                assert result is not None
                assert os.path.isdir(result)
                # Should contain a job file and a targets file
                files = os.listdir(result)
                assert "job" in files
                assert any(
                    "netscan1" in f and f.endswith(".txt") for f in files
                )

        asyncio.run(_run())

    def test_make_job_vulnscan_creates_ports_file(self, mock_db, tmp_path):
        """make_job for VULNSCAN creates a ports file."""
        from cyhy_db.models.enum import Stage

        job_file = tmp_path / "vulnscan.py"
        job_file.write_text("#!/usr/bin/env python3\npass")

        source = DatabaseJobSource(
            str(job_file), job_type=Stage.VULNSCAN, count=2
        )

        mock_host = MagicMock()
        mock_host.ip = "10.0.0.1"

        async def _run():
            with (
                patch(
                    "cyhy_commander.job_source.db_ops.fetch_ready_hosts",
                    new_callable=AsyncMock,
                    return_value=[mock_host],
                ),
                patch(
                    "cyhy_commander.job_source.PortScanDoc.find",
                    return_value=MagicMock(to_list=AsyncMock(return_value=[])),
                ),
            ):
                result = await source.make_job()
                assert result is not None
                files = os.listdir(result)
                assert "ports" in files

        asyncio.run(_run())
