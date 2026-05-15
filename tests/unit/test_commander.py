"""Unit tests for Commander class."""

import asyncio
import os
import subprocess
import time
from unittest.mock import AsyncMock, MagicMock, patch

from cyhy_commander.commander import (
    Commander,
    cli_entry,
    load_config,
)
from cyhy_commander.config_model import CommanderConfig


def _make_config(**overrides):
    """Create a minimal CommanderConfig for testing."""
    defaults = {
        "mongodb_uri": "mongodb://localhost:27017/test",
        "mongodb_database": "test",
        "nmap_hosts": ["scanner1"],
        "nessus_hosts": ["nessus1"],
        "test_mode": True,
    }
    defaults.update(overrides)
    return CommanderConfig(**defaults)


class TestCommanderInit:
    """Tests for Commander.__init__."""

    def test_init_sets_attributes(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        assert cmd._Commander__is_running is True
        assert cmd._Commander__test_mode is True
        assert cmd._Commander__keep_failures is False
        assert cmd._Commander__keep_successes is False
        assert cmd._Commander__shutdown_when_idle is False
        assert cmd._Commander__next_scan_limit == 2000

    def test_init_custom_config(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config(
            keep_failures=True,
            keep_successes=True,
            shutdown_when_idle=True,
            next_scan_limit=500,
        )
        cmd = Commander(config)
        assert cmd._Commander__keep_failures is True
        assert cmd._Commander__keep_successes is True
        assert cmd._Commander__shutdown_when_idle is True
        assert cmd._Commander__next_scan_limit == 500


class TestSetupDirectories:
    """Tests for Commander.__setup_directories."""

    def test_creates_directories(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        Commander(config)
        assert (tmp_path / "done").exists()
        assert (tmp_path / "pushed").exists()
        assert (tmp_path / "failed").exists()


class TestSetupSources:
    """Tests for Commander.__setup_sources."""

    def test_test_mode_sources(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config(test_mode=True)
        cmd = Commander(config)
        cmd._Commander__setup_sources()
        # In test mode: 3 nmap sources (NETSCAN1, NETSCAN2, PORTSCAN)
        # + 1 nessus (VULNSCAN)
        assert len(cmd._Commander__nmap_sources) == 3
        assert len(cmd._Commander__nessus_sources) == 1

    def test_normal_mode_sources(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config(test_mode=False)
        cmd = Commander(config)
        cmd._Commander__setup_sources()
        # Normal mode: 3 nmap (DB) + 1 nessus (DirectoryJobSource + DatabaseJobSource)
        assert len(cmd._Commander__nmap_sources) == 3
        assert len(cmd._Commander__nessus_sources) == 2


class TestSetupSinks:
    """Tests for Commander.__setup_sinks."""

    def test_test_mode_sinks(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config(test_mode=True)
        cmd = Commander(config)
        cmd._Commander__setup_sinks()
        assert len(cmd._Commander__success_sinks) == 1
        assert "NoOpSink" in str(cmd._Commander__success_sinks[0])
        assert len(cmd._Commander__failure_sinks) == 1

    def test_normal_mode_sinks(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config(test_mode=False)
        cmd = Commander(config)
        cmd._Commander__setup_sinks()
        assert len(cmd._Commander__success_sinks) == 4
        assert len(cmd._Commander__failure_sinks) == 1


class TestHandleTerm:
    """Tests for Commander.handle_term."""

    def test_sets_is_running_false(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        assert cmd._Commander__is_running is True
        cmd.handle_term()
        assert cmd._Commander__is_running is False


class TestUniqueFilename:
    """Tests for Commander.__unique_filename."""

    def test_returns_path_if_not_exists(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        result = cmd._Commander__unique_filename(str(tmp_path / "nonexistent"))
        assert result == str(tmp_path / "nonexistent")

    def test_returns_timestamped_if_exists(self, tmp_path):
        os.chdir(tmp_path)
        existing = tmp_path / "existing"
        existing.touch()
        config = _make_config()
        cmd = Commander(config)
        result = cmd._Commander__unique_filename(str(existing))
        assert result != str(existing)
        assert "existing." in result


class TestMoveToPushed:
    """Tests for Commander.__move_to_pushed."""

    def test_test_mode_moves_to_pushed(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config(test_mode=True)
        cmd = Commander(config)
        job_dir = tmp_path / "job1"
        job_dir.mkdir()
        (job_dir / "file.txt").write_text("data")
        cmd._Commander__move_to_pushed(str(job_dir))
        assert not job_dir.exists()
        assert (tmp_path / "pushed").exists()

    def test_normal_mode_deletes(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config(test_mode=False)
        cmd = Commander(config)
        job_dir = tmp_path / "job2"
        job_dir.mkdir()
        (job_dir / "file.txt").write_text("data")
        cmd._Commander__move_to_pushed(str(job_dir))
        assert not job_dir.exists()


class TestLowestHost:
    """Tests for Commander.__lowest_host."""

    def test_returns_lowest(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        counts = {"host1": 5, "host2": 2, "host3": 8}
        assert cmd._Commander__lowest_host(counts) == "host2"

    def test_returns_none_for_empty(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        assert cmd._Commander__lowest_host({}) is None


class TestJobFromSources:
    """Tests for Commander.__job_from_sources."""

    def test_returns_job_from_first_available(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        source1 = MagicMock()
        source1.get_job.return_value = None
        source2 = MagicMock()
        source2.get_job.return_value = "/path/to/job"
        with patch("cyhy_commander.commander.RANDOMIZE_SOURCES", False):
            result = cmd._Commander__job_from_sources([source1, source2])
        assert result == "/path/to/job"

    def test_returns_none_when_no_jobs(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        source = MagicMock()
        source.get_job.return_value = None
        with patch("cyhy_commander.commander.RANDOMIZE_SOURCES", False):
            result = cmd._Commander__job_from_sources([source])
        assert result is None


class TestDoneJobs:
    """Tests for Commander.__done_jobs."""

    def test_done_jobs_success(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        cmd._Commander__successful_job_queue = asyncio.Queue()
        cmd._Commander__failed_job_queue = asyncio.Queue()

        # Mock SSH to return a job listing, then .done content, then rsync, then rm
        mock_ssh = MagicMock()
        # ls runner/done -> returns "JOB1"
        mock_ssh.run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout="JOB1", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="0", stderr=""),  # .done
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),  # rm
        ]
        mock_ssh.rsync_pull_dir = MagicMock()
        cmd._Commander__ssh = mock_ssh

        async def _run():
            await cmd._Commander__done_jobs("scanner1")
            assert not cmd._Commander__successful_job_queue.empty()

        asyncio.run(_run())

    def test_done_jobs_failed_exit_code(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        cmd._Commander__successful_job_queue = asyncio.Queue()
        cmd._Commander__failed_job_queue = asyncio.Queue()

        mock_ssh = MagicMock()
        mock_ssh.run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout="JOB1", stderr=""),
            subprocess.CompletedProcess(
                [], 0, stdout="1", stderr=""
            ),  # non-zero
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),  # rm
        ]
        mock_ssh.rsync_pull_dir = MagicMock()
        cmd._Commander__ssh = mock_ssh

        async def _run():
            await cmd._Commander__done_jobs("scanner1")
            assert not cmd._Commander__failed_job_queue.empty()

        asyncio.run(_run())


class TestRunningJobCount:
    """Tests for Commander.__running_job_count."""

    def test_returns_count(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)

        mock_ssh = MagicMock()
        mock_ssh.run.return_value = subprocess.CompletedProcess(
            [], 0, stdout="job1\njob2\njob3", stderr=""
        )
        cmd._Commander__ssh = mock_ssh

        async def _run():
            count = await cmd._Commander__running_job_count("scanner1")
            assert count == 3

        asyncio.run(_run())

    def test_returns_none_on_error(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)

        mock_ssh = MagicMock()
        mock_ssh.run.return_value = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="error"
        )
        cmd._Commander__ssh = mock_ssh

        async def _run():
            count = await cmd._Commander__running_job_count("scanner1")
            assert count is None

        asyncio.run(_run())


class TestPushJob:
    """Tests for Commander.__push_job."""

    def test_push_job_success(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config(test_mode=True)
        cmd = Commander(config)

        job_dir = tmp_path / "NETSCAN1-test"
        job_dir.mkdir()
        (job_dir / "job").write_text("script")

        mock_ssh = MagicMock()
        mock_ssh.rsync_push_dir = MagicMock()
        mock_ssh.run.return_value = subprocess.CompletedProcess(
            [], 0, stdout="", stderr=""
        )
        cmd._Commander__ssh = mock_ssh

        async def _run():
            await cmd._Commander__push_job("scanner1", str(job_dir))
            mock_ssh.rsync_push_dir.assert_called_once()
            mock_ssh.run.assert_called_once()  # touch .ready

        asyncio.run(_run())


class TestFillHosts:
    """Tests for Commander.__fill_hosts."""

    def test_fill_hosts_fills_lowest(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)

        source = MagicMock()
        source.get_job.side_effect = ["/path/job1", "/path/job2", None]

        mock_ssh = MagicMock()
        mock_ssh.rsync_push_dir = MagicMock()
        mock_ssh.run.return_value = subprocess.CompletedProcess(
            [], 0, stdout="", stderr=""
        )
        cmd._Commander__ssh = mock_ssh

        async def _run():
            counts = {"host1": 0, "host2": 1}
            with patch("cyhy_commander.commander.RANDOMIZE_SOURCES", False):
                await cmd._Commander__fill_hosts(counts, [source], "nmap", 2)

        asyncio.run(_run())


class TestProcessJobs:
    """Tests for __process_successful_job and __process_failed_job."""

    def test_process_successful_job(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config(test_mode=True)
        cmd = Commander(config)
        cmd._Commander__setup_sinks()

        job_dir = tmp_path / "NETSCAN1-20260101"
        job_dir.mkdir()
        target_file = job_dir / "NETSCAN1-20260101.txt"
        target_file.write_text("192.168.1.1\n")

        async def _run():
            with patch(
                "cyhy_commander.job_sink.db_ops.transition_host",
                new_callable=AsyncMock,
            ):
                await cmd._Commander__process_successful_job(str(job_dir))

        asyncio.run(_run())

    def test_process_failed_job(self, tmp_path, mock_db):
        os.chdir(tmp_path)
        config = _make_config(test_mode=True)
        cmd = Commander(config)
        cmd._Commander__setup_sinks()

        job_dir = tmp_path / "NETSCAN1-20260101"
        job_dir.mkdir()
        target_file = job_dir / "NETSCAN1-20260101.txt"
        target_file.write_text("192.168.1.1\n")

        async def _run():
            with patch(
                "cyhy_commander.job_sink.db_ops.transition_host",
                new_callable=AsyncMock,
            ):
                await cmd._Commander__process_failed_job(str(job_dir))

        asyncio.run(_run())


class TestCheckCooldowns:
    """Tests for Commander.__check_cooldowns."""

    def test_host_restored_after_cooldown(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        # Put a host on cooldown that expired
        cmd._Commander__hosts_on_cooldown = [
            {
                "host": "scanner1",
                "cooldown_start": time.time() - 3600,
                "work_groups": ["nmap"],
            }
        ]
        nmap_hosts = []
        nessus_hosts = []
        cmd._Commander__check_cooldowns(nmap_hosts, nessus_hosts)
        assert "scanner1" in nmap_hosts
        assert len(cmd._Commander__hosts_on_cooldown) == 0

    def test_host_stays_on_cooldown(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        cmd._Commander__hosts_on_cooldown = [
            {
                "host": "scanner1",
                "cooldown_start": time.time(),
                "work_groups": ["nmap"],
            }
        ]
        nmap_hosts = []
        nessus_hosts = []
        cmd._Commander__check_cooldowns(nmap_hosts, nessus_hosts)
        assert "scanner1" not in nmap_hosts
        assert len(cmd._Commander__hosts_on_cooldown) == 1


class TestCheckStopFile:
    """Tests for Commander.__check_stop_file_async."""

    def test_stop_file_sets_not_running(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)
        (tmp_path / "stop").touch()

        async def _run():
            await cmd._Commander__check_stop_file_async()
            assert cmd._Commander__is_running is False

        asyncio.run(_run())

    def test_no_stop_file_keeps_running(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)

        async def _run():
            await cmd._Commander__check_stop_file_async()
            assert cmd._Commander__is_running is True

        asyncio.run(_run())


class TestCheckDatabasePause:
    """Tests for Commander.__check_database_pause_async."""

    def test_no_pause(self, tmp_path):
        os.chdir(tmp_path)
        config = _make_config()
        cmd = Commander(config)

        async def _run():
            with patch(
                "cyhy_commander.commander.db_ops.should_commander_pause",
                new_callable=AsyncMock,
                return_value=False,
            ):
                await cmd._Commander__check_database_pause_async()
                assert cmd._Commander__is_running is True

        asyncio.run(_run())


class TestRunLoop:
    """Tests for Commander.run() loop."""

    def test_run_single_iteration(self, tmp_path):
        """run() exits after one iteration when _is_running is set to False."""
        os.chdir(tmp_path)
        config = _make_config(poll_interval=1)
        cmd = Commander(config)

        call_count = 0

        async def fake_check_stop():
            nonlocal call_count
            call_count += 1
            cmd._Commander__is_running = False

        async def _run():
            with (
                patch.object(
                    cmd,
                    "_Commander__check_stop_file_async",
                    side_effect=fake_check_stop,
                ),
                patch(
                    "cyhy_commander.commander.db_ops.check_host_next_scans",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.commander.db_ops.balance_ready_hosts",
                    new_callable=AsyncMock,
                ),
                patch(
                    "cyhy_commander.commander.db_ops.should_commander_pause",
                    new_callable=AsyncMock,
                    return_value=False,
                ),
            ):
                await cmd.run()

        asyncio.run(_run())
        assert call_count == 1


class TestLoadConfig:
    """Tests for load_config."""

    def test_load_config_calls_get_config(self):
        mock_config = _make_config()
        with patch(
            "cyhy_commander.commander.get_config", return_value=mock_config
        ):
            result = load_config()
            assert result.mongodb_uri == "mongodb://localhost:27017/test"


class TestCliEntry:
    """Tests for cli_entry argument parsing."""

    def test_cli_entry_parses_args(self):
        with (
            patch(
                "sys.argv",
                ["cyhy-commander", "/tmp/workdir", "--debug"],
            ),
            patch("cyhy_commander.commander.asyncio.run") as mock_run,
        ):
            cli_entry()
            mock_run.assert_called_once()
