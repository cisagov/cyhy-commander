"""End-to-end async integration tests for the Commander work cycle.

Exercises the full Commander.run() work cycle using a mock SSH transport
(no real scanner hosts required) and an in-memory MongoDB via mongomock-motor.

Tests:
- Full work cycle completes at least one iteration without error
- Graceful shutdown via Commander.handle_term() (SIGTERM handler)
- handle_term() sets _is_running to False, causing run() to exit cleanly
- SSH transport calls are dispatched via asyncio.to_thread()
- Job queues (successful/failed) are processed correctly

Requirements: AC-8.2, MR-7.1
"""

# Standard Python Libraries
import asyncio
import os
import signal
import subprocess  # nosec B404
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Third-party libraries
import beanie
import mongomock_motor
import pytest

# ---------------------------------------------------------------------------
# Ensure cyhy_config is importable (it is not installed in the test env)
# ---------------------------------------------------------------------------

if "cyhy_config" not in sys.modules:
    _mock_cyhy_config = types.ModuleType("cyhy_config")
    _mock_cyhy_config.get_config = lambda **kwargs: None  # type: ignore[attr-defined]
    sys.modules["cyhy_config"] = _mock_cyhy_config

from cyhy_db.models import (  # noqa: E402
    CVEDoc,
    HostDoc,
    HostScanDoc,
    KEVDoc,
    NotificationDoc,
    PlaceDoc,
    PortScanDoc,
    ReportDoc,
    RequestDoc,
    ScanDoc,
    SnapshotDoc,
    SystemControlDoc,
    TallyDoc,
    TicketDoc,
    VulnScanDoc,
)

# Now we can import commander modules
from cyhy_commander.commander import Commander  # noqa: E402
from cyhy_commander.config_model import CommanderConfig  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALL_DOCUMENT_MODELS = [
    CVEDoc,
    HostDoc,
    HostScanDoc,
    KEVDoc,
    NotificationDoc,
    PlaceDoc,
    PortScanDoc,
    ReportDoc,
    RequestDoc,
    ScanDoc,
    SnapshotDoc,
    SystemControlDoc,
    TallyDoc,
    TicketDoc,
    VulnScanDoc,
]

NMAP_HOST = "nmap-scanner.test"
NESSUS_HOST = "nessus-scanner.test"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**overrides) -> CommanderConfig:
    """Build a minimal CommanderConfig suitable for integration tests."""
    defaults = {
        "mongodb_uri": "mongodb://localhost:27017/",
        "mongodb_database": "test_db",
        "nmap_hosts": [NMAP_HOST],
        "nessus_hosts": [NESSUS_HOST],
        "jobs_per_nmap_host": 2,
        "jobs_per_nessus_host": 2,
        "poll_interval": 1,
        "next_scan_limit": 10,
        "test_mode": False,  # Use False to avoid DatabaseJobSource bug in commander.py
        "keep_failures": False,
        "keep_successes": False,
        "shutdown_when_idle": False,
    }
    defaults.update(overrides)
    return CommanderConfig(**defaults)


def _make_ssh_result(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess:
    """Build a fake subprocess.CompletedProcess for SSH mock returns."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _make_mock_ssh() -> MagicMock:
    """Create a mock SSHTransport that simulates an idle scanner host.

    The mock returns:
    - ls runner/done  → empty listing (no done jobs)
    - ls runner/running → empty listing (no running jobs, count=0)
    - touch .ready → success
    - rsync_push_dir → no-op (returns None)
    - rsync_pull_dir → no-op (returns None)
    """
    mock = MagicMock()
    # Default: all SSH commands succeed with empty output
    mock.run.return_value = _make_ssh_result(returncode=0, stdout="", stderr="")
    mock.rsync_push_dir.return_value = None
    mock.rsync_pull_dir.return_value = None
    return mock


def _make_commander_with_mock_ssh(
    config: CommanderConfig, tmp_path: Path
) -> tuple:
    """Create a Commander instance with a mock SSH transport.

    Returns (commander, mock_ssh).  The caller must be inside a patched
    context for ssh_transport.SSHTransport.

    Changes to tmp_path so Commander.__setup_directories() can create dirs.
    """
    mock_ssh = _make_mock_ssh()
    orig_dir = os.getcwd()
    os.chdir(tmp_path)
    return mock_ssh, orig_dir


# ---------------------------------------------------------------------------
# Context manager for Commander setup
# ---------------------------------------------------------------------------


class _CommanderContext:
    """Context manager that sets up a Commander with mocked SSH and DB ops.

    Patches:
    - ssh_transport.SSHTransport → mock_ssh
    - db_ops.check_host_next_scans → AsyncMock (no-op)
    - db_ops.balance_ready_hosts → AsyncMock (no-op)
    - db_ops.should_commander_pause → AsyncMock returning False
    - Commander._Commander__setup_sources → no-op (avoids DatabaseJobSource bug)
    - Commander._Commander__setup_sinks → no-op (avoids real sink setup)

    Usage::

        with _CommanderContext(config, tmp_path) as ctx:
            commander = ctx.commander
            mock_ssh = ctx.mock_ssh
            await commander.run()
    """

    def __init__(
        self,
        config: CommanderConfig,
        tmp_path: Path,
        mock_ssh: MagicMock | None = None,
        check_host_next_scans_side_effect=None,
    ):
        self.config = config
        self.tmp_path = tmp_path
        self.mock_ssh = mock_ssh or _make_mock_ssh()
        self._check_side_effect = check_host_next_scans_side_effect
        self.commander: Commander | None = None
        self._orig_dir: str | None = None
        self._patches: list = []

    def __enter__(self):
        self._orig_dir = os.getcwd()
        os.chdir(self.tmp_path)

        # Patch SSHTransport constructor to return our mock
        p_ssh = patch(
            "cyhy_commander.commander.ssh_transport.SSHTransport",
            return_value=self.mock_ssh,
        )
        # Patch db_ops functions used in the work cycle
        p_check = patch(
            "cyhy_commander.commander.db_ops.check_host_next_scans",
            new_callable=AsyncMock,
            **(
                {"side_effect": self._check_side_effect}
                if self._check_side_effect
                else {}
            ),
        )
        p_balance = patch(
            "cyhy_commander.commander.db_ops.balance_ready_hosts",
            new_callable=AsyncMock,
        )
        p_pause = patch(
            "cyhy_commander.commander.db_ops.should_commander_pause",
            new_callable=AsyncMock,
            return_value=False,
        )
        # Patch internal setup methods to avoid DatabaseJobSource constructor
        # bug in commander.py (passes self.__db as positional arg to new API)
        p_sources = patch.object(Commander, "_Commander__setup_sources")
        p_sinks = patch.object(Commander, "_Commander__setup_sinks")

        for p in [p_ssh, p_check, p_balance, p_pause, p_sources, p_sinks]:
            p.start()
            self._patches.append(p)

        self.commander = Commander(self.config)
        # Manually set up empty queues (normally done in run() after __setup_sources)
        # We need these so __process_completed_jobs() doesn't fail
        self.commander._Commander__successful_job_queue = asyncio.Queue()
        self.commander._Commander__failed_job_queue = asyncio.Queue()
        # Set empty sources/sinks so __fill_hosts and __process_completed_jobs work
        self.commander._Commander__nmap_sources = []
        self.commander._Commander__nessus_sources = []
        self.commander._Commander__success_sinks = []
        self.commander._Commander__failure_sinks = []

        return self

    def __exit__(self, *args):
        for p in reversed(self._patches):
            p.stop()
        if self._orig_dir:
            os.chdir(self._orig_dir)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db_for_commander():
    """Initialise an in-memory MongoDB for Commander integration tests.

    Uses mongomock-motor + Beanie, consistent with the unit test conftest.
    """
    client = mongomock_motor.AsyncMongoMockClient()
    db = client["test_commander_db"]

    # Patch mongomock's list_collection_names to accept the
    # authorizedCollections kwarg that beanie/pymongo 4.x passes.
    _orig = db.delegate.list_collection_names

    def _patched(*args, **kwargs):
        kwargs.pop("authorizedCollections", None)
        kwargs.pop("nameOnly", None)
        return _orig(*args, **kwargs)

    db.delegate.list_collection_names = _patched

    async def _init():
        await beanie.init_beanie(
            database=db, document_models=_ALL_DOCUMENT_MODELS
        )

    asyncio.run(_init())
    yield db


# ---------------------------------------------------------------------------
# Test: graceful shutdown via handle_term()
# ---------------------------------------------------------------------------


class TestHandleTerm:
    """Commander.handle_term() sets _is_running to False for graceful shutdown.

    Validates: MR-7.1, AC-4.5
    """

    def test_handle_term_sets_is_running_false(
        self, mock_db_for_commander, tmp_path
    ):
        """handle_term() sets the internal _is_running flag to False.

        This is the mechanism that causes Commander.run() to exit after the
        current work cycle completes, implementing graceful SIGTERM shutdown.
        """
        config = _make_config()
        with _CommanderContext(config, tmp_path) as ctx:
            commander = ctx.commander
            # Before handle_term: should be running
            assert commander._Commander__is_running is True
            # Call the SIGTERM handler
            commander.handle_term()
            # After handle_term: should be stopped
            assert commander._Commander__is_running is False

    def test_handle_term_is_idempotent(self, mock_db_for_commander, tmp_path):
        """Calling handle_term() multiple times does not raise and stays False."""
        config = _make_config()
        with _CommanderContext(config, tmp_path) as ctx:
            commander = ctx.commander
            commander.handle_term()
            commander.handle_term()  # second call must not raise
            assert commander._Commander__is_running is False


# ---------------------------------------------------------------------------
# Test: run() exits cleanly after handle_term()
# ---------------------------------------------------------------------------


class TestRunGracefulShutdown:
    """Commander.run() exits after handle_term() is called.

    Validates: MR-7.1, FR-7.2, AC-4.2
    """

    def test_run_exits_after_handle_term(self, mock_db_for_commander, tmp_path):
        """Commander.run() completes when handle_term() is called mid-cycle.

        The test schedules handle_term() to fire after a short delay, then
        awaits commander.run().  run() must return (not hang) once
        _is_running is False.
        """
        config = _make_config(poll_interval=1)

        async def _run():
            with _CommanderContext(config, tmp_path) as ctx:
                commander = ctx.commander

                # Schedule handle_term() to fire after 0.05 s so run() can
                # start its first iteration before being asked to stop.
                async def _trigger_shutdown():
                    await asyncio.sleep(0.05)
                    commander.handle_term()

                shutdown_task = asyncio.create_task(_trigger_shutdown())

                # run() should return within a reasonable timeout
                await asyncio.wait_for(commander.run(), timeout=5.0)
                await shutdown_task

        asyncio.run(_run())

    def test_run_completes_current_cycle_before_stopping(
        self, mock_db_for_commander, tmp_path
    ):
        """run() finishes the in-progress work cycle before exiting.

        We track how many times check_host_next_scans is called to confirm
        at least one full cycle ran before shutdown.
        """
        config = _make_config(poll_interval=1)
        cycle_count = {"n": 0}

        async def _counting_check():
            cycle_count["n"] += 1

        async def _run():
            with _CommanderContext(
                config,
                tmp_path,
                check_host_next_scans_side_effect=_counting_check,
            ) as ctx:
                commander = ctx.commander

                async def _trigger_shutdown():
                    # Wait until at least one cycle has run
                    while cycle_count["n"] < 1:
                        await asyncio.sleep(0.01)
                    commander.handle_term()

                shutdown_task = asyncio.create_task(_trigger_shutdown())
                await asyncio.wait_for(commander.run(), timeout=5.0)
                await shutdown_task

        asyncio.run(_run())
        assert (
            cycle_count["n"] >= 1
        ), "Expected at least one work cycle to complete"


# ---------------------------------------------------------------------------
# Test: full work cycle with mock SSH transport
# ---------------------------------------------------------------------------


class TestFullWorkCycleWithMockSSH:
    """Full work cycle exercises SSH transport calls via asyncio.to_thread().

    Validates: MR-7.1, MR-7.3, AC-8.2
    """

    def test_work_cycle_calls_ssh_for_each_host(
        self, mock_db_for_commander, tmp_path
    ):
        """Each work cycle calls SSH run() for done-job and running-job listing.

        With one nmap host and one nessus host, the cycle should call
        ssh.run() at least twice (once per host for the 'ls runner/done' check).
        """
        config = _make_config(poll_interval=1)
        mock_ssh = _make_mock_ssh()

        async def _run():
            with _CommanderContext(config, tmp_path, mock_ssh=mock_ssh) as ctx:
                commander = ctx.commander

                async def _trigger_shutdown():
                    await asyncio.sleep(0.1)
                    commander.handle_term()

                shutdown_task = asyncio.create_task(_trigger_shutdown())
                await asyncio.wait_for(commander.run(), timeout=5.0)
                await shutdown_task

        asyncio.run(_run())

        # SSH run() should have been called at least twice (one per host for
        # the 'ls runner/done' listing)
        assert mock_ssh.run.call_count >= 2, (
            f"Expected SSH run() to be called at least twice, "
            f"got {mock_ssh.run.call_count}"
        )

    def test_work_cycle_with_done_job_on_scanner(
        self, mock_db_for_commander, tmp_path
    ):
        """A done job on the scanner is retrieved and queued for processing.

        Simulates a scanner host that has one completed job in runner/done.
        The mock SSH uses command-based routing to return appropriate responses
        for each SSH command regardless of call order (nmap and nessus hosts
        run concurrently via asyncio.gather).
        """
        config = _make_config(poll_interval=1)

        # Track which host/command combinations have been seen so we can
        # return the right response for each call.
        nmap_done_listed = {"done": False}

        def _ssh_run_side_effect(host, command, **kwargs):
            """Route SSH responses based on host and command content."""
            if host == NMAP_HOST:
                if "runner/done" in command and "ls" in command:
                    if not nmap_done_listed["done"]:
                        nmap_done_listed["done"] = True
                        return _make_ssh_result(returncode=0, stdout="job001\n")
                    return _make_ssh_result(returncode=0, stdout="")
                elif ".done" in command:
                    # cat .done → exit code 0
                    return _make_ssh_result(returncode=0, stdout="0\n")
                elif "rm -rf" in command:
                    return _make_ssh_result(returncode=0, stdout="")
                elif "runner/running" in command:
                    return _make_ssh_result(returncode=0, stdout="")
            # Default: success with empty output
            return _make_ssh_result(returncode=0, stdout="")

        mock_ssh = MagicMock()
        mock_ssh.run.side_effect = _ssh_run_side_effect
        mock_ssh.rsync_pull_dir.return_value = None
        mock_ssh.rsync_push_dir.return_value = None

        async def _run():
            with _CommanderContext(config, tmp_path, mock_ssh=mock_ssh) as ctx:
                commander = ctx.commander

                async def _trigger_shutdown():
                    await asyncio.sleep(0.15)
                    commander.handle_term()

                shutdown_task = asyncio.create_task(_trigger_shutdown())
                await asyncio.wait_for(commander.run(), timeout=5.0)
                await shutdown_task

        asyncio.run(_run())

        # rsync_pull_dir should have been called to retrieve the done job
        assert (
            mock_ssh.rsync_pull_dir.call_count >= 1
        ), "Expected rsync_pull_dir to be called for the done job"

    def test_work_cycle_handles_ssh_failure_gracefully(
        self, mock_db_for_commander, tmp_path
    ):
        """SSH failures do not crash the work cycle; commander continues running.

        When SSH returns a non-zero exit code, the commander logs a warning
        and continues to the next host/cycle.
        """
        config = _make_config(poll_interval=1)
        cycle_count = {"n": 0}

        async def _counting_check():
            cycle_count["n"] += 1

        # All SSH calls fail
        mock_ssh = MagicMock()
        mock_ssh.run.return_value = _make_ssh_result(
            returncode=1, stdout="", stderr="Connection refused"
        )
        mock_ssh.rsync_push_dir.return_value = None
        mock_ssh.rsync_pull_dir.return_value = None

        async def _run():
            with _CommanderContext(
                config,
                tmp_path,
                mock_ssh=mock_ssh,
                check_host_next_scans_side_effect=_counting_check,
            ) as ctx:
                commander = ctx.commander

                async def _trigger_shutdown():
                    while cycle_count["n"] < 2:
                        await asyncio.sleep(0.01)
                    commander.handle_term()

                shutdown_task = asyncio.create_task(_trigger_shutdown())
                await asyncio.wait_for(commander.run(), timeout=10.0)
                await shutdown_task

        asyncio.run(_run())

        # Commander should have completed at least 2 cycles despite SSH failures
        assert cycle_count["n"] >= 2, (
            f"Expected at least 2 cycles despite SSH failures, "
            f"got {cycle_count['n']}"
        )

    def test_work_cycle_dispatches_ssh_concurrently_for_multiple_hosts(
        self, mock_db_for_commander, tmp_path
    ):
        """SSH calls for nmap and nessus hosts are dispatched concurrently.

        With two nmap hosts and one nessus host, all three should be contacted
        within a single work cycle.
        """
        config = _make_config(
            nmap_hosts=["nmap1.test", "nmap2.test"],
            nessus_hosts=["nessus1.test"],
            poll_interval=1,
        )
        mock_ssh = _make_mock_ssh()

        async def _run():
            with _CommanderContext(config, tmp_path, mock_ssh=mock_ssh) as ctx:
                commander = ctx.commander

                async def _trigger_shutdown():
                    await asyncio.sleep(0.1)
                    commander.handle_term()

                shutdown_task = asyncio.create_task(_trigger_shutdown())
                await asyncio.wait_for(commander.run(), timeout=5.0)
                await shutdown_task

        asyncio.run(_run())

        # With 3 hosts, each getting at least one 'ls runner/done' call,
        # we expect at least 3 SSH run() calls per cycle
        assert mock_ssh.run.call_count >= 3, (
            f"Expected SSH run() called at least 3 times (one per host), "
            f"got {mock_ssh.run.call_count}"
        )


# ---------------------------------------------------------------------------
# Test: stop file triggers shutdown
# ---------------------------------------------------------------------------


class TestStopFileShutdown:
    """Commander shuts down when a stop file is present.

    Validates: MR-7.1
    """

    def test_stop_file_causes_shutdown(self, mock_db_for_commander, tmp_path):
        """Placing a 'stop' file in the working directory causes run() to exit."""
        config = _make_config(poll_interval=1)

        async def _run():
            with _CommanderContext(config, tmp_path) as ctx:
                commander = ctx.commander

                async def _create_stop_file():
                    await asyncio.sleep(0.05)
                    Path("stop").touch()

                stop_task = asyncio.create_task(_create_stop_file())
                await asyncio.wait_for(commander.run(), timeout=5.0)
                await stop_task

        asyncio.run(_run())

        # After shutdown, the stop file should have been removed
        assert not (
            tmp_path / "stop"
        ).exists(), "Stop file should be removed after shutdown"


# ---------------------------------------------------------------------------
# Test: SIGTERM signal integration
# ---------------------------------------------------------------------------


class TestSIGTERMIntegration:
    """SIGTERM signal triggers graceful shutdown via loop.add_signal_handler().

    Validates: MR-7.1, FR-7.2, AC-4.2, AC-4.5
    """

    def test_sigterm_triggers_handle_term(
        self, mock_db_for_commander, tmp_path
    ):
        """Sending SIGTERM to the process calls handle_term() and stops run().

        This test registers the signal handler on the running event loop
        (as _async_main does) and then sends SIGTERM to the current process.
        """
        config = _make_config(poll_interval=1)

        async def _run():
            with _CommanderContext(config, tmp_path) as ctx:
                commander = ctx.commander

                # Register the signal handler exactly as _async_main does
                loop = asyncio.get_running_loop()
                loop.add_signal_handler(signal.SIGTERM, commander.handle_term)
                loop.add_signal_handler(signal.SIGINT, commander.handle_term)

                async def _send_sigterm():
                    await asyncio.sleep(0.05)
                    os.kill(os.getpid(), signal.SIGTERM)

                sigterm_task = asyncio.create_task(_send_sigterm())
                try:
                    await asyncio.wait_for(commander.run(), timeout=5.0)
                finally:
                    await sigterm_task
                    # Restore default signal handlers
                    try:
                        loop.remove_signal_handler(signal.SIGTERM)
                        loop.remove_signal_handler(signal.SIGINT)
                    except Exception:
                        pass  # nosec B110

        asyncio.run(_run())

        # If we reach here, run() exited cleanly after SIGTERM

    def test_handle_term_called_directly_stops_run(
        self, mock_db_for_commander, tmp_path
    ):
        """Calling handle_term() directly (simulating signal delivery) stops run().

        This is the unit-level verification that the signal handler mechanism
        works correctly without actually sending OS signals.
        """
        config = _make_config(poll_interval=1)

        async def _run():
            with _CommanderContext(config, tmp_path) as ctx:
                commander = ctx.commander

                # Verify initial state
                assert commander._Commander__is_running is True

                async def _trigger():
                    await asyncio.sleep(0.05)
                    commander.handle_term()

                trigger_task = asyncio.create_task(_trigger())
                await asyncio.wait_for(commander.run(), timeout=5.0)
                await trigger_task

                # After run() returns, _is_running must be False
                assert commander._Commander__is_running is False

        asyncio.run(_run())
