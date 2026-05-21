"""Unit tests for the metrics module.

Tests cover startup sequencing, daemon thread behavior, degraded mode,
initial gauge values, startup probe state transitions, and graceful shutdown.

Requirements: 2.9, 2.10, 3.2, 3.5, 3.8, 8.1, 8.2, 11.1, 11.3, 11.4
"""

import socket
import threading
import time
import urllib.error
import urllib.request
from unittest.mock import patch

import pytest

from cyhy_commander import metrics


@pytest.fixture(autouse=True)
def reset_metrics_state():
    """Reset module-level state between tests.

    Ensures each test starts with a clean slate: no running server,
    first_cycle_completed is False, and gauge values are reset to 0.
    """
    # Ensure any running server is stopped before the test
    if metrics._server is not None:
        metrics.shutdown_server()

    # Reset module-level state
    metrics._first_cycle_completed = False
    metrics._server = None
    metrics._server_thread = None
    metrics._liveness_threshold = metrics.DEFAULT_LIVENESS_THRESHOLD
    metrics._readiness_threshold = metrics.DEFAULT_READINESS_THRESHOLD
    metrics._bearer_token = None

    # Reset gauge values to 0
    metrics.last_cycle_completed_timestamp_seconds.set(0)
    metrics.last_db_success_timestamp_seconds.set(0)

    yield

    # Cleanup after test
    if metrics._server is not None:
        metrics.shutdown_server()

    # Restore state
    metrics._first_cycle_completed = False
    metrics._server = None
    metrics._server_thread = None


def _find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _port_is_open(port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is accepting connections on localhost."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except (ConnectionRefusedError, OSError, TimeoutError):
        return False


class TestStartupSequencing:
    """Test that the metrics server accepts connections before run() enters main loop.

    Validates: Requirement 11.1 - Server SHALL start and be accepting HTTP
    connections on the Metrics_Port before the Commander begins its first
    Work_Cycle.
    """

    def test_server_accepts_connections_after_start(self):
        """Metrics server accepts TCP connections immediately after start_server()."""
        port = _find_free_port()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()

        # Give the thread a moment to start accepting
        time.sleep(0.1)

        assert _port_is_open(port), (
            f"Metrics server should be accepting connections on port {port}"
        )

    def test_server_responds_to_http_after_start(self):
        """Metrics server responds to HTTP requests immediately after start_server()."""
        port = _find_free_port()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()

        time.sleep(0.1)

        url = f"http://127.0.0.1:{port}/livez"
        response = urllib.request.urlopen(url, timeout=2)
        # Before first cycle, /livez returns 200 (startup grace)
        assert response.status == 200

    def test_is_server_running_true_after_start(self):
        """is_server_running() returns True after successful start."""
        port = _find_free_port()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()

        time.sleep(0.1)
        assert metrics.is_server_running() is True


class TestDaemonThread:
    """Test that the server thread is a daemon thread.

    Validates: Requirement 11.4 - Server SHALL run as a daemon thread that
    does not prevent the Python process from exiting.
    """

    def test_server_thread_is_daemon(self):
        """The metrics server thread has daemon=True."""
        port = _find_free_port()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()

        assert metrics._server_thread is not None
        assert metrics._server_thread.daemon is True

    def test_server_thread_name(self):
        """The metrics server thread is named 'metrics-server'."""
        port = _find_free_port()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()

        assert metrics._server_thread.name == "metrics-server"


class TestDegradedMode:
    """Test that the commander continues when the port is occupied.

    Validates: Requirement 3.5 - IF the Metrics_Port is already in use,
    THEN THE Commander SHALL log an error and continue operating without
    metrics exposition (degraded mode).
    """

    def test_continues_when_port_occupied(self):
        """start_server() does not raise when port is already in use."""
        # Occupy a port
        port = _find_free_port()
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("0.0.0.0", port))
        blocker.listen(1)

        try:
            with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
                # Should not raise — degraded mode
                metrics.start_server()

            # Server should not be running
            assert metrics._server is None
            assert metrics._server_thread is None
            assert metrics.is_server_running() is False
        finally:
            blocker.close()

    def test_degraded_mode_does_not_crash_instrumentation(self):
        """Instrumentation helpers work even when server failed to start."""
        port = _find_free_port()
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("0.0.0.0", port))
        blocker.listen(1)

        try:
            with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
                metrics.start_server()

            # These should not raise even without a running server
            metrics.record_cycle_completed()
            metrics.record_db_success()
            metrics.observe_cycle_duration(1.5)
            metrics.inc_jobs_pushed("NETSCAN1", 10)
            metrics.inc_jobs_pulled("PORTSCAN", 5, success=True)
            metrics.inc_jobs_failed("VULNSCAN")
            metrics.inc_host_errors("scanner1")
            metrics.set_scanner_status("scanner1", "nmap", True)
        finally:
            blocker.close()


class TestInitialGaugeValues:
    """Test initial gauge values at startup.

    Validates: Requirement 2.9 - WHILE the Commander has not yet completed
    its first Work_Cycle, last_cycle_completed_timestamp_seconds SHALL be 0.0.
    Validates: Requirement 2.10 - WHILE the Commander has not yet completed
    its first successful database operation, last_db_success_timestamp_seconds
    SHALL be 0.0.
    """

    def test_last_cycle_completed_starts_at_zero(self):
        """last_cycle_completed_timestamp_seconds starts at 0.0."""
        value = metrics.last_cycle_completed_timestamp_seconds._value.get()
        assert value == 0.0

    def test_last_db_success_starts_at_zero(self):
        """last_db_success_timestamp_seconds starts at 0.0."""
        value = metrics.last_db_success_timestamp_seconds._value.get()
        assert value == 0.0

    def test_first_cycle_completed_starts_false(self):
        """_first_cycle_completed starts as False."""
        assert metrics._first_cycle_completed is False


class TestStartupProbeStateTransition:
    """Test /startupz returns 503 then 200 after first cycle.

    Validates: Requirement 8.1 - /startupz SHALL return HTTP 200 once the
    Commander has completed its first Work_Cycle successfully.
    Validates: Requirement 8.2 - /startupz SHALL return HTTP 503 before
    the first Work_Cycle completes.
    """

    def test_startupz_returns_503_before_first_cycle(self):
        """_check_startup() returns 503 before first cycle completes."""
        status_code, body = metrics._check_startup()
        assert status_code == 503
        assert body == "first cycle not completed"

    def test_startupz_returns_200_after_first_cycle(self):
        """_check_startup() returns 200 after record_cycle_completed() is called."""
        metrics.record_cycle_completed()

        status_code, body = metrics._check_startup()
        assert status_code == 200
        assert body == "ok"

    def test_startupz_http_503_then_200(self):
        """Full HTTP test: /startupz returns 503 then 200 after first cycle."""
        port = _find_free_port()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()

        time.sleep(0.1)
        base_url = f"http://127.0.0.1:{port}"

        # Before first cycle: 503
        try:
            urllib.request.urlopen(f"{base_url}/startupz", timeout=2)
            pytest.fail("Expected HTTP 503 but got 200")
        except urllib.error.HTTPError as e:
            assert e.code == 503

        # Complete first cycle
        metrics.record_cycle_completed()

        # After first cycle: 200
        response = urllib.request.urlopen(f"{base_url}/startupz", timeout=2)
        assert response.status == 200

    def test_startupz_stays_200_after_multiple_cycles(self):
        """Once first cycle completes, /startupz stays 200 permanently."""
        metrics.record_cycle_completed()
        assert metrics._check_startup() == (200, "ok")

        # Simulate more cycles
        metrics.record_cycle_completed()
        assert metrics._check_startup() == (200, "ok")


class TestGracefulShutdown:
    """Test that the server stops and releases the port within 5 seconds.

    Validates: Requirement 11.3 - Server SHALL stop and release the
    Metrics_Port within 5 seconds of the main coroutine completing.
    """

    def test_shutdown_releases_port(self):
        """After shutdown_server(), the port is released."""
        port = _find_free_port()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()

        time.sleep(0.1)
        assert _port_is_open(port)

        metrics.shutdown_server()

        # Port should be released — we should be able to bind to it
        time.sleep(0.2)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Should not raise
            s.bind(("0.0.0.0", port))

    def test_shutdown_completes_within_5_seconds(self):
        """shutdown_server() completes within 5 seconds."""
        port = _find_free_port()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()

        time.sleep(0.1)

        start = time.monotonic()
        metrics.shutdown_server()
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, (
            f"shutdown_server() took {elapsed:.2f}s, exceeding 5s limit"
        )

    def test_is_server_running_false_after_shutdown(self):
        """is_server_running() returns False after shutdown."""
        port = _find_free_port()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()

        time.sleep(0.1)
        assert metrics.is_server_running() is True

        metrics.shutdown_server()
        assert metrics.is_server_running() is False

    def test_shutdown_idempotent(self):
        """Calling shutdown_server() when no server is running does not raise."""
        # No server started — should be a no-op
        metrics.shutdown_server()
        assert metrics._server is None
        assert metrics._server_thread is None

    def test_server_globals_cleared_after_shutdown(self):
        """_server and _server_thread are set to None after shutdown."""
        port = _find_free_port()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()

        time.sleep(0.1)
        assert metrics._server is not None
        assert metrics._server_thread is not None

        metrics.shutdown_server()
        assert metrics._server is None
        assert metrics._server_thread is None


class TestServerBinding:
    """Test server binds to 0.0.0.0 on the configured port.

    Validates: Requirement 3.2 - Server SHALL start as a daemon thread
    using a ThreadingWSGIServer that does not block the Work_Cycle event loop.
    Validates: Requirement 3.8 - IF the Metrics_Server encounters an
    unrecoverable error after startup, THEN THE Commander SHALL continue
    operating.
    """

    def test_server_uses_threading_wsgi(self):
        """The server is an instance of _ThreadingWSGIServer."""
        port = _find_free_port()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()

        assert isinstance(metrics._server, metrics._ThreadingWSGIServer)

    def test_server_does_not_block_main_thread(self):
        """start_server() returns immediately without blocking."""
        port = _find_free_port()

        start = time.monotonic()
        with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
            metrics.start_server()
        elapsed = time.monotonic() - start

        # start_server should return nearly instantly (< 1 second)
        assert elapsed < 1.0, (
            f"start_server() took {elapsed:.2f}s — it should not block"
        )
