"""Integration tests for the WSGI metrics/health server.

Tests cover the full server lifecycle, Prometheus exposition format,
health endpoint responses, and concurrent request handling.

Requirements: 3.1, 3.3, 3.4, 3.10, 3.11, 3.12, 6.1
"""

import concurrent.futures
import socket
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


def _start_server_on_free_port() -> int:
    """Start the metrics server on a free port and return the port number."""
    port = _find_free_port()
    with patch.dict("os.environ", {"CYHY_METRICS_PORT": str(port)}):
        metrics.start_server()
    time.sleep(0.1)
    return port


class TestFullServerLifecycle:
    """Test the complete server lifecycle: start, serve, shutdown.

    Validates: Requirements 3.1, 6.1
    """

    def test_start_serve_all_endpoints_shutdown(self):
        """Server starts, serves all endpoints, and shuts down cleanly."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        # Verify server is running
        assert metrics.is_server_running() is True

        # Hit /livez (returns 200 during startup grace)
        resp = urllib.request.urlopen(f"{base_url}/livez", timeout=2)
        assert resp.status == 200

        # Hit /readyz (returns 503 before first DB op)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{base_url}/readyz", timeout=2)
        assert exc_info.value.code == 503

        # Hit /startupz (returns 503 before first cycle)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{base_url}/startupz", timeout=2)
        assert exc_info.value.code == 503

        # Hit /metrics (returns 200 with Prometheus data)
        resp = urllib.request.urlopen(f"{base_url}/metrics", timeout=2)
        assert resp.status == 200

        # Shutdown
        metrics.shutdown_server()
        assert metrics.is_server_running() is False

    def test_server_not_reachable_after_shutdown(self):
        """After shutdown, the server no longer accepts connections."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        # Verify it's reachable
        resp = urllib.request.urlopen(f"{base_url}/livez", timeout=2)
        assert resp.status == 200

        # Shutdown
        metrics.shutdown_server()
        time.sleep(0.2)

        # Should no longer be reachable
        with pytest.raises((urllib.error.URLError, ConnectionRefusedError, OSError)):
            urllib.request.urlopen(f"{base_url}/livez", timeout=1)


class TestMetricsEndpoint:
    """Test /metrics returns valid Prometheus exposition format.

    Validates: Requirements 3.1, 3.3
    """

    def test_metrics_returns_prometheus_format(self):
        """/metrics returns text in Prometheus exposition format."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        resp = urllib.request.urlopen(f"{base_url}/metrics", timeout=2)
        content = resp.read().decode("utf-8")

        # Prometheus exposition format contains HELP and TYPE lines
        assert "# HELP" in content
        assert "# TYPE" in content

        # Should contain our defined metrics
        assert "cyhy_commander_work_cycle_duration_seconds" in content
        assert "cyhy_commander_last_cycle_completed_timestamp_seconds" in content
        assert "cyhy_commander_last_db_success_timestamp_seconds" in content

    def test_metrics_content_type(self):
        """/metrics returns appropriate content type for Prometheus."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        resp = urllib.request.urlopen(f"{base_url}/metrics", timeout=2)
        content_type = resp.headers.get("Content-Type", "")

        # Prometheus client returns text/plain or the OpenMetrics type
        assert "text/plain" in content_type or "text/openmetrics" in content_type

    def test_metrics_reflects_recorded_values(self):
        """/metrics reflects values recorded via instrumentation helpers."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        # Record some metrics
        metrics.inc_jobs_pushed("NETSCAN1", 5)
        metrics.inc_jobs_pushed("NETSCAN1", 3)
        metrics.record_cycle_completed()

        resp = urllib.request.urlopen(f"{base_url}/metrics", timeout=2)
        content = resp.read().decode("utf-8")

        # jobs_pushed_total for NETSCAN1 should be 2 (two inc calls)
        assert 'cyhy_commander_jobs_pushed_total{stage="NETSCAN1"} 2.0' in content
        # ips_pushed_total for NETSCAN1 should be 8 (5 + 3)
        assert 'cyhy_commander_ips_pushed_total{stage="NETSCAN1"} 8.0' in content
        # last_cycle_completed_timestamp should be non-zero
        assert "cyhy_commander_last_cycle_completed_timestamp_seconds" in content


class TestHealthEndpointContentType:
    """Test all health endpoints return correct Content-Type and status codes.

    Validates: Requirements 3.4, 3.10, 3.11, 3.12
    """

    def test_livez_content_type_is_text_plain(self):
        """/livez returns Content-Type: text/plain."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        resp = urllib.request.urlopen(f"{base_url}/livez", timeout=2)
        assert "text/plain" in resp.headers.get("Content-Type", "")

    def test_readyz_content_type_is_text_plain(self):
        """/readyz returns Content-Type: text/plain."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        # readyz returns 503 before first DB op
        try:
            urllib.request.urlopen(f"{base_url}/readyz", timeout=2)
        except urllib.error.HTTPError as e:
            assert "text/plain" in e.headers.get("Content-Type", "")

    def test_startupz_content_type_is_text_plain(self):
        """/startupz returns Content-Type: text/plain."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        # startupz returns 503 before first cycle
        try:
            urllib.request.urlopen(f"{base_url}/startupz", timeout=2)
        except urllib.error.HTTPError as e:
            assert "text/plain" in e.headers.get("Content-Type", "")

    def test_livez_returns_200_during_startup_grace(self):
        """/livez returns 200 before first cycle (startup grace period).

        Validates: Requirement 3.10
        """
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        resp = urllib.request.urlopen(f"{base_url}/livez", timeout=2)
        assert resp.status == 200
        assert resp.read() == b"ok"

    def test_livez_returns_200_when_cycle_fresh(self):
        """/livez returns 200 when last cycle is within threshold."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        # Complete a cycle to set the timestamp
        metrics.record_cycle_completed()

        resp = urllib.request.urlopen(f"{base_url}/livez", timeout=2)
        assert resp.status == 200
        assert resp.read() == b"ok"

    def test_livez_returns_503_when_cycle_stale(self):
        """/livez returns 503 when last cycle exceeds threshold.

        Validates: Requirement 3.10
        """
        port = _find_free_port()
        # Use a very short threshold so we can trigger staleness
        with patch.dict(
            "os.environ",
            {"CYHY_METRICS_PORT": str(port), "CYHY_LIVENESS_THRESHOLD_SECONDS": "1"},
        ):
            metrics.start_server()
        time.sleep(0.1)
        base_url = f"http://127.0.0.1:{port}"

        # Complete a cycle, then wait for it to go stale
        metrics.record_cycle_completed()
        time.sleep(1.1)

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{base_url}/livez", timeout=2)
        assert exc_info.value.code == 503
        assert exc_info.value.read() == b"work cycle stale"

    def test_readyz_returns_503_before_first_db_op(self):
        """/readyz returns 503 before any DB operation succeeds.

        Validates: Requirement 3.11
        """
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{base_url}/readyz", timeout=2)
        assert exc_info.value.code == 503
        assert exc_info.value.read() == b"database connection stale"

    def test_readyz_returns_200_after_db_success(self):
        """/readyz returns 200 after a successful DB operation.

        Validates: Requirement 3.11
        """
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        metrics.record_db_success()

        resp = urllib.request.urlopen(f"{base_url}/readyz", timeout=2)
        assert resp.status == 200
        assert resp.read() == b"ok"

    def test_startupz_returns_503_before_first_cycle(self):
        """/startupz returns 503 before first cycle completes.

        Validates: Requirement 3.12
        """
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{base_url}/startupz", timeout=2)
        assert exc_info.value.code == 503
        assert exc_info.value.read() == b"first cycle not completed"

    def test_startupz_returns_200_after_first_cycle(self):
        """/startupz returns 200 after first cycle completes.

        Validates: Requirement 3.12
        """
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        metrics.record_cycle_completed()

        resp = urllib.request.urlopen(f"{base_url}/startupz", timeout=2)
        assert resp.status == 200
        assert resp.read() == b"ok"

    def test_unknown_path_returns_404(self):
        """Unknown paths return 404 with empty body."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{base_url}/nonexistent", timeout=2)
        assert exc_info.value.code == 404
        assert exc_info.value.read() == b""


class TestConcurrentRequests:
    """Test that ThreadingWSGIServer handles concurrent requests.

    Validates: Requirement 3.1 (ThreadingWSGIServer)
    """

    def test_concurrent_requests_all_succeed(self):
        """Multiple concurrent requests are all served successfully."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        # Complete a cycle so /livez and /startupz return 200
        metrics.record_cycle_completed()
        metrics.record_db_success()

        endpoints = ["/livez", "/readyz", "/startupz", "/metrics"]
        num_requests = 20

        def _make_request(endpoint: str) -> int:
            """Make a request and return the status code."""
            url = f"{base_url}{endpoint}"
            resp = urllib.request.urlopen(url, timeout=5)
            return resp.status

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for i in range(num_requests):
                endpoint = endpoints[i % len(endpoints)]
                futures.append(executor.submit(_make_request, endpoint))

            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All requests should succeed with 200
        assert all(status == 200 for status in results), (
            f"Expected all 200 responses, got: {results}"
        )

    def test_concurrent_requests_during_metric_updates(self):
        """Concurrent requests succeed even while metrics are being updated."""
        port = _start_server_on_free_port()
        base_url = f"http://127.0.0.1:{port}"

        metrics.record_cycle_completed()
        metrics.record_db_success()

        errors = []

        def _update_metrics():
            """Simulate metric updates happening concurrently."""
            for _ in range(50):
                metrics.inc_jobs_pushed("NETSCAN1", 1)
                metrics.inc_jobs_pulled("PORTSCAN", 2, success=True)
                metrics.observe_cycle_duration(0.5)

        def _make_requests():
            """Make requests to the server concurrently."""
            for _ in range(10):
                try:
                    resp = urllib.request.urlopen(
                        f"{base_url}/metrics", timeout=5
                    )
                    if resp.status != 200:
                        errors.append(f"Got status {resp.status}")
                except Exception as e:
                    errors.append(str(e))

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(_update_metrics),
                executor.submit(_update_metrics),
                executor.submit(_make_requests),
                executor.submit(_make_requests),
            ]
            concurrent.futures.wait(futures)
            # Re-raise any exceptions from threads
            for f in futures:
                f.result()

        assert not errors, f"Errors during concurrent access: {errors}"
