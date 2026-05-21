"""Tests for the Docker HEALTHCHECK probe script (scripts/healthcheck.py).

Tests cover the liveness and readiness subcommands, connection failure
handling, timeout behavior, and invalid subcommand error reporting.

Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6
"""

import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

# Path to the healthcheck script
SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "healthcheck.py"


def _find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _HealthHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler that returns 200 for /livez and /readyz."""

    def do_GET(self):
        if self.path in ("/livez", "/readyz"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress request logging during tests."""
        pass


class _UnhealthyHandler(BaseHTTPRequestHandler):
    """HTTP handler that returns 503 for all health endpoints."""

    def do_GET(self):
        self.send_response(503)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"unhealthy")

    def log_message(self, format, *args):
        """Suppress request logging during tests."""
        pass


@pytest.fixture()
def healthy_server():
    """Start a local HTTP server that returns 200 for health endpoints."""
    port = _find_free_port()
    server = HTTPServer(("127.0.0.1", port), _HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()


@pytest.fixture()
def unhealthy_server():
    """Start a local HTTP server that returns 503 for health endpoints."""
    port = _find_free_port()
    server = HTTPServer(("127.0.0.1", port), _UnhealthyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()


def _run_healthcheck(subcommand: str | None, port: int, timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run the healthcheck script with the given subcommand and port."""
    cmd = [sys.executable, str(SCRIPT_PATH)]
    if subcommand is not None:
        cmd.append(subcommand)
    env = {"CYHY_METRICS_PORT": str(port), "PATH": ""}
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


class TestLivenessSubcommand:
    """Test the liveness subcommand behavior.

    Validates: Requirements 9.1, 9.2
    """

    def test_liveness_returns_0_on_healthy_server(self, healthy_server):
        """liveness subcommand exits 0 when server returns HTTP 200."""
        result = _run_healthcheck("liveness", healthy_server)
        assert result.returncode == 0

    def test_liveness_returns_1_on_unhealthy_server(self, unhealthy_server):
        """liveness subcommand exits 1 when server returns non-200."""
        result = _run_healthcheck("liveness", unhealthy_server)
        assert result.returncode == 1


class TestReadinessSubcommand:
    """Test the readiness subcommand behavior.

    Validates: Requirements 9.1, 9.3
    """

    def test_readiness_returns_0_on_ready_server(self, healthy_server):
        """readiness subcommand exits 0 when server returns HTTP 200."""
        result = _run_healthcheck("readiness", healthy_server)
        assert result.returncode == 0

    def test_readiness_returns_1_on_not_ready_server(self, unhealthy_server):
        """readiness subcommand exits 1 when server returns non-200."""
        result = _run_healthcheck("readiness", unhealthy_server)
        assert result.returncode == 1


class TestConnectionFailure:
    """Test behavior when the metrics server is unreachable.

    Validates: Requirements 9.4
    """

    def test_connection_refused_returns_exit_code_1(self):
        """Script exits 1 when connection is refused (no server listening)."""
        # Use a port that nothing is listening on
        port = _find_free_port()
        result = _run_healthcheck("liveness", port)
        assert result.returncode == 1

    def test_readiness_connection_refused_returns_exit_code_1(self):
        """readiness also exits 1 when connection is refused."""
        port = _find_free_port()
        result = _run_healthcheck("readiness", port)
        assert result.returncode == 1


class TestTimeoutHandling:
    """Test that the script completes within 3 seconds.

    Validates: Requirements 9.4, 9.6
    """

    def test_timeout_completes_within_3_seconds(self):
        """Script completes within 3 seconds even on connection failure."""
        port = _find_free_port()
        start = time.monotonic()
        result = _run_healthcheck("liveness", port, timeout=5.0)
        elapsed = time.monotonic() - start

        assert result.returncode == 1
        assert elapsed < 3.0, f"Script took {elapsed:.2f}s, expected < 3s"

    def test_readiness_timeout_completes_within_3_seconds(self):
        """readiness subcommand also completes within 3 seconds on failure."""
        port = _find_free_port()
        start = time.monotonic()
        result = _run_healthcheck("readiness", port, timeout=5.0)
        elapsed = time.monotonic() - start

        assert result.returncode == 1
        assert elapsed < 3.0, f"Script took {elapsed:.2f}s, expected < 3s"


class TestInvalidSubcommand:
    """Test behavior with invalid or missing subcommands.

    Validates: Requirements 9.5
    """

    def test_no_subcommand_returns_exit_code_2(self):
        """No subcommand exits 2 with usage on stderr."""
        port = _find_free_port()
        result = _run_healthcheck(None, port)
        assert result.returncode == 2
        assert "Usage:" in result.stderr or "usage:" in result.stderr.lower()

    def test_invalid_subcommand_returns_exit_code_2(self):
        """Unrecognized subcommand exits 2 with usage on stderr."""
        port = _find_free_port()
        result = _run_healthcheck("bogus", port)
        assert result.returncode == 2
        assert "Usage:" in result.stderr or "usage:" in result.stderr.lower()

    def test_invalid_subcommand_usage_mentions_liveness_and_readiness(self):
        """Usage message mentions both valid subcommands."""
        port = _find_free_port()
        result = _run_healthcheck("invalid", port)
        assert result.returncode == 2
        assert "liveness" in result.stderr
        assert "readiness" in result.stderr


class TestInvalidSubcommandProperty:
    """Property-based test for invalid healthcheck subcommand behavior.

    Feature: observability-and-probes, Property 11: Invalid healthcheck subcommand produces usage error

    Validates: Requirements 9.5
    """

    @settings(max_examples=100)
    @given(
        subcommand=st.text(
            alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
        ).filter(lambda s: s not in ("liveness", "readiness")),
    )
    def test_invalid_subcommand_produces_usage_error(self, subcommand: str) -> None:
        """Feature: observability-and-probes, Property 11: Invalid healthcheck subcommand produces usage error.

        For any string argument not in {liveness, readiness}, the script exits
        with code 2 and prints a usage message to stderr.

        Validates: Requirements 9.5
        """
        port = _find_free_port()
        result = _run_healthcheck(subcommand, port)
        assert result.returncode == 2, (
            f"Expected exit code 2 for invalid subcommand {subcommand!r}, got {result.returncode}"
        )
        assert "usage" in result.stderr.lower(), (
            f"Expected usage message in stderr for subcommand {subcommand!r}, got: {result.stderr!r}"
        )

    def test_no_argument_produces_usage_error(self) -> None:
        """Feature: observability-and-probes, Property 11: Invalid healthcheck subcommand produces usage error.

        No argument (empty argv) also exits with code 2 and usage message.

        Validates: Requirements 9.5
        """
        port = _find_free_port()
        result = _run_healthcheck(None, port)
        assert result.returncode == 2, (
            f"Expected exit code 2 for no subcommand, got {result.returncode}"
        )
        assert "usage" in result.stderr.lower(), (
            f"Expected usage message in stderr for no subcommand, got: {result.stderr!r}"
        )
