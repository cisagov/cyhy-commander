"""Prometheus metrics and health probe server for cyhy-commander.

This module defines all Prometheus metric singletons, module-level state
for health probe evaluation, configuration functions that read from
environment variables, and the WSGI health/metrics application.
"""

import hmac
import logging
import math
import os
import socketserver
import threading
import time
from typing import Any
from wsgiref.simple_server import WSGIServer, make_server

from cyhy_logging import CYHY_ROOT_LOGGER
from prometheus_client import Counter, Gauge, Histogram, make_wsgi_app

logger = logging.getLogger(f"{CYHY_ROOT_LOGGER}.{__name__}")

# ---------------------------------------------------------------------------
# Default configuration constants
# ---------------------------------------------------------------------------

DEFAULT_METRICS_PORT: int = 9090
DEFAULT_LIVENESS_THRESHOLD: float = 300.0  # seconds
DEFAULT_READINESS_THRESHOLD: float = 120.0  # seconds

# ---------------------------------------------------------------------------
# Prometheus metric singletons (default global registry)
# ---------------------------------------------------------------------------

work_cycle_duration_seconds: Histogram = Histogram(
    "cyhy_commander_work_cycle_duration_seconds",
    "Wall-clock duration of each work cycle iteration",
)

jobs_pushed_total: Counter = Counter(
    "cyhy_commander_jobs_pushed_total",
    "Jobs successfully pushed to scanner hosts",
    ["stage"],
)

jobs_pulled_total: Counter = Counter(
    "cyhy_commander_jobs_pulled_total",
    "Completed jobs pulled from scanner hosts",
    ["stage"],
)

jobs_failed_total: Counter = Counter(
    "cyhy_commander_jobs_failed_total",
    "Jobs that completed with non-zero exit code",
    ["stage"],
)

host_errors_total: Counter = Counter(
    "cyhy_commander_host_errors_total",
    "SSH/rsync exceptions per scanner host",
    ["host"],
)

ips_pushed_total: Counter = Counter(
    "cyhy_commander_ips_pushed_total",
    "IP addresses pushed in job bundles",
    ["stage"],
)

ips_pulled_total: Counter = Counter(
    "cyhy_commander_ips_pulled_total",
    "IP addresses in pulled jobs by stage and status",
    ["stage", "status"],
)

last_cycle_completed_timestamp_seconds: Gauge = Gauge(
    "cyhy_commander_last_cycle_completed_timestamp_seconds",
    "Unix timestamp of last successful cycle completion",
)

last_db_success_timestamp_seconds: Gauge = Gauge(
    "cyhy_commander_last_db_success_timestamp_seconds",
    "Unix timestamp of last successful DB operation",
)

scanner_connection_status: Gauge = Gauge(
    "cyhy_commander_scanner_connection_status",
    "1 if last SSH/rsync to host succeeded, 0 if failed",
    ["host", "workgroup"],
)

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_first_cycle_completed: bool = False
_liveness_threshold: float = DEFAULT_LIVENESS_THRESHOLD
_readiness_threshold: float = DEFAULT_READINESS_THRESHOLD
_bearer_token: str | None = None

_server: WSGIServer | None = None
_server_thread: threading.Thread | None = None

# ---------------------------------------------------------------------------
# Prometheus WSGI app for /metrics endpoint
# ---------------------------------------------------------------------------

_metrics_app = make_wsgi_app()


# ---------------------------------------------------------------------------
# Configuration functions
# ---------------------------------------------------------------------------


def get_metrics_port() -> int:
    """Read CYHY_METRICS_PORT env var; validate range [1024, 65535].

    Returns:
        The configured port number, or DEFAULT_METRICS_PORT (9090) if
        the environment variable is unset, empty, non-numeric, or
        outside the valid range.
    """
    raw = os.environ.get("CYHY_METRICS_PORT", "")
    if not raw:
        return DEFAULT_METRICS_PORT
    try:
        port = int(raw)
    except ValueError:
        logger.warning(
            "Invalid CYHY_METRICS_PORT value %r (not an integer); "
            "using default %d",
            raw,
            DEFAULT_METRICS_PORT,
        )
        return DEFAULT_METRICS_PORT
    if port < 1024 or port > 65535:
        logger.warning(
            "CYHY_METRICS_PORT value %d out of range [1024, 65535]; "
            "using default %d",
            port,
            DEFAULT_METRICS_PORT,
        )
        return DEFAULT_METRICS_PORT
    return port


def get_liveness_threshold() -> float:
    """Read CYHY_LIVENESS_THRESHOLD_SECONDS; validate positive numeric.

    Returns:
        The configured threshold in seconds, or
        DEFAULT_LIVENESS_THRESHOLD (300.0) if the environment variable
        is unset, empty, non-numeric, or non-positive.
    """
    raw = os.environ.get("CYHY_LIVENESS_THRESHOLD_SECONDS", "")
    if not raw:
        return DEFAULT_LIVENESS_THRESHOLD
    try:
        value = float(raw)
    except (ValueError, OverflowError):
        logger.warning(
            "Invalid CYHY_LIVENESS_THRESHOLD_SECONDS value %r "
            "(not numeric); using default %s",
            raw,
            DEFAULT_LIVENESS_THRESHOLD,
        )
        return DEFAULT_LIVENESS_THRESHOLD
    if not (value > 0):  # Catches <= 0, NaN, and -0.0
        logger.warning(
            "CYHY_LIVENESS_THRESHOLD_SECONDS value %s is not "
            "positive; using default %s",
            raw,
            DEFAULT_LIVENESS_THRESHOLD,
        )
        return DEFAULT_LIVENESS_THRESHOLD
    if math.isinf(value):
        logger.warning(
            "CYHY_LIVENESS_THRESHOLD_SECONDS value %r is infinite; "
            "using default %s",
            raw,
            DEFAULT_LIVENESS_THRESHOLD,
        )
        return DEFAULT_LIVENESS_THRESHOLD
    return value


def get_readiness_threshold() -> float:
    """Read CYHY_READINESS_THRESHOLD_SECONDS; validate int [1, 3600].

    Returns:
        The configured threshold in seconds, or
        DEFAULT_READINESS_THRESHOLD (120.0) if the environment variable
        is unset, empty, non-integer, or outside the valid range
        [1, 3600].
    """
    raw = os.environ.get("CYHY_READINESS_THRESHOLD_SECONDS", "")
    if not raw:
        return DEFAULT_READINESS_THRESHOLD
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "Invalid CYHY_READINESS_THRESHOLD_SECONDS value %r "
            "(not an integer); using default %s",
            raw,
            DEFAULT_READINESS_THRESHOLD,
        )
        return DEFAULT_READINESS_THRESHOLD
    if value < 1 or value > 3600:
        logger.warning(
            "CYHY_READINESS_THRESHOLD_SECONDS value %d out of range "
            "[1, 3600]; using default %s",
            value,
            DEFAULT_READINESS_THRESHOLD,
        )
        return DEFAULT_READINESS_THRESHOLD
    return float(value)


def get_bearer_token() -> str | None:
    """Read CYHY_METRICS_BEARER_TOKEN; return None if unset/empty.

    If the token is set but shorter than 8 characters, a warning is
    logged but the token is still returned for use.

    Returns:
        The bearer token string, or None if the environment variable
        is not set or is empty.
    """
    raw = os.environ.get("CYHY_METRICS_BEARER_TOKEN", "")
    if not raw:
        return None
    if len(raw) < 8:
        logger.warning(
            "CYHY_METRICS_BEARER_TOKEN is shorter than 8 characters; "
            "consider using a longer token for security"
        )
    return raw


# ---------------------------------------------------------------------------
# Health check functions
# ---------------------------------------------------------------------------


def _check_liveness() -> tuple[int, str]:
    """Evaluate liveness: return (status_code, body).

    Returns 200 if:
      - First cycle not yet completed (startup grace), OR
      - (now - last_cycle_timestamp) < liveness_threshold
    Returns 503 otherwise.
    """
    global _first_cycle_completed, _liveness_threshold

    if not _first_cycle_completed:
        return (200, "ok")

    last_cycle = last_cycle_completed_timestamp_seconds._value.get()
    elapsed = time.time() - last_cycle
    if elapsed < _liveness_threshold:
        return (200, "ok")
    return (503, "work cycle stale")


def _check_readiness() -> tuple[int, str]:
    """Evaluate readiness: return (status_code, body).

    Returns 200 if:
      - last_db_success_timestamp > 0 AND
      - (now - last_db_success_timestamp) < readiness_threshold
    Returns 503 otherwise (including before first DB op).
    """
    global _readiness_threshold

    last_db = last_db_success_timestamp_seconds._value.get()
    if last_db == 0:
        return (503, "database connection stale")

    elapsed = time.time() - last_db
    if elapsed < _readiness_threshold:
        return (200, "ok")
    return (503, "database connection stale")


def _check_startup() -> tuple[int, str]:
    """Evaluate startup: return (status_code, body).

    Returns 200 if first_cycle_completed flag is True.
    Returns 503 otherwise.
    """
    global _first_cycle_completed

    if _first_cycle_completed:
        return (200, "ok")
    return (503, "first cycle not completed")


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def _authenticate(environ: dict[str, Any]) -> bool:
    """Validate Bearer token using hmac.compare_digest.

    Returns True if no token is configured or if the provided token
    matches the configured token. Returns False otherwise.
    """
    global _bearer_token

    if _bearer_token is None:
        return True

    auth_header = environ.get("HTTP_AUTHORIZATION", "")
    if not auth_header.startswith("Bearer "):
        return False

    provided_token = auth_header[7:]  # Strip "Bearer " prefix
    return hmac.compare_digest(provided_token, _bearer_token)


# ---------------------------------------------------------------------------
# WSGI Application
# ---------------------------------------------------------------------------


def health_app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
    """WSGI application routing requests to health/metrics handlers.

    Routes:
        GET /metrics  -> prometheus_client WSGI app (with optional auth)
        GET /livez    -> liveness check
        GET /readyz   -> readiness check
        GET /startupz -> startup check
        *             -> 404
    """
    path = environ.get("PATH_INFO", "")

    if path == "/metrics":
        if not _authenticate(environ):
            start_response("401 Unauthorized", [("Content-Type", "text/plain")])
            return [b""]
        return list(_metrics_app(environ, start_response))

    if path == "/livez":
        status_code, body = _check_liveness()
        status_str = f"{status_code} {'OK' if status_code == 200 else 'Service Unavailable'}"
        start_response(status_str, [("Content-Type", "text/plain")])
        return [body.encode("utf-8")]

    if path == "/readyz":
        status_code, body = _check_readiness()
        status_str = f"{status_code} {'OK' if status_code == 200 else 'Service Unavailable'}"
        start_response(status_str, [("Content-Type", "text/plain")])
        return [body.encode("utf-8")]

    if path == "/startupz":
        status_code, body = _check_startup()
        status_str = f"{status_code} {'OK' if status_code == 200 else 'Service Unavailable'}"
        start_response(status_str, [("Content-Type", "text/plain")])
        return [body.encode("utf-8")]

    # All other paths return 404 with empty body
    start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b""]


# ---------------------------------------------------------------------------
# Threading WSGI Server
# ---------------------------------------------------------------------------


class _ThreadingWSGIServer(socketserver.ThreadingMixIn, WSGIServer):
    """A WSGI server that handles each request in a new thread."""

    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# Server Lifecycle
# ---------------------------------------------------------------------------


def start_server() -> None:
    """Start the metrics/health WSGI server in a daemon thread.

    Binds to 0.0.0.0:<metrics_port>. If the port is in use, logs an
    error and returns (degraded mode). Sets _server and _server_thread
    module globals.
    """
    global _server, _server_thread, _bearer_token, _liveness_threshold, _readiness_threshold

    # Load configuration from environment
    port = get_metrics_port()
    _liveness_threshold = get_liveness_threshold()
    _readiness_threshold = get_readiness_threshold()
    _bearer_token = get_bearer_token()

    try:
        _server = make_server("0.0.0.0", port, health_app, server_class=_ThreadingWSGIServer)
    except OSError as exc:
        logger.error(
            "Failed to bind metrics server to 0.0.0.0:%d: %s. "
            "Continuing in degraded mode without metrics exposition.",
            port,
            exc,
        )
        _server = None
        _server_thread = None
        return

    def _serve() -> None:
        """Run the WSGI server until shutdown is called."""
        try:
            _server.serve_forever()
        except Exception:
            logger.error(
                "Metrics server encountered an unhandled exception. "
                "Continuing in degraded mode without metrics exposition.",
                exc_info=True,
            )

    _server_thread = threading.Thread(target=_serve, name="metrics-server", daemon=True)
    _server_thread.start()
    logger.info("Metrics server started on 0.0.0.0:%d", port)


def shutdown_server() -> None:
    """Shut down the WSGI server and join the thread (timeout 5s).

    Called during graceful shutdown after the main coroutine returns.
    """
    global _server, _server_thread

    if _server is not None:
        _server.shutdown()

    if _server_thread is not None:
        _server_thread.join(timeout=5.0)
        if _server_thread.is_alive():
            logger.warning("Metrics server thread did not stop within 5 seconds")

    _server = None
    _server_thread = None


def is_server_running() -> bool:
    """Return True if the metrics server thread is alive."""
    return _server_thread is not None and _server_thread.is_alive()
