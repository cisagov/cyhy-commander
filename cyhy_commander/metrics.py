"""Prometheus metrics and health probe server for cyhy-commander.

This module defines all Prometheus metric singletons, module-level state
for health probe evaluation, and configuration functions that read from
environment variables.
"""

import logging
import os

from cyhy_logging import CYHY_ROOT_LOGGER
from prometheus_client import Counter, Gauge, Histogram

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
    except ValueError:
        logger.warning(
            "Invalid CYHY_LIVENESS_THRESHOLD_SECONDS value %r "
            "(not numeric); using default %s",
            raw,
            DEFAULT_LIVENESS_THRESHOLD,
        )
        return DEFAULT_LIVENESS_THRESHOLD
    if value <= 0:
        logger.warning(
            "CYHY_LIVENESS_THRESHOLD_SECONDS value %s is not "
            "positive; using default %s",
            value,
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
