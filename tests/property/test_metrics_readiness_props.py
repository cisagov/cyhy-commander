"""Property-based tests for readiness endpoint status based on DB staleness.

Verifies Property 5: For any last_db_timestamp and any current_time and any
positive threshold, the /readyz endpoint SHALL return HTTP 200 if
last_db_timestamp > 0 AND (current_time - last_db_timestamp) < threshold,
and HTTP 503 otherwise (including when last_db_timestamp is 0).

**Validates: Requirements 3.11, 5.2, 5.3, 5.6**
"""

from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander import metrics


@pytest.fixture(autouse=True)
def reset_metrics_state():
    """Reset module-level state between tests."""
    metrics._readiness_threshold = metrics.DEFAULT_READINESS_THRESHOLD
    metrics.last_db_success_timestamp_seconds.set(0)
    yield
    metrics._readiness_threshold = metrics.DEFAULT_READINESS_THRESHOLD
    metrics.last_db_success_timestamp_seconds.set(0)


@settings(max_examples=100)
@given(
    current_time=st.floats(min_value=1.0, max_value=1e9),
    threshold=st.floats(min_value=0.001, max_value=1e6),
)
def test_readiness_returns_503_when_last_db_timestamp_is_zero(
    current_time: float, threshold: float
) -> None:
    """Feature: observability-and-probes, Property 5: Readiness endpoint returns correct status based on DB staleness.

    When last_db_timestamp is 0 (no successful DB operation yet), /readyz SHALL
    always return HTTP 503 regardless of current time or threshold.
    """
    metrics._readiness_threshold = threshold
    metrics.last_db_success_timestamp_seconds.set(0)

    with patch("cyhy_commander.metrics.time.time", return_value=current_time):
        status_code, body = metrics._check_readiness()

    assert status_code == 503
    assert body == "database connection stale"


@settings(max_examples=100)
@given(
    last_db_timestamp=st.integers(min_value=1, max_value=10**9),
    threshold=st.integers(min_value=1, max_value=10**6),
    elapsed=st.integers(min_value=0, max_value=10**6 - 1),
)
def test_readiness_returns_200_when_db_not_stale(
    last_db_timestamp: int, threshold: int, elapsed: int
) -> None:
    """Feature: observability-and-probes, Property 5: Readiness endpoint returns correct status based on DB staleness.

    When last_db_timestamp > 0 and (current_time - last_db_timestamp) < threshold,
    /readyz SHALL return HTTP 200.
    """
    # Constrain elapsed to be strictly less than threshold
    elapsed = elapsed % threshold  # ensures 0 <= elapsed < threshold

    metrics._readiness_threshold = float(threshold)
    metrics.last_db_success_timestamp_seconds.set(float(last_db_timestamp))

    # current_time such that elapsed < threshold
    current_time = float(last_db_timestamp + elapsed)

    with patch("cyhy_commander.metrics.time.time", return_value=current_time):
        status_code, body = metrics._check_readiness()

    assert status_code == 200
    assert body == "ok"


@settings(max_examples=100)
@given(
    last_db_timestamp=st.integers(min_value=1, max_value=10**9),
    threshold=st.integers(min_value=1, max_value=10**6),
    overshoot=st.integers(min_value=0, max_value=10**6),
)
def test_readiness_returns_503_when_db_stale(
    last_db_timestamp: int, threshold: int, overshoot: int
) -> None:
    """Feature: observability-and-probes, Property 5: Readiness endpoint returns correct status based on DB staleness.

    When last_db_timestamp > 0 and (current_time - last_db_timestamp) >= threshold,
    /readyz SHALL return HTTP 503.
    """
    metrics._readiness_threshold = float(threshold)
    metrics.last_db_success_timestamp_seconds.set(float(last_db_timestamp))

    # current_time is at or beyond the threshold (elapsed >= threshold)
    current_time = float(last_db_timestamp + threshold + overshoot)

    with patch("cyhy_commander.metrics.time.time", return_value=current_time):
        status_code, body = metrics._check_readiness()

    assert status_code == 503
    assert body == "database connection stale"
