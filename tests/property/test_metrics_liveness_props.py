"""Property-based tests for liveness endpoint status based on staleness.

Verifies Property 4: For any last_cycle_timestamp > 0 and any current_time
and any positive threshold, the /livez endpoint SHALL return HTTP 200 if
(current_time - last_cycle_timestamp) < threshold, and HTTP 503 if
(current_time - last_cycle_timestamp) >= threshold. When last_cycle_timestamp
is 0 (first cycle not yet completed), /livez SHALL always return HTTP 200.

**Validates: Requirements 3.10, 4.2, 4.3, 4.6**
"""

from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander import metrics


@pytest.fixture(autouse=True)
def reset_metrics_state():
    """Reset module-level state between tests."""
    metrics._first_cycle_completed = False
    metrics._liveness_threshold = metrics.DEFAULT_LIVENESS_THRESHOLD
    metrics.last_cycle_completed_timestamp_seconds.set(0)
    yield
    metrics._first_cycle_completed = False
    metrics._liveness_threshold = metrics.DEFAULT_LIVENESS_THRESHOLD
    metrics.last_cycle_completed_timestamp_seconds.set(0)


@settings(max_examples=100)
@given(
    current_time=st.floats(min_value=1.0, max_value=1e9),
    threshold=st.floats(min_value=0.001, max_value=1e6),
)
def test_liveness_returns_200_when_first_cycle_not_completed(
    current_time: float, threshold: float
) -> None:
    """Feature: observability-and-probes, Property 4: Liveness endpoint returns correct status based on staleness.

    When first cycle not completed (last_cycle_timestamp is 0), /livez SHALL
    always return HTTP 200 regardless of current time or threshold.
    """
    # Ensure first cycle is NOT completed
    metrics._first_cycle_completed = False
    metrics._liveness_threshold = threshold
    metrics.last_cycle_completed_timestamp_seconds.set(0)

    with patch("cyhy_commander.metrics.time.time", return_value=current_time):
        status_code, body = metrics._check_liveness()

    assert status_code == 200
    assert body == "ok"


@settings(max_examples=100)
@given(
    last_cycle_timestamp=st.integers(min_value=1, max_value=10**9),
    threshold=st.integers(min_value=1, max_value=10**6),
    elapsed=st.integers(min_value=0, max_value=10**6 - 1),
)
def test_liveness_returns_200_when_cycle_not_stale(
    last_cycle_timestamp: int, threshold: int, elapsed: int
) -> None:
    """Feature: observability-and-probes, Property 4: Liveness endpoint returns correct status based on staleness.

    When first cycle completed and (current_time - last_cycle_timestamp) < threshold,
    /livez SHALL return HTTP 200.
    """
    # Constrain elapsed to be strictly less than threshold
    elapsed = elapsed % threshold  # ensures 0 <= elapsed < threshold

    # Set up state: first cycle completed
    metrics._first_cycle_completed = True
    metrics._liveness_threshold = float(threshold)
    metrics.last_cycle_completed_timestamp_seconds.set(float(last_cycle_timestamp))

    # current_time such that elapsed < threshold
    current_time = float(last_cycle_timestamp + elapsed)

    with patch("cyhy_commander.metrics.time.time", return_value=current_time):
        status_code, body = metrics._check_liveness()

    assert status_code == 200
    assert body == "ok"


@settings(max_examples=100)
@given(
    last_cycle_timestamp=st.integers(min_value=1, max_value=10**9),
    threshold=st.integers(min_value=1, max_value=10**6),
    overshoot=st.integers(min_value=0, max_value=10**6),
)
def test_liveness_returns_503_when_cycle_stale(
    last_cycle_timestamp: int, threshold: int, overshoot: int
) -> None:
    """Feature: observability-and-probes, Property 4: Liveness endpoint returns correct status based on staleness.

    When first cycle completed and (current_time - last_cycle_timestamp) >= threshold,
    /livez SHALL return HTTP 503.
    """
    # Set up state: first cycle completed
    metrics._first_cycle_completed = True
    metrics._liveness_threshold = float(threshold)
    metrics.last_cycle_completed_timestamp_seconds.set(float(last_cycle_timestamp))

    # current_time is at or beyond the threshold (elapsed >= threshold)
    current_time = float(last_cycle_timestamp + threshold + overshoot)

    with patch("cyhy_commander.metrics.time.time", return_value=current_time):
        status_code, body = metrics._check_liveness()

    assert status_code == 503
    assert body == "work cycle stale"
