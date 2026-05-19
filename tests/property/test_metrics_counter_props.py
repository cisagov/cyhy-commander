"""Property-based tests for counter increment correctness.

Verifies Property 1: For any valid stage label (NETSCAN1, NETSCAN2,
PORTSCAN, VULNSCAN) and any sequence of N push/pull/fail events, the
corresponding counter metric (jobs_pushed_total, jobs_pulled_total,
jobs_failed_total) SHALL have a value equal to N for that stage label
after all events are recorded.

**Validates: Requirements 2.3, 2.4, 2.5**
"""

import prometheus_client
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander import metrics


@pytest.fixture(autouse=True)
def reset_prometheus_registry():
    """Reset the prometheus registry between tests to avoid state leakage.

    Unregisters all collectors from the default registry and re-imports
    the metrics module to get fresh metric objects.
    """
    yield
    # After each test, clear all samples from the labeled counters
    # by removing all child metrics (label combinations).
    metrics.jobs_pushed_total._metrics.clear()
    metrics.jobs_pulled_total._metrics.clear()
    metrics.jobs_failed_total._metrics.clear()


@settings(max_examples=100)
@given(
    stage=st.sampled_from(["NETSCAN1", "NETSCAN2", "PORTSCAN", "VULNSCAN"]),
    count=st.integers(min_value=1, max_value=1000),
)
def test_jobs_pushed_counter_increments_correctly(stage: str, count: int) -> None:
    """Feature: observability-and-probes, Property 1: Counter metrics increment correctly.

    For any valid stage and N calls to inc_jobs_pushed, the
    jobs_pushed_total counter for that stage equals N.
    """
    # Clear any prior state for this label
    metrics.jobs_pushed_total._metrics.clear()

    for _ in range(count):
        metrics.inc_jobs_pushed(stage)

    assert metrics.jobs_pushed_total.labels(stage=stage)._value.get() == count


@settings(max_examples=100)
@given(
    stage=st.sampled_from(["NETSCAN1", "NETSCAN2", "PORTSCAN", "VULNSCAN"]),
    count=st.integers(min_value=1, max_value=1000),
)
def test_jobs_pulled_counter_increments_correctly(stage: str, count: int) -> None:
    """Feature: observability-and-probes, Property 1: Counter metrics increment correctly.

    For any valid stage and N calls to inc_jobs_pulled, the
    jobs_pulled_total counter for that stage equals N.
    """
    # Clear any prior state for this label
    metrics.jobs_pulled_total._metrics.clear()

    for _ in range(count):
        metrics.inc_jobs_pulled(stage)

    assert metrics.jobs_pulled_total.labels(stage=stage)._value.get() == count


@settings(max_examples=100)
@given(
    stage=st.sampled_from(["NETSCAN1", "NETSCAN2", "PORTSCAN", "VULNSCAN"]),
    count=st.integers(min_value=1, max_value=1000),
)
def test_jobs_failed_counter_increments_correctly(stage: str, count: int) -> None:
    """Feature: observability-and-probes, Property 1: Counter metrics increment correctly.

    For any valid stage and N calls to inc_jobs_failed, the
    jobs_failed_total counter for that stage equals N.
    """
    # Clear any prior state for this label
    metrics.jobs_failed_total._metrics.clear()

    for _ in range(count):
        metrics.inc_jobs_failed(stage)

    assert metrics.jobs_failed_total.labels(stage=stage)._value.get() == count
