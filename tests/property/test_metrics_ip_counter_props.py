"""Property-based tests for IP counter increment by job IP count.

Verifies Property 2: For any positive integer N and valid stage, the
`ips_pushed_total` counter increments by exactly N when a job with N IPs
is pushed, and `ips_pulled_total` increments by exactly N with the correct
status label when a job with N IPs is pulled.

**Validates: Requirements 2.11, 2.12**
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander import metrics


@pytest.fixture(autouse=True)
def reset_prometheus_registry():
    """Reset the prometheus registry between tests to avoid state leakage."""
    yield
    metrics.ips_pushed_total._metrics.clear()
    metrics.ips_pulled_total._metrics.clear()


@settings(max_examples=100)
@given(
    stage=st.sampled_from(["NETSCAN1", "NETSCAN2", "PORTSCAN", "VULNSCAN"]),
    ip_count=st.integers(min_value=1, max_value=1000),
)
def test_ips_pushed_total_increments_by_ip_count(stage: str, ip_count: int) -> None:
    """Feature: observability-and-probes, Property 2: IP counter metrics increment by job IP count."""
    metrics.ips_pushed_total._metrics.clear()

    metrics.inc_jobs_pushed(stage, ip_count)

    assert metrics.ips_pushed_total.labels(stage=stage)._value.get() == ip_count


@settings(max_examples=100)
@given(
    stage=st.sampled_from(["NETSCAN1", "NETSCAN2", "PORTSCAN", "VULNSCAN"]),
    ip_count=st.integers(min_value=1, max_value=1000),
)
def test_ips_pulled_total_increments_by_ip_count_on_success(stage: str, ip_count: int) -> None:
    """Feature: observability-and-probes, Property 2: IP counter metrics increment by job IP count."""
    metrics.ips_pulled_total._metrics.clear()

    metrics.inc_jobs_pulled(stage, ip_count, success=True)

    assert (
        metrics.ips_pulled_total.labels(stage=stage, status="success")._value.get() == ip_count
    )


@settings(max_examples=100)
@given(
    stage=st.sampled_from(["NETSCAN1", "NETSCAN2", "PORTSCAN", "VULNSCAN"]),
    ip_count=st.integers(min_value=1, max_value=1000),
)
def test_ips_pulled_total_increments_by_ip_count_on_failure(stage: str, ip_count: int) -> None:
    """Feature: observability-and-probes, Property 2: IP counter metrics increment by job IP count."""
    metrics.ips_pulled_total._metrics.clear()

    metrics.inc_jobs_pulled(stage, ip_count, success=False)

    assert (
        metrics.ips_pulled_total.labels(stage=stage, status="failure")._value.get() == ip_count
    )
