"""Property-based tests for scanner connection gauge.

Verifies Property 3: For any host string and workgroup string, calling
set_scanner_status(host, workgroup, True) SHALL set the gauge to 1, and
calling set_scanner_status(host, workgroup, False) SHALL set the gauge to 0.
The gauge value SHALL always reflect only the most recent call for that
(host, workgroup) pair.

**Validates: Requirements 2.13**
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander import metrics


@pytest.fixture(autouse=True)
def reset_prometheus_registry():
    """Reset the prometheus registry between tests to avoid state leakage."""
    yield
    metrics.scanner_connection_status._metrics.clear()


# Strategy for generating non-empty host/workgroup strings
host_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P")),
    min_size=1,
    max_size=50,
)
workgroup_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P")),
    min_size=1,
    max_size=50,
)


@settings(max_examples=100)
@given(
    host=host_strategy,
    workgroup=workgroup_strategy,
)
def test_set_scanner_status_true_sets_gauge_to_1(host: str, workgroup: str) -> None:
    """Feature: observability-and-probes, Property 3: Scanner connection gauge reflects last operation outcome.

    For any host and workgroup, set_scanner_status(host, workgroup, True)
    sets the gauge to 1.
    """
    metrics.scanner_connection_status._metrics.clear()

    metrics.set_scanner_status(host, workgroup, True)

    assert metrics.scanner_connection_status.labels(host=host, workgroup=workgroup)._value.get() == 1


@settings(max_examples=100)
@given(
    host=host_strategy,
    workgroup=workgroup_strategy,
)
def test_set_scanner_status_false_sets_gauge_to_0(host: str, workgroup: str) -> None:
    """Feature: observability-and-probes, Property 3: Scanner connection gauge reflects last operation outcome.

    For any host and workgroup, set_scanner_status(host, workgroup, False)
    sets the gauge to 0.
    """
    metrics.scanner_connection_status._metrics.clear()

    metrics.set_scanner_status(host, workgroup, False)

    assert metrics.scanner_connection_status.labels(host=host, workgroup=workgroup)._value.get() == 0


@settings(max_examples=100)
@given(
    host=host_strategy,
    workgroup=workgroup_strategy,
    statuses=st.lists(st.booleans(), min_size=2, max_size=20),
)
def test_gauge_reflects_most_recent_call(
    host: str, workgroup: str, statuses: list[bool]
) -> None:
    """Feature: observability-and-probes, Property 3: Scanner connection gauge reflects last operation outcome.

    For any sequence of set_scanner_status calls on the same (host, workgroup)
    pair, the gauge value reflects only the most recent call.
    """
    metrics.scanner_connection_status._metrics.clear()

    for status in statuses:
        metrics.set_scanner_status(host, workgroup, status)

    expected = 1 if statuses[-1] else 0
    assert metrics.scanner_connection_status.labels(host=host, workgroup=workgroup)._value.get() == expected
