"""Property-based tests for unknown paths returning 404.

Verifies Property 6: For any HTTP request path that is not exactly /metrics,
/livez, /readyz, or /startupz, the WSGI application SHALL return HTTP 404
with an empty response body.

**Validates: Requirements 3.13, 6.3, 6.4**
"""

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from cyhy_commander import metrics

# The set of known/valid paths that the WSGI app handles
KNOWN_PATHS = frozenset({"/metrics", "/livez", "/readyz", "/startupz"})


@pytest.fixture(autouse=True)
def reset_metrics_state():
    """Reset module-level state between tests."""
    metrics._first_cycle_completed = False
    metrics._liveness_threshold = metrics.DEFAULT_LIVENESS_THRESHOLD
    metrics._readiness_threshold = metrics.DEFAULT_READINESS_THRESHOLD
    metrics._bearer_token = None
    metrics.last_cycle_completed_timestamp_seconds.set(0)
    metrics.last_db_success_timestamp_seconds.set(0)
    yield
    metrics._first_cycle_completed = False
    metrics._liveness_threshold = metrics.DEFAULT_LIVENESS_THRESHOLD
    metrics._readiness_threshold = metrics.DEFAULT_READINESS_THRESHOLD
    metrics._bearer_token = None
    metrics.last_cycle_completed_timestamp_seconds.set(0)
    metrics.last_db_success_timestamp_seconds.set(0)


def _make_environ(path: str) -> dict:
    """Create a minimal WSGI environ dict with the given PATH_INFO."""
    return {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": path,
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "9090",
        "HTTP_HOST": "localhost:9090",
    }


class _StartResponseCapture:
    """Capture the status and headers passed to start_response."""

    def __init__(self):
        self.status = None
        self.headers = None

    def __call__(self, status, headers):
        self.status = status
        self.headers = headers


@settings(max_examples=100)
@given(path=st.text(min_size=0, max_size=200))
def test_unknown_paths_return_404(path: str) -> None:
    """Feature: observability-and-probes, Property 6: Unknown paths return 404.

    For any HTTP request path not in {/metrics, /livez, /readyz, /startupz},
    the WSGI application SHALL return HTTP 404 with an empty response body.
    """
    # Filter out the known paths — we only test unknown paths
    assume(path not in KNOWN_PATHS)

    environ = _make_environ(path)
    start_response = _StartResponseCapture()

    response_body = metrics.health_app(environ, start_response)

    assert start_response.status == "404 Not Found"
    assert response_body == [b""]
