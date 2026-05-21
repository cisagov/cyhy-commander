"""Property-based tests for bearer token authentication.

Verifies Property 9: For any non-empty configured bearer token T and any HTTP
request to /metrics: if the request includes an Authorization: Bearer X header
where X equals T (compared in constant time), the request SHALL be served with
metrics data; if the header is missing, malformed, or X does not equal T, the
response SHALL be HTTP 401 with an empty body. When no token is configured, all
requests to /metrics SHALL be served without authentication.

**Validates: Requirements 7.1, 7.2, 7.3, 7.4**
"""

from unittest.mock import patch

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from cyhy_commander import metrics


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


def _make_environ(path: str = "/metrics", auth_header: str | None = None) -> dict:
    """Create a minimal WSGI environ dict for the given path and optional auth."""
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": path,
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "9090",
        "HTTP_HOST": "localhost:9090",
    }
    if auth_header is not None:
        environ["HTTP_AUTHORIZATION"] = auth_header
    return environ


class _StartResponseCapture:
    """Capture the status and headers passed to start_response."""

    def __init__(self):
        self.status = None
        self.headers = None

    def __call__(self, status, headers):
        self.status = status
        self.headers = headers


# Strategy for non-empty bearer tokens
_token_strategy = st.text(min_size=1, max_size=200, alphabet=st.characters(codec="ascii", categories=("L", "N", "P", "S")))


@settings(max_examples=100)
@given(token=_token_strategy)
def test_valid_bearer_token_serves_metrics(token: str) -> None:
    """Feature: observability-and-probes, Property 9: Bearer token authentication.

    For any non-empty token T, a request with Authorization: Bearer T SHALL be
    served with metrics data (not 401).
    """
    metrics._bearer_token = token

    environ = _make_environ(auth_header=f"Bearer {token}")
    start_response = _StartResponseCapture()

    metrics.health_app(environ, start_response)

    # Should NOT be 401 — the request is authenticated
    assert start_response.status != "401 Unauthorized", (
        f"Valid token {token!r} was rejected"
    )
    # Should be 200 OK (prometheus metrics response)
    assert start_response.status.startswith("200")


@settings(max_examples=100)
@given(token=_token_strategy)
def test_missing_auth_header_returns_401(token: str) -> None:
    """Feature: observability-and-probes, Property 9: Bearer token authentication.

    For any non-empty configured token T, a request missing the Authorization
    header SHALL receive HTTP 401 with an empty body.
    """
    metrics._bearer_token = token

    environ = _make_environ(auth_header=None)
    start_response = _StartResponseCapture()

    response_body = metrics.health_app(environ, start_response)

    assert start_response.status == "401 Unauthorized"
    assert response_body == [b""]


@settings(max_examples=100)
@given(
    token=_token_strategy,
    wrong_token=_token_strategy,
)
def test_wrong_token_returns_401(token: str, wrong_token: str) -> None:
    """Feature: observability-and-probes, Property 9: Bearer token authentication.

    For any non-empty configured token T and any token X != T, a request with
    Authorization: Bearer X SHALL receive HTTP 401 with an empty body.
    """
    assume(token != wrong_token)
    metrics._bearer_token = token

    environ = _make_environ(auth_header=f"Bearer {wrong_token}")
    start_response = _StartResponseCapture()

    response_body = metrics.health_app(environ, start_response)

    assert start_response.status == "401 Unauthorized"
    assert response_body == [b""]


@settings(max_examples=100)
@given(
    token=_token_strategy,
    malformed_header=st.one_of(
        # No "Bearer " prefix
        st.text(min_size=1, max_size=100).filter(lambda s: not s.startswith("Bearer ")),
        # Just "Bearer" without space and token
        st.just("Bearer"),
        # Other auth schemes
        st.text(min_size=1, max_size=50).map(lambda s: f"Basic {s}"),
        st.text(min_size=1, max_size=50).map(lambda s: f"Token {s}"),
    ),
)
def test_malformed_auth_header_returns_401(token: str, malformed_header: str) -> None:
    """Feature: observability-and-probes, Property 9: Bearer token authentication.

    For any non-empty configured token T, a request with a malformed
    Authorization header (not matching 'Bearer <token>' format) SHALL receive
    HTTP 401 with an empty body.
    """
    metrics._bearer_token = token

    environ = _make_environ(auth_header=malformed_header)
    start_response = _StartResponseCapture()

    response_body = metrics.health_app(environ, start_response)

    assert start_response.status == "401 Unauthorized"
    assert response_body == [b""]


@settings(max_examples=100)
@given(auth_header=st.one_of(
    st.none(),
    st.text(min_size=0, max_size=200).map(lambda s: f"Bearer {s}"),
    st.text(min_size=0, max_size=200),
))
def test_no_token_configured_serves_without_auth(auth_header: str | None) -> None:
    """Feature: observability-and-probes, Property 9: Bearer token authentication.

    When no token is configured (None), all requests to /metrics SHALL be served
    without authentication regardless of what Authorization header is present.
    """
    metrics._bearer_token = None

    environ = _make_environ(auth_header=auth_header)
    start_response = _StartResponseCapture()

    metrics.health_app(environ, start_response)

    # Should NOT be 401 — no auth required
    assert start_response.status != "401 Unauthorized", (
        f"Request rejected despite no token configured (header={auth_header!r})"
    )
    # Should be 200 OK (prometheus metrics response)
    assert start_response.status.startswith("200")


@settings(max_examples=100)
@given(token=_token_strategy)
def test_constant_time_comparison_used(token: str) -> None:
    """Feature: observability-and-probes, Property 9: Bearer token authentication.

    Verify that hmac.compare_digest is used for token comparison (constant-time).
    """
    metrics._bearer_token = token

    environ = _make_environ(auth_header=f"Bearer {token}")

    with patch("cyhy_commander.metrics.hmac.compare_digest", return_value=True) as mock_compare:
        start_response = _StartResponseCapture()
        metrics.health_app(environ, start_response)

        # hmac.compare_digest should have been called with the provided and configured tokens
        mock_compare.assert_called_once_with(token, token)
