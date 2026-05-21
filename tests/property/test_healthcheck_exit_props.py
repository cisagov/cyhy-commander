"""Property-based tests for healthcheck script exit codes.

Verifies Property 10: For any HTTP response status code returned by the
metrics server health endpoints, the healthcheck.py script SHALL exit
with code 0 if and only if the status is 200, and exit with code 1 for
any other status or connection failure.

**Validates: Requirements 9.2, 9.3, 9.4**
"""

import importlib.util
import socket
import urllib.error
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

# Import the healthcheck module directly from the scripts directory
_SCRIPT_PATH = Path(__file__).parent.parent.parent / "scripts" / "healthcheck.py"
_spec = importlib.util.spec_from_file_location("healthcheck", _SCRIPT_PATH)
_healthcheck = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_healthcheck)


def _mock_response(status_code: int):
    """Create a mock HTTP response with the given status code."""
    response = MagicMock()
    response.status = status_code
    response.read.return_value = b"body"
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    return response


# HTTP status codes in the valid range, excluding 200
_non_200_status_codes = st.integers(min_value=201, max_value=599)


@settings(max_examples=100)
@given(status_code=_non_200_status_codes)
def test_exit_1_on_non_200_status(status_code: int) -> None:
    """Feature: observability-and-probes, Property 10: Healthcheck exit code reflects HTTP status.

    For any non-200 HTTP status code, the check() function returns 1.
    """
    # urllib.request.urlopen raises HTTPError for 4xx/5xx status codes
    error = urllib.error.HTTPError(
        url="http://localhost:9090/livez",
        code=status_code,
        msg="error",
        hdrs={},
        fp=BytesIO(b""),
    )
    with patch("urllib.request.urlopen", side_effect=error):
        with patch.object(_healthcheck, "METRICS_PORT", 9090):
            exit_code = _healthcheck.check("/livez")
    assert exit_code == 1, (
        f"Expected exit 1 for HTTP {status_code}, got {exit_code}"
    )


@settings(max_examples=100)
@given(status_code=st.just(200))
def test_exit_0_on_http_200(status_code: int) -> None:
    """Feature: observability-and-probes, Property 10: Healthcheck exit code reflects HTTP status.

    The check() function returns 0 when the server returns HTTP 200.
    """
    response = _mock_response(status_code)
    with patch("urllib.request.urlopen", return_value=response):
        with patch.object(_healthcheck, "METRICS_PORT", 9090):
            exit_code = _healthcheck.check("/livez")
    assert exit_code == 0, (
        f"Expected exit 0 for HTTP {status_code}, got {exit_code}"
    )


@settings(max_examples=100)
@given(
    endpoint=st.sampled_from(["/livez", "/readyz"]),
    status_code=_non_200_status_codes,
)
def test_exit_1_for_both_endpoints_on_non_200(
    endpoint: str, status_code: int
) -> None:
    """Feature: observability-and-probes, Property 10: Healthcheck exit code reflects HTTP status.

    For any non-200 status and either endpoint, check() returns 1.
    """
    error = urllib.error.HTTPError(
        url=f"http://localhost:9090{endpoint}",
        code=status_code,
        msg="error",
        hdrs={},
        fp=BytesIO(b""),
    )
    with patch("urllib.request.urlopen", side_effect=error):
        with patch.object(_healthcheck, "METRICS_PORT", 9090):
            exit_code = _healthcheck.check(endpoint)
    assert exit_code == 1, (
        f"Expected exit 1 for HTTP {status_code} on {endpoint}, "
        f"got {exit_code}"
    )


@settings(max_examples=100)
@given(endpoint=st.sampled_from(["/livez", "/readyz"]))
def test_exit_0_for_both_endpoints_on_200(endpoint: str) -> None:
    """Feature: observability-and-probes, Property 10: Healthcheck exit code reflects HTTP status.

    For HTTP 200 and either endpoint, check() returns 0.
    """
    response = _mock_response(200)
    with patch("urllib.request.urlopen", return_value=response):
        with patch.object(_healthcheck, "METRICS_PORT", 9090):
            exit_code = _healthcheck.check(endpoint)
    assert exit_code == 0, (
        f"Expected exit 0 for HTTP 200 on {endpoint}, got {exit_code}"
    )


def test_exit_1_on_connection_refused() -> None:
    """Feature: observability-and-probes, Property 10: Healthcheck exit code reflects HTTP status.

    check() returns 1 when the connection is refused (URLError).
    """
    error = urllib.error.URLError(
        reason=ConnectionRefusedError("Connection refused")
    )
    with patch("urllib.request.urlopen", side_effect=error):
        with patch.object(_healthcheck, "METRICS_PORT", 9090):
            exit_code = _healthcheck.check("/livez")
    assert exit_code == 1, (
        f"Expected exit 1 on connection refused, got {exit_code}"
    )


def test_exit_1_on_timeout() -> None:
    """Feature: observability-and-probes, Property 10: Healthcheck exit code reflects HTTP status.

    check() returns 1 when the connection times out (OSError).
    """
    error = OSError("Connection timed out")
    with patch("urllib.request.urlopen", side_effect=error):
        with patch.object(_healthcheck, "METRICS_PORT", 9090):
            exit_code = _healthcheck.check("/livez")
    assert exit_code == 1, (
        f"Expected exit 1 on timeout, got {exit_code}"
    )


def test_exit_1_on_connection_failure_readiness() -> None:
    """Feature: observability-and-probes, Property 10: Healthcheck exit code reflects HTTP status.

    check() returns 1 for /readyz when the server is unreachable.
    """
    error = urllib.error.URLError(
        reason=ConnectionRefusedError("Connection refused")
    )
    with patch("urllib.request.urlopen", side_effect=error):
        with patch.object(_healthcheck, "METRICS_PORT", 9090):
            exit_code = _healthcheck.check("/readyz")
    assert exit_code == 1, (
        f"Expected exit 1 on connection failure, got {exit_code}"
    )
