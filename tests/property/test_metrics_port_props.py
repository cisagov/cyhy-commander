"""Property-based tests for port configuration validation.

Verifies Property 7: For any string value of CYHY_METRICS_PORT, if it
parses to an integer in [1024, 65535] then that integer is used;
otherwise default 9090 is returned.

**Validates: Requirements 3.6**
"""

import os
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander.metrics import DEFAULT_METRICS_PORT, get_metrics_port


@settings(max_examples=100)
@given(port_value=st.integers(min_value=1024, max_value=65535))
def test_valid_port_values_are_used(port_value: int) -> None:
    """Feature: observability-and-probes, Property 7: Port configuration validation.

    Valid integer port values in [1024, 65535] are returned as-is.
    """
    with patch.dict(os.environ, {"CYHY_METRICS_PORT": str(port_value)}):
        assert get_metrics_port() == port_value


@settings(max_examples=100)
@given(port_value=st.integers().filter(lambda x: x < 1024 or x > 65535))
def test_out_of_range_port_values_return_default(port_value: int) -> None:
    """Feature: observability-and-probes, Property 7: Port configuration validation.

    Integer values outside [1024, 65535] fall back to default 9090.
    """
    with patch.dict(os.environ, {"CYHY_METRICS_PORT": str(port_value)}):
        assert get_metrics_port() == DEFAULT_METRICS_PORT


@settings(max_examples=100)
@given(
    raw_value=st.text(
        alphabet=st.characters(blacklist_characters="\x00"),
        min_size=1,
    ).filter(lambda s: not _is_valid_port_string(s))
)
def test_non_integer_strings_return_default(raw_value: str) -> None:
    """Feature: observability-and-probes, Property 7: Port configuration validation.

    Non-integer string values fall back to default 9090.
    """
    with patch.dict(os.environ, {"CYHY_METRICS_PORT": raw_value}):
        assert get_metrics_port() == DEFAULT_METRICS_PORT


def test_empty_or_unset_env_returns_default() -> None:
    """Feature: observability-and-probes, Property 7: Port configuration validation.

    Unset or empty CYHY_METRICS_PORT returns default 9090.
    """
    # Unset case
    env = os.environ.copy()
    env.pop("CYHY_METRICS_PORT", None)
    with patch.dict(os.environ, env, clear=True):
        assert get_metrics_port() == DEFAULT_METRICS_PORT

    # Empty string case
    with patch.dict(os.environ, {"CYHY_METRICS_PORT": ""}):
        assert get_metrics_port() == DEFAULT_METRICS_PORT


def _is_valid_port_string(s: str) -> bool:
    """Check if a string represents a valid port in [1024, 65535]."""
    try:
        port = int(s)
        return 1024 <= port <= 65535
    except (ValueError, OverflowError):
        return False
