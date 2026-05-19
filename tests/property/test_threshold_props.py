"""Property-based tests for threshold environment variable validation.

Verifies Property 8: Threshold environment variable validation.

- For any string value of CYHY_LIVENESS_THRESHOLD_SECONDS, if it parses to a
  positive numeric value then that value is used as the liveness threshold;
  otherwise the threshold defaults to 300.
- For any string value of CYHY_READINESS_THRESHOLD_SECONDS, if it parses to an
  integer in [1, 3600] then that value is used; otherwise the threshold
  defaults to 120.

**Validates: Requirements 4.4, 4.5, 5.4, 5.5**
"""

import os
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander.metrics import (
    DEFAULT_LIVENESS_THRESHOLD,
    DEFAULT_READINESS_THRESHOLD,
    get_liveness_threshold,
    get_readiness_threshold,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Strategy for valid positive numeric strings (liveness threshold)
valid_liveness_values = st.floats(
    min_value=0.001, max_value=1e9, allow_nan=False, allow_infinity=False
)

# Strategy for valid integer strings in [1, 3600] (readiness threshold)
valid_readiness_values = st.integers(min_value=1, max_value=3600)

# Strategy for arbitrary strings that may or may not be valid.
# Exclude null bytes since os.environ cannot contain them.
arbitrary_strings = st.text(
    alphabet=st.characters(
        codec="ascii", exclude_characters="\x00"
    ),
    min_size=0,
    max_size=50,
)


# ---------------------------------------------------------------------------
# Property 8a: Liveness threshold - valid positive numeric → used
# ---------------------------------------------------------------------------


@given(value=valid_liveness_values)
@settings(max_examples=100)
def test_liveness_threshold_valid_positive_numeric_is_used(
    value: float,
) -> None:
    """Feature: observability-and-probes, Property 8: Threshold environment variable validation.

    Valid positive numeric CYHY_LIVENESS_THRESHOLD_SECONDS values are used.

    **Validates: Requirements 4.4, 4.5**
    """
    env_value = str(value)
    with patch.dict(
        os.environ, {"CYHY_LIVENESS_THRESHOLD_SECONDS": env_value}
    ):
        result = get_liveness_threshold()
    assert result == float(env_value), (
        f"Expected {float(env_value)}, got {result} for input {env_value!r}"
    )


# ---------------------------------------------------------------------------
# Property 8b: Liveness threshold - invalid → 300 default
# ---------------------------------------------------------------------------


@given(raw=arbitrary_strings)
@settings(max_examples=100)
def test_liveness_threshold_invalid_returns_default(raw: str) -> None:
    """Feature: observability-and-probes, Property 8: Threshold environment variable validation.

    Invalid CYHY_LIVENESS_THRESHOLD_SECONDS values fall back to 300.0 default.

    **Validates: Requirements 4.4, 4.5**
    """
    # Determine if the value is valid (positive numeric)
    try:
        parsed = float(raw)
        is_valid = parsed > 0
    except (ValueError, OverflowError):
        is_valid = False

    # Skip values that are actually valid - we only test invalid ones here
    if is_valid:
        return

    with patch.dict(
        os.environ, {"CYHY_LIVENESS_THRESHOLD_SECONDS": raw}
    ):
        result = get_liveness_threshold()
    assert result == DEFAULT_LIVENESS_THRESHOLD, (
        f"Expected default {DEFAULT_LIVENESS_THRESHOLD}, got {result} "
        f"for invalid input {raw!r}"
    )


# ---------------------------------------------------------------------------
# Property 8c: Liveness threshold - unset env var → 300 default
# ---------------------------------------------------------------------------


def test_liveness_threshold_unset_returns_default() -> None:
    """Feature: observability-and-probes, Property 8: Threshold environment variable validation.

    Unset CYHY_LIVENESS_THRESHOLD_SECONDS returns 300.0 default.

    **Validates: Requirements 4.4, 4.5**
    """
    env = os.environ.copy()
    env.pop("CYHY_LIVENESS_THRESHOLD_SECONDS", None)
    with patch.dict(os.environ, env, clear=True):
        result = get_liveness_threshold()
    assert result == DEFAULT_LIVENESS_THRESHOLD


# ---------------------------------------------------------------------------
# Property 8d: Readiness threshold - valid integer in [1, 3600] → used
# ---------------------------------------------------------------------------


@given(value=valid_readiness_values)
@settings(max_examples=100)
def test_readiness_threshold_valid_integer_in_range_is_used(
    value: int,
) -> None:
    """Feature: observability-and-probes, Property 8: Threshold environment variable validation.

    Valid integer CYHY_READINESS_THRESHOLD_SECONDS values in [1, 3600] are used.

    **Validates: Requirements 5.4, 5.5**
    """
    env_value = str(value)
    with patch.dict(
        os.environ, {"CYHY_READINESS_THRESHOLD_SECONDS": env_value}
    ):
        result = get_readiness_threshold()
    assert result == float(value), (
        f"Expected {float(value)}, got {result} for input {env_value!r}"
    )


# ---------------------------------------------------------------------------
# Property 8e: Readiness threshold - invalid → 120 default
# ---------------------------------------------------------------------------


@given(raw=arbitrary_strings)
@settings(max_examples=100)
def test_readiness_threshold_invalid_returns_default(raw: str) -> None:
    """Feature: observability-and-probes, Property 8: Threshold environment variable validation.

    Invalid CYHY_READINESS_THRESHOLD_SECONDS values fall back to 120.0 default.

    **Validates: Requirements 5.4, 5.5**
    """
    # Determine if the value is valid (integer in [1, 3600])
    try:
        parsed = int(raw)
        is_valid = 1 <= parsed <= 3600
    except (ValueError, OverflowError):
        is_valid = False

    # Skip values that are actually valid - we only test invalid ones here
    if is_valid:
        return

    with patch.dict(
        os.environ, {"CYHY_READINESS_THRESHOLD_SECONDS": raw}
    ):
        result = get_readiness_threshold()
    assert result == DEFAULT_READINESS_THRESHOLD, (
        f"Expected default {DEFAULT_READINESS_THRESHOLD}, got {result} "
        f"for invalid input {raw!r}"
    )


# ---------------------------------------------------------------------------
# Property 8f: Readiness threshold - out of range integers → 120 default
# ---------------------------------------------------------------------------


@given(
    value=st.one_of(
        st.integers(max_value=0),
        st.integers(min_value=3601),
    )
)
@settings(max_examples=100)
def test_readiness_threshold_out_of_range_returns_default(
    value: int,
) -> None:
    """Feature: observability-and-probes, Property 8: Threshold environment variable validation.

    Out-of-range integer CYHY_READINESS_THRESHOLD_SECONDS values fall back to 120.0 default.

    **Validates: Requirements 5.4, 5.5**
    """
    env_value = str(value)
    with patch.dict(
        os.environ, {"CYHY_READINESS_THRESHOLD_SECONDS": env_value}
    ):
        result = get_readiness_threshold()
    assert result == DEFAULT_READINESS_THRESHOLD, (
        f"Expected default {DEFAULT_READINESS_THRESHOLD}, got {result} "
        f"for out-of-range input {env_value!r}"
    )


# ---------------------------------------------------------------------------
# Property 8g: Readiness threshold - unset env var → 120 default
# ---------------------------------------------------------------------------


def test_readiness_threshold_unset_returns_default() -> None:
    """Feature: observability-and-probes, Property 8: Threshold environment variable validation.

    Unset CYHY_READINESS_THRESHOLD_SECONDS returns 120.0 default.

    **Validates: Requirements 5.4, 5.5**
    """
    env = os.environ.copy()
    env.pop("CYHY_READINESS_THRESHOLD_SECONDS", None)
    with patch.dict(os.environ, env, clear=True):
        result = get_readiness_threshold()
    assert result == DEFAULT_READINESS_THRESHOLD
