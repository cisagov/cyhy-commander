"""Property-based tests for DefaultHostStateManager.

Verifies the two core correctness properties of the host state machine
using Hypothesis.

**Validates: Requirements MR-8.1, MR-8.2**
"""

from cyhy_db.models.enum import Stage, Status
from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander.host_state_manager import (
    DefaultHostStateManager,
    StateTransitionResult,
)

# Shared instance — new_state() is pure (no I/O, no mutable state)
_hsm = DefaultHostStateManager()


@given(
    stage=st.sampled_from(Stage),
    status=st.sampled_from(Status),
    up=st.booleans(),
    has_open_ports=st.booleans(),
    was_failure=st.booleans(),
)
@settings(max_examples=500)
def test_state_machine_determinism(
    stage: Stage,
    status: Status,
    up: bool,
    has_open_ports: bool,
    was_failure: bool,
) -> None:
    """Property MR-8.1: State machine determinism.

    For all (stage, status, up, has_open_ports, was_failure) inputs,
    calling new_state() twice with identical inputs returns identical results.

    **Validates: Requirements MR-8.1**
    """
    result1 = _hsm.new_state(stage, status, up, has_open_ports, was_failure)
    result2 = _hsm.new_state(stage, status, up, has_open_ports, was_failure)
    assert result1 == result2, (
        f"Non-deterministic result for "
        f"(stage={stage!r}, status={status!r}, up={up}, "
        f"has_open_ports={has_open_ports}, was_failure={was_failure}): "
        f"{result1!r} != {result2!r}"
    )


@given(
    stage=st.sampled_from(Stage),
    status=st.sampled_from(Status),
    up=st.booleans(),
    has_open_ports=st.booleans(),
    was_failure=st.booleans(),
)
@settings(max_examples=500)
def test_state_machine_exhaustiveness(
    stage: Stage,
    status: Status,
    up: bool,
    has_open_ports: bool,
    was_failure: bool,
) -> None:
    """Property MR-8.2: State machine exhaustiveness.

    For all (stage, status) combinations, new_state() completes without
    raising an exception and returns a StateTransitionResult with valid
    Stage and Status values.

    **Validates: Requirements MR-8.2**
    """
    # Must not raise for any input combination
    result = _hsm.new_state(stage, status, up, has_open_ports, was_failure)

    assert isinstance(
        result, StateTransitionResult
    ), f"new_state() returned {type(result)!r} instead of StateTransitionResult"
    assert isinstance(
        result.new_stage, Stage
    ), f"result.new_stage={result.new_stage!r} is not a valid Stage"
    assert isinstance(
        result.new_status, Status
    ), f"result.new_status={result.new_status!r} is not a valid Status"
    assert result.finished_stage is None or isinstance(
        result.finished_stage, Stage
    ), f"result.finished_stage={result.finished_stage!r} is not Stage or None"
