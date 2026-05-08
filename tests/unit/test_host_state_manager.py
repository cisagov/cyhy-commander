"""Unit tests for DefaultHostStateManager.

Covers every row of the state-transition table, the DONE terminal state,
failure transitions, was_changed semantics, and unexpected (stage, status)
combinations.

Requirements: AC-8.1, FR-8.1
"""

import pytest
from cyhy_db.models.enum import Stage, Status

from cyhy_commander.host_state_manager import (
    DefaultHostStateManager,
    StateTransitionResult,
)


@pytest.fixture
def manager():
    """Return a fresh DefaultHostStateManager for each test."""
    return DefaultHostStateManager()


# ---------------------------------------------------------------------------
# State-transition table — normal (non-failure) transitions
# ---------------------------------------------------------------------------


class TestNetscan1Running:
    """NETSCAN1 / RUNNING transitions."""

    def test_up_true_goes_to_portscan_waiting(self, manager):
        """NETSCAN1/RUNNING + up=True → PORTSCAN/WAITING, finished=NETSCAN1."""
        result = manager.new_state(Stage.NETSCAN1, Status.RUNNING, up=True)
        assert result.new_stage == Stage.PORTSCAN
        assert result.new_status == Status.WAITING
        assert result.was_changed is True
        assert result.finished_stage == Stage.NETSCAN1

    def test_up_false_goes_to_netscan2_waiting(self, manager):
        """NETSCAN1/RUNNING + up=False → NETSCAN2/WAITING, finished=NETSCAN1."""
        result = manager.new_state(Stage.NETSCAN1, Status.RUNNING, up=False)
        assert result.new_stage == Stage.NETSCAN2
        assert result.new_status == Status.WAITING
        assert result.was_changed is True
        assert result.finished_stage == Stage.NETSCAN1


class TestNetscan2Running:
    """NETSCAN2 / RUNNING transitions."""

    def test_up_true_goes_to_portscan_waiting(self, manager):
        """NETSCAN2/RUNNING + up=True → PORTSCAN/WAITING, finished=NETSCAN2."""
        result = manager.new_state(Stage.NETSCAN2, Status.RUNNING, up=True)
        assert result.new_stage == Stage.PORTSCAN
        assert result.new_status == Status.WAITING
        assert result.was_changed is True
        assert result.finished_stage == Stage.NETSCAN2

    def test_up_false_goes_to_netscan2_done(self, manager):
        """NETSCAN2/RUNNING + up=False → NETSCAN2/DONE, finished=NETSCAN2."""
        result = manager.new_state(Stage.NETSCAN2, Status.RUNNING, up=False)
        assert result.new_stage == Stage.NETSCAN2
        assert result.new_status == Status.DONE
        assert result.was_changed is True
        assert result.finished_stage == Stage.NETSCAN2


class TestPortscanRunning:
    """PORTSCAN / RUNNING transitions."""

    def test_has_open_ports_true_goes_to_vulnscan_waiting(self, manager):
        """PORTSCAN/RUNNING + has_open_ports=True → VULNSCAN/WAITING, finished=PORTSCAN."""
        result = manager.new_state(
            Stage.PORTSCAN, Status.RUNNING, has_open_ports=True
        )
        assert result.new_stage == Stage.VULNSCAN
        assert result.new_status == Status.WAITING
        assert result.was_changed is True
        assert result.finished_stage == Stage.PORTSCAN

    def test_has_open_ports_false_goes_to_portscan_done(self, manager):
        """PORTSCAN/RUNNING + has_open_ports=False → PORTSCAN/DONE, finished=PORTSCAN."""
        result = manager.new_state(
            Stage.PORTSCAN, Status.RUNNING, has_open_ports=False
        )
        assert result.new_stage == Stage.PORTSCAN
        assert result.new_status == Status.DONE
        assert result.was_changed is True
        assert result.finished_stage == Stage.PORTSCAN


class TestVulnscanRunning:
    """VULNSCAN / RUNNING transition."""

    def test_goes_to_vulnscan_done(self, manager):
        """VULNSCAN/RUNNING → VULNSCAN/DONE, finished=VULNSCAN."""
        result = manager.new_state(Stage.VULNSCAN, Status.RUNNING)
        assert result.new_stage == Stage.VULNSCAN
        assert result.new_status == Status.DONE
        assert result.was_changed is True
        assert result.finished_stage == Stage.VULNSCAN


# ---------------------------------------------------------------------------
# DONE terminal state
# ---------------------------------------------------------------------------


class TestDoneTerminalState:
    """DONE/DONE is a terminal state — no further transitions."""

    def test_done_returns_unchanged(self, manager):
        """DONE/DONE → DONE/DONE, was_changed=False, finished_stage=None."""
        result = manager.new_state(Stage.VULNSCAN, Status.DONE)
        assert result.new_stage == Stage.VULNSCAN
        assert result.new_status == Status.DONE
        assert result.was_changed is False
        assert result.finished_stage is None

    def test_done_ignores_up_flag(self, manager):
        """DONE/DONE with up=True still returns unchanged state."""
        result = manager.new_state(Stage.NETSCAN1, Status.DONE, up=True)
        assert result.new_stage == Stage.NETSCAN1
        assert result.new_status == Status.DONE
        assert result.was_changed is False
        assert result.finished_stage is None

    def test_done_ignores_was_failure_flag(self, manager):
        """DONE/DONE with was_failure=True still returns unchanged state (terminal)."""
        result = manager.new_state(Stage.PORTSCAN, Status.DONE, was_failure=True)
        assert result.new_stage == Stage.PORTSCAN
        assert result.new_status == Status.DONE
        assert result.was_changed is False
        assert result.finished_stage is None

    @pytest.mark.parametrize("stage", list(Stage))
    def test_done_is_terminal_for_all_stages(self, manager, stage):
        """DONE status is terminal regardless of which stage the host is in."""
        result = manager.new_state(stage, Status.DONE)
        assert result.new_stage == stage
        assert result.new_status == Status.DONE
        assert result.was_changed is False
        assert result.finished_stage is None


# ---------------------------------------------------------------------------
# Failure transitions
# ---------------------------------------------------------------------------


class TestFailureTransitions:
    """was_failure=True reverts any non-DONE host to WAITING in the same stage."""

    @pytest.mark.parametrize("stage", list(Stage))
    def test_failure_from_running_reverts_to_waiting(self, manager, stage):
        """Any stage/RUNNING + was_failure=True → same_stage/WAITING, was_changed=True."""
        result = manager.new_state(stage, Status.RUNNING, was_failure=True)
        assert result.new_stage == stage
        assert result.new_status == Status.WAITING
        assert result.was_changed is True  # RUNNING → WAITING is a real change
        assert result.finished_stage is None

    @pytest.mark.parametrize("stage", list(Stage))
    def test_failure_from_waiting_returns_unchanged(self, manager, stage):
        """Any stage/WAITING + was_failure=True → same_stage/WAITING, was_changed=False."""
        result = manager.new_state(stage, Status.WAITING, was_failure=True)
        assert result.new_stage == stage
        assert result.new_status == Status.WAITING
        assert result.was_changed is False  # WAITING → WAITING: no real change
        assert result.finished_stage is None

    @pytest.mark.parametrize("stage", list(Stage))
    def test_failure_from_ready_reverts_to_waiting(self, manager, stage):
        """Any stage/READY + was_failure=True → same_stage/WAITING, was_changed=True."""
        result = manager.new_state(stage, Status.READY, was_failure=True)
        assert result.new_stage == stage
        assert result.new_status == Status.WAITING
        assert result.was_changed is True  # READY → WAITING is a real change
        assert result.finished_stage is None

    def test_failure_preserves_stage(self, manager):
        """Failure transition keeps the host in its current stage."""
        result = manager.new_state(Stage.PORTSCAN, Status.RUNNING, was_failure=True)
        assert result.new_stage == Stage.PORTSCAN

    def test_failure_finished_stage_is_none(self, manager):
        """Failure transition never sets finished_stage."""
        result = manager.new_state(Stage.VULNSCAN, Status.RUNNING, was_failure=True)
        assert result.finished_stage is None


# ---------------------------------------------------------------------------
# Unexpected (stage, status) combinations
# ---------------------------------------------------------------------------


class TestUnexpectedCombinations:
    """Unexpected (stage, status) pairs return unchanged state without raising."""

    def test_netscan1_done_returns_unchanged(self, manager):
        """NETSCAN1/DONE is handled by the DONE terminal branch — unchanged."""
        result = manager.new_state(Stage.NETSCAN1, Status.DONE)
        assert result.new_stage == Stage.NETSCAN1
        assert result.new_status == Status.DONE
        assert result.was_changed is False
        assert result.finished_stage is None

    def test_portscan_ready_returns_unchanged(self, manager):
        """PORTSCAN/READY is an unexpected combination — returns unchanged state."""
        result = manager.new_state(Stage.PORTSCAN, Status.READY)
        assert result.new_stage == Stage.PORTSCAN
        assert result.new_status == Status.READY
        assert result.was_changed is False
        assert result.finished_stage is None

    def test_netscan1_waiting_returns_unchanged(self, manager):
        """NETSCAN1/WAITING is an unexpected combination — returns unchanged state."""
        result = manager.new_state(Stage.NETSCAN1, Status.WAITING)
        assert result.new_stage == Stage.NETSCAN1
        assert result.new_status == Status.WAITING
        assert result.was_changed is False
        assert result.finished_stage is None

    def test_vulnscan_ready_returns_unchanged(self, manager):
        """VULNSCAN/READY is an unexpected combination — returns unchanged state."""
        result = manager.new_state(Stage.VULNSCAN, Status.READY)
        assert result.new_stage == Stage.VULNSCAN
        assert result.new_status == Status.READY
        assert result.was_changed is False
        assert result.finished_stage is None

    def test_netscan2_ready_returns_unchanged(self, manager):
        """NETSCAN2/READY is an unexpected combination — returns unchanged state."""
        result = manager.new_state(Stage.NETSCAN2, Status.READY)
        assert result.new_stage == Stage.NETSCAN2
        assert result.new_status == Status.READY
        assert result.was_changed is False
        assert result.finished_stage is None

    @pytest.mark.parametrize(
        "stage, status",
        [
            (Stage.NETSCAN1, Status.WAITING),
            (Stage.NETSCAN2, Status.WAITING),
            (Stage.PORTSCAN, Status.WAITING),
            (Stage.VULNSCAN, Status.WAITING),
            (Stage.NETSCAN1, Status.READY),
            (Stage.NETSCAN2, Status.READY),
            (Stage.PORTSCAN, Status.READY),
            (Stage.VULNSCAN, Status.READY),
        ],
    )
    def test_unexpected_combinations_do_not_raise(self, manager, stage, status):
        """All unexpected (stage, status) combinations complete without exception."""
        result = manager.new_state(stage, status)
        assert isinstance(result, StateTransitionResult)

    @pytest.mark.parametrize(
        "stage, status",
        [
            (Stage.NETSCAN1, Status.WAITING),
            (Stage.NETSCAN2, Status.WAITING),
            (Stage.PORTSCAN, Status.WAITING),
            (Stage.VULNSCAN, Status.WAITING),
            (Stage.NETSCAN1, Status.READY),
            (Stage.NETSCAN2, Status.READY),
            (Stage.PORTSCAN, Status.READY),
            (Stage.VULNSCAN, Status.READY),
        ],
    )
    def test_unexpected_combinations_return_was_changed_false(
        self, manager, stage, status
    ):
        """Unexpected combinations return was_changed=False."""
        result = manager.new_state(stage, status)
        assert result.was_changed is False

    @pytest.mark.parametrize(
        "stage, status",
        [
            (Stage.NETSCAN1, Status.WAITING),
            (Stage.NETSCAN2, Status.WAITING),
            (Stage.PORTSCAN, Status.WAITING),
            (Stage.VULNSCAN, Status.WAITING),
            (Stage.NETSCAN1, Status.READY),
            (Stage.NETSCAN2, Status.READY),
            (Stage.PORTSCAN, Status.READY),
            (Stage.VULNSCAN, Status.READY),
        ],
    )
    def test_unexpected_combinations_preserve_stage_and_status(
        self, manager, stage, status
    ):
        """Unexpected combinations return the same stage and status unchanged."""
        result = manager.new_state(stage, status)
        assert result.new_stage == stage
        assert result.new_status == status


# ---------------------------------------------------------------------------
# Return type and immutability
# ---------------------------------------------------------------------------


class TestReturnType:
    """StateTransitionResult is a frozen dataclass."""

    def test_returns_state_transition_result(self, manager):
        """new_state() always returns a StateTransitionResult instance."""
        result = manager.new_state(Stage.NETSCAN1, Status.RUNNING, up=True)
        assert isinstance(result, StateTransitionResult)

    def test_result_is_immutable(self, manager):
        """StateTransitionResult is frozen — attribute assignment raises FrozenInstanceError."""
        result = manager.new_state(Stage.NETSCAN1, Status.RUNNING, up=True)
        with pytest.raises(Exception):  # FrozenInstanceError is a subclass of AttributeError
            result.new_stage = Stage.VULNSCAN  # type: ignore[misc]

    def test_result_fields_have_correct_types(self, manager):
        """All fields of StateTransitionResult have the expected types."""
        result = manager.new_state(Stage.NETSCAN1, Status.RUNNING, up=True)
        assert isinstance(result.new_stage, Stage)
        assert isinstance(result.new_status, Status)
        assert isinstance(result.was_changed, bool)
        # finished_stage is Stage | None
        assert result.finished_stage is None or isinstance(result.finished_stage, Stage)
