"""Host scan state machine for CyHy Commander.

This module provides the DefaultHostStateManager class, which implements
the deterministic state machine that determines the next (stage, status)
for a host after a scan completes.

Ported from cyhy-core/cyhy/db/host_state_manager.py with zero dependency
on cyhy.db, cyhy.core, or cyhy.util.
"""

# Standard Python Libraries
import logging
from dataclasses import dataclass

# Third-party libraries
from cyhy_db.models.enum import Stage, Status

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StateTransitionResult:
    """The result of applying the host state machine.

    Attributes:
        new_stage: The stage the host should move to.
        new_status: The status the host should move to.
        was_changed: True if the state actually changed from the input.
        finished_stage: The stage that was completed, or None if no stage
            was finished (e.g., failure revert, terminal DONE, or unexpected).
    """

    new_stage: Stage
    new_status: Status
    was_changed: bool
    finished_stage: Stage | None


class DefaultHostStateManager:
    """Implements the host scan stage/status state machine.

    All transitions are deterministic given the same inputs. This class
    performs no I/O; the caller is responsible for persisting results.
    """

    def new_state(
        self,
        stage: Stage,
        status: Status,
        up: bool = False,
        has_open_ports: bool = False,
        was_failure: bool = False,
    ) -> StateTransitionResult:
        """Apply the state machine and return the new state.

        This method is pure (no I/O). The caller is responsible for
        persisting the result to the database.

        State-transition table:
          NETSCAN1 / RUNNING, up=True      → PORTSCAN  / WAITING  (finished: NETSCAN1)
          NETSCAN1 / RUNNING, up=False     → NETSCAN2  / WAITING  (finished: NETSCAN1)
          NETSCAN2 / RUNNING, up=True      → PORTSCAN  / WAITING  (finished: NETSCAN2)
          NETSCAN2 / RUNNING, up=False     → NETSCAN2  / DONE     (finished: NETSCAN2)
          PORTSCAN / RUNNING, ports=True   → VULNSCAN  / WAITING  (finished: PORTSCAN)
          PORTSCAN / RUNNING, ports=False  → PORTSCAN  / DONE     (finished: PORTSCAN)
          VULNSCAN / RUNNING               → VULNSCAN  / DONE     (finished: VULNSCAN)
          Any non-DONE, was_failure=True   → same_stage / WAITING (finished: None)
          DONE / DONE                      → DONE      / DONE     (terminal, no change)

        Args:
            stage: The host's current scan stage.
            status: The host's current scan status.
            up: Whether the host responded to the network scan (NETSCAN only).
            has_open_ports: Whether the host has open ports (PORTSCAN only).
            was_failure: Whether the scan failed; causes revert to WAITING.

        Returns:
            A StateTransitionResult describing the new state.
        """
        # Terminal state: DONE status means the host has completed its scan
        # cycle. No further transitions occur.
        if status == Status.DONE:
            return StateTransitionResult(
                new_stage=stage,
                new_status=Status.DONE,
                was_changed=False,
                finished_stage=None,
            )

        # Failure transition: any non-DONE host with was_failure=True reverts
        # to the same stage with WAITING status.
        if was_failure:
            was_changed = status != Status.WAITING
            return StateTransitionResult(
                new_stage=stage,
                new_status=Status.WAITING,
                was_changed=was_changed,
                finished_stage=None,
            )

        # Normal transitions — only defined for RUNNING status.
        if status == Status.RUNNING:
            if stage == Stage.NETSCAN1:
                if up:
                    return StateTransitionResult(
                        new_stage=Stage.PORTSCAN,
                        new_status=Status.WAITING,
                        was_changed=True,
                        finished_stage=Stage.NETSCAN1,
                    )
                else:
                    return StateTransitionResult(
                        new_stage=Stage.NETSCAN2,
                        new_status=Status.WAITING,
                        was_changed=True,
                        finished_stage=Stage.NETSCAN1,
                    )

            elif stage == Stage.NETSCAN2:
                if up:
                    return StateTransitionResult(
                        new_stage=Stage.PORTSCAN,
                        new_status=Status.WAITING,
                        was_changed=True,
                        finished_stage=Stage.NETSCAN2,
                    )
                else:
                    return StateTransitionResult(
                        new_stage=Stage.NETSCAN2,
                        new_status=Status.DONE,
                        was_changed=True,
                        finished_stage=Stage.NETSCAN2,
                    )

            elif stage == Stage.PORTSCAN:
                if has_open_ports:
                    return StateTransitionResult(
                        new_stage=Stage.VULNSCAN,
                        new_status=Status.WAITING,
                        was_changed=True,
                        finished_stage=Stage.PORTSCAN,
                    )
                else:
                    return StateTransitionResult(
                        new_stage=Stage.PORTSCAN,
                        new_status=Status.DONE,
                        was_changed=True,
                        finished_stage=Stage.PORTSCAN,
                    )

            elif stage == Stage.VULNSCAN:
                return StateTransitionResult(
                    new_stage=Stage.VULNSCAN,
                    new_status=Status.DONE,
                    was_changed=True,
                    finished_stage=Stage.VULNSCAN,
                )

        # Unexpected (stage, status) combination — log a warning and return
        # unchanged state rather than raising.
        logger.warning(
            "Unexpected (stage=%r, status=%r) combination in host state machine; "
            "returning unchanged state.",
            stage,
            status,
        )
        return StateTransitionResult(
            new_stage=stage,
            new_status=status,
            was_changed=False,
            finished_stage=None,
        )
