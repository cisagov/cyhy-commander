"""Property-based tests for DefaultScheduler.

Verifies the monotonicity property of the scheduler's priority-to-interval
mapping using Hypothesis.

**Validates: Requirements MR-8.3**
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander.scheduler import DefaultScheduler

# Shared instance — timedelta_for_priority is pure (no I/O, no mutable state)
_scheduler = DefaultScheduler()


@given(
    p1=st.integers(min_value=-16, max_value=1),
    p2=st.integers(min_value=-16, max_value=1),
)
@settings(max_examples=500)
def test_scheduler_monotonicity(p1: int, p2: int) -> None:
    """Property MR-8.3: Scheduler monotonicity.

    For any two priorities p1 < p2 in [-16, 1],
    timedelta_for_priority(p1) < timedelta_for_priority(p2).
    Equal priorities produce equal intervals.

    Lower priority number = higher urgency = shorter scan interval.

    **Validates: Requirements MR-8.3**
    """
    td1 = _scheduler.timedelta_for_priority(p1)
    td2 = _scheduler.timedelta_for_priority(p2)

    if p1 < p2:
        assert td1 < td2, (
            f"Expected timedelta_for_priority({p1}) < timedelta_for_priority({p2}), "
            f"but got {td1} >= {td2}"
        )
    elif p1 == p2:
        assert td1 == td2, (
            f"Expected timedelta_for_priority({p1}) == timedelta_for_priority({p2}), "
            f"but got {td1} != {td2}"
        )
    else:
        # p1 > p2
        assert td1 > td2, (
            f"Expected timedelta_for_priority({p1}) > timedelta_for_priority({p2}), "
            f"but got {td1} <= {td2}"
        )
