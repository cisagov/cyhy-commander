"""Property-based tests for cooldown duration invariant.

Verifies Property 6 (MR-8.6): a host placed on cooldown at time T must
not appear in any work group for any query time in
[T, T + cooldown_duration_minutes); it must reappear at or after
T + cooldown_duration_minutes.

**Validates: Requirements MR-8.6, AC-11.6**
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander.commander import Commander
from cyhy_commander.config_model import CommanderConfig


def _make_commander(cooldown_minutes: int) -> Commander:
    """Create a Commander with the given cooldown duration."""
    config = CommanderConfig(
        mongodb_uri="mongodb://localhost:27017/test",
        mongodb_database="test",
        nmap_hosts=["scanner1"],
        nessus_hosts=["nessus1"],
        test_mode=True,
    )
    config.scanner_reliability.cooldown_duration_minutes = cooldown_minutes
    work_dir = Path(tempfile.mkdtemp())
    return Commander(config, work_dir=work_dir)


@given(
    cooldown_minutes=st.integers(min_value=1, max_value=120),
    elapsed_seconds=st.integers(min_value=0, max_value=7199),
)
@settings(max_examples=200, deadline=None)
def test_cooldown_duration_invariant(
    cooldown_minutes: int, elapsed_seconds: int
) -> None:
    """Host on cooldown is excluded before duration, restored at/after."""
    cooldown_start = 1000000.0
    cooldown_end = cooldown_start + cooldown_minutes * 60
    query_time = cooldown_start + elapsed_seconds

    commander = _make_commander(cooldown_minutes)

    # Place host on cooldown
    # Access private attribute for testing
    commander._Commander__hosts_on_cooldown.append(
        {
            "host": "scanner1",
            "cooldown_start": cooldown_start,
            "work_groups": ["nmap"],
        }
    )

    # Simulate the work cycle's exclusion check
    hosts_on_cooldown = commander._Commander__hosts_on_cooldown
    excluded = "scanner1" in [h["host"] for h in hosts_on_cooldown]
    assert excluded, "Host should be excluded while on cooldown list"

    # Now run __check_cooldowns at query_time
    nmap_hosts: list[str] = []
    nessus_hosts: list[str] = []

    with patch("cyhy_commander.commander.time.time", return_value=query_time):
        commander._Commander__check_cooldowns(nmap_hosts, nessus_hosts)

    if query_time < cooldown_end:
        # Host must NOT be restored yet
        assert "scanner1" not in nmap_hosts
        assert len(commander._Commander__hosts_on_cooldown) == 1
    else:
        # Host must be restored
        assert "scanner1" in nmap_hosts
        assert len(commander._Commander__hosts_on_cooldown) == 0
