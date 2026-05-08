"""Unit tests for DefaultScheduler.

Covers timedelta_for_priority at each anchor point, interpolation between
anchor points, clamping at boundaries, and schedule_host with mocked DB
returning various severity/KEV combinations.

Requirements: AC-8.1, FR-8.2
"""

import asyncio
from datetime import timedelta, datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyhy_commander.scheduler import DefaultScheduler, _calculate_priority


@pytest.fixture
def scheduler():
    """Return a fresh DefaultScheduler for each test."""
    return DefaultScheduler()


# ---------------------------------------------------------------------------
# timedelta_for_priority — anchor points
# ---------------------------------------------------------------------------


class TestTimedeltaForPriorityAnchors:
    """timedelta_for_priority returns exact values at each anchor point."""

    def test_priority_1_is_90_days(self, scheduler):
        """Priority 1 (down host) → 90 days."""
        assert scheduler.timedelta_for_priority(1) == timedelta(days=90)

    def test_priority_0_is_14_days(self, scheduler):
        """Priority 0 → 14 days."""
        assert scheduler.timedelta_for_priority(0) == timedelta(days=14)

    def test_priority_minus_1_is_7_days(self, scheduler):
        """Priority -1 (up, no vulns) → 7 days."""
        assert scheduler.timedelta_for_priority(-1) == timedelta(days=7)

    def test_priority_minus_4_is_4_days(self, scheduler):
        """Priority -4 (severity 2) → 4 days."""
        assert scheduler.timedelta_for_priority(-4) == timedelta(days=4)

    def test_priority_minus_8_is_24_hours(self, scheduler):
        """Priority -8 (severity 3) → 24 hours."""
        assert scheduler.timedelta_for_priority(-8) == timedelta(hours=24)

    def test_priority_minus_16_is_12_hours(self, scheduler):
        """Priority -16 (severity 4 / KEV) → 12 hours."""
        assert scheduler.timedelta_for_priority(-16) == timedelta(hours=12)

    @pytest.mark.parametrize(
        "priority, expected",
        [
            (1, timedelta(days=90)),
            (0, timedelta(days=14)),
            (-1, timedelta(days=7)),
            (-4, timedelta(days=4)),
            (-8, timedelta(hours=24)),
            (-16, timedelta(hours=12)),
        ],
    )
    def test_all_anchor_points(self, scheduler, priority, expected):
        """All six anchor points return their exact expected timedelta."""
        assert scheduler.timedelta_for_priority(priority) == expected


# ---------------------------------------------------------------------------
# timedelta_for_priority — interpolation between anchor points
# ---------------------------------------------------------------------------


class TestTimedeltaForPriorityInterpolation:
    """timedelta_for_priority linearly interpolates between anchor points."""

    def test_midpoint_between_minus_1_and_minus_4(self, scheduler):
        """Priority -2.5 is midway between -1 (168h) and -4 (96h) → 132h."""
        # Linear interpolation: 168 + (96 - 168) * ((-2.5 - (-1)) / (-4 - (-1)))
        # = 168 + (-72) * (1.5 / 3) = 168 - 36 = 132 hours
        result = scheduler.timedelta_for_priority(-2.5)
        assert result == timedelta(hours=132)

    def test_midpoint_between_minus_8_and_minus_16(self, scheduler):
        """Priority -12 is midway between -8 (24h) and -16 (12h) → 18h."""
        # Linear interpolation: 24 + (12 - 24) * ((-12 - (-8)) / (-16 - (-8)))
        # = 24 + (-12) * (4 / 8) = 24 - 6 = 18 hours
        result = scheduler.timedelta_for_priority(-12)
        assert result == timedelta(hours=18)

    def test_midpoint_between_0_and_minus_1(self, scheduler):
        """Priority -0.5 is midway between 0 (336h) and -1 (168h) → 252h."""
        # Linear interpolation: 336 + (168 - 336) * (0.5 / 1) = 336 - 84 = 252h
        result = scheduler.timedelta_for_priority(-0.5)
        assert result == timedelta(hours=252)

    def test_midpoint_between_0_and_1(self, scheduler):
        """Priority 0.5 is midway between 0 (336h) and 1 (2160h) → 1248h."""
        # Linear interpolation: 336 + (2160 - 336) * 0.5 = 336 + 912 = 1248h
        result = scheduler.timedelta_for_priority(0.5)
        assert result == timedelta(hours=1248)

    def test_midpoint_between_minus_4_and_minus_8(self, scheduler):
        """Priority -6 is midway between -4 (96h) and -8 (24h) → 60h."""
        # Linear interpolation: 96 + (24 - 96) * ((-6 - (-4)) / (-8 - (-4)))
        # = 96 + (-72) * (2 / 4) = 96 - 36 = 60 hours
        result = scheduler.timedelta_for_priority(-6)
        assert result == timedelta(hours=60)

    def test_interpolated_value_is_between_anchor_bounds(self, scheduler):
        """Any priority between two anchors produces an interval between those anchors."""
        # Between -1 (7 days) and -4 (4 days)
        result = scheduler.timedelta_for_priority(-2)
        assert timedelta(days=4) < result < timedelta(days=7)

    def test_interpolation_is_monotonically_decreasing(self, scheduler):
        """Higher urgency (lower priority number) always yields a shorter interval."""
        priorities = [1, 0, -1, -2, -4, -6, -8, -12, -16]
        intervals = [scheduler.timedelta_for_priority(p) for p in priorities]
        for i in range(len(intervals) - 1):
            assert intervals[i] > intervals[i + 1], (
                f"Interval for priority {priorities[i]} ({intervals[i]}) "
                f"should be greater than for {priorities[i+1]} ({intervals[i+1]})"
            )


# ---------------------------------------------------------------------------
# timedelta_for_priority — boundary clamping
# ---------------------------------------------------------------------------


class TestTimedeltaForPriorityClamping:
    """Values outside [-16, 1] are clamped to the nearest anchor."""

    def test_priority_above_1_clamps_to_90_days(self, scheduler):
        """Priority > 1 clamps to the maximum interval (90 days)."""
        assert scheduler.timedelta_for_priority(5) == timedelta(days=90)
        assert scheduler.timedelta_for_priority(100) == timedelta(days=90)

    def test_priority_below_minus_16_clamps_to_12_hours(self, scheduler):
        """Priority < -16 clamps to the minimum interval (12 hours)."""
        assert scheduler.timedelta_for_priority(-20) == timedelta(hours=12)
        assert scheduler.timedelta_for_priority(-100) == timedelta(hours=12)

    def test_returns_timedelta_instance(self, scheduler):
        """timedelta_for_priority always returns a timedelta."""
        for priority in [1, 0, -1, -4, -8, -16, 5, -20]:
            result = scheduler.timedelta_for_priority(priority)
            assert isinstance(result, timedelta), (
                f"Expected timedelta for priority={priority}, got {type(result)}"
            )


# ---------------------------------------------------------------------------
# schedule_host — via _calculate_priority mock
# ---------------------------------------------------------------------------


class TestScheduleHost:
    """schedule_host sets host.priority and host.next_scan correctly."""

    def _make_host(self, up: bool = True):
        """Create a minimal mock HostDoc."""
        host = MagicMock()
        host.ip = "192.168.1.1"
        host.state = MagicMock()
        host.state.up = up
        host.priority = 0
        host.next_scan = None
        return host

    def test_schedule_host_sets_priority(self, scheduler):
        """schedule_host sets host.priority to the computed value."""
        host = self._make_host(up=False)
        with patch(
            "cyhy_commander.scheduler._calculate_priority",
            new=AsyncMock(return_value=1),
        ):
            asyncio.run(scheduler.schedule_host(host))
        assert host.priority == 1

    def test_schedule_host_sets_next_scan(self, scheduler):
        """schedule_host sets host.next_scan to a future datetime."""
        host = self._make_host(up=True)
        before = datetime.now(timezone.utc)
        with patch(
            "cyhy_commander.scheduler._calculate_priority",
            new=AsyncMock(return_value=-1),
        ):
            asyncio.run(scheduler.schedule_host(host))
        after = datetime.now(timezone.utc)

        assert host.next_scan is not None
        # next_scan should be approximately utcnow() + 7 days
        expected_interval = timedelta(days=7)
        assert host.next_scan >= before + expected_interval
        assert host.next_scan <= after + expected_interval

    def test_schedule_host_does_not_save(self, scheduler):
        """schedule_host does NOT call host.save() — caller is responsible."""
        host = self._make_host(up=True)
        with patch(
            "cyhy_commander.scheduler._calculate_priority",
            new=AsyncMock(return_value=-1),
        ):
            asyncio.run(scheduler.schedule_host(host))
        host.save.assert_not_called()

    def test_schedule_host_down_host_priority_1(self, scheduler):
        """Down host gets priority 1 (90-day interval)."""
        host = self._make_host(up=False)
        with patch(
            "cyhy_commander.scheduler._calculate_priority",
            new=AsyncMock(return_value=1),
        ):
            asyncio.run(scheduler.schedule_host(host))
        assert host.priority == 1
        # next_scan should be ~90 days from now
        expected = datetime.now(timezone.utc) + timedelta(days=90)
        delta = abs(host.next_scan - expected)
        assert delta < timedelta(seconds=5)

    def test_schedule_host_kev_priority_minus_16(self, scheduler):
        """Host with KEV vulnerability gets priority -16 (12-hour interval)."""
        host = self._make_host(up=True)
        with patch(
            "cyhy_commander.scheduler._calculate_priority",
            new=AsyncMock(return_value=-16),
        ):
            asyncio.run(scheduler.schedule_host(host))
        assert host.priority == -16
        expected = datetime.now(timezone.utc) + timedelta(hours=12)
        delta = abs(host.next_scan - expected)
        assert delta < timedelta(seconds=5)

    def test_schedule_host_severity_4_priority_minus_16(self, scheduler):
        """Host with severity 4 vulnerability gets priority -16 (12-hour interval)."""
        host = self._make_host(up=True)
        with patch(
            "cyhy_commander.scheduler._calculate_priority",
            new=AsyncMock(return_value=-16),
        ):
            asyncio.run(scheduler.schedule_host(host))
        assert host.priority == -16

    def test_schedule_host_severity_3_priority_minus_8(self, scheduler):
        """Host with severity 3 vulnerability gets priority -8 (24-hour interval)."""
        host = self._make_host(up=True)
        with patch(
            "cyhy_commander.scheduler._calculate_priority",
            new=AsyncMock(return_value=-8),
        ):
            asyncio.run(scheduler.schedule_host(host))
        assert host.priority == -8
        expected = datetime.now(timezone.utc) + timedelta(hours=24)
        delta = abs(host.next_scan - expected)
        assert delta < timedelta(seconds=5)

    def test_schedule_host_severity_2_priority_minus_4(self, scheduler):
        """Host with severity 2 vulnerability gets priority -4 (4-day interval)."""
        host = self._make_host(up=True)
        with patch(
            "cyhy_commander.scheduler._calculate_priority",
            new=AsyncMock(return_value=-4),
        ):
            asyncio.run(scheduler.schedule_host(host))
        assert host.priority == -4
        expected = datetime.now(timezone.utc) + timedelta(days=4)
        delta = abs(host.next_scan - expected)
        assert delta < timedelta(seconds=5)

    def test_schedule_host_no_vulns_priority_minus_1(self, scheduler):
        """Host with no vulnerabilities gets priority -1 (7-day interval)."""
        host = self._make_host(up=True)
        with patch(
            "cyhy_commander.scheduler._calculate_priority",
            new=AsyncMock(return_value=-1),
        ):
            asyncio.run(scheduler.schedule_host(host))
        assert host.priority == -1
        expected = datetime.now(timezone.utc) + timedelta(days=7)
        delta = abs(host.next_scan - expected)
        assert delta < timedelta(seconds=5)

    def test_schedule_host_next_scan_is_timezone_aware(self, scheduler):
        """host.next_scan is a timezone-aware datetime (UTC)."""
        host = self._make_host(up=True)
        with patch(
            "cyhy_commander.scheduler._calculate_priority",
            new=AsyncMock(return_value=-1),
        ):
            asyncio.run(scheduler.schedule_host(host))
        assert host.next_scan.tzinfo is not None


# ---------------------------------------------------------------------------
# _calculate_priority — unit tests with mocked VulnScanDoc queries
# ---------------------------------------------------------------------------


class TestCalculatePriority:
    """_calculate_priority returns the correct priority for each host state."""

    def _make_host(self, up: bool = True):
        """Create a minimal mock HostDoc."""
        host = MagicMock()
        host.ip = "10.0.0.1"
        host.state = MagicMock()
        host.state.up = up
        return host

    def _make_vuln_scan_doc_mock(self, kev_count: int, max_severity):
        """Return a mock VulnScanDoc class that returns controlled query results.

        The mock replaces the entire VulnScanDoc class in the scheduler module
        so that class-attribute access (VulnScanDoc.ip, VulnScanDoc.latest,
        VulnScanDoc.kev, VulnScanDoc.severity) works without Beanie being
        initialized, and VulnScanDoc.find() returns the expected results.
        """
        # First find() call returns kev_count; second returns max_severity
        kev_find = MagicMock()
        kev_find.count = AsyncMock(return_value=kev_count)

        severity_find = MagicMock()
        severity_find.max = AsyncMock(return_value=max_severity)

        mock_class = MagicMock()
        # Class attribute access (VulnScanDoc.ip, etc.) returns a MagicMock
        # that supports == comparison (MagicMock.__eq__ returns a MagicMock)
        mock_class.find = MagicMock(side_effect=[kev_find, severity_find])
        return mock_class

    def test_down_host_returns_priority_1(self):
        """Down host (state.up=False) → priority 1."""
        host = self._make_host(up=False)
        result = asyncio.run(_calculate_priority(host))
        assert result == 1

    def test_kev_vulnerability_returns_minus_16(self):
        """Host with KEV vulnerability → priority -16."""
        host = self._make_host(up=True)
        mock_vuln = self._make_vuln_scan_doc_mock(kev_count=1, max_severity=4)

        with patch("cyhy_commander.scheduler.VulnScanDoc", mock_vuln):
            result = asyncio.run(_calculate_priority(host))

        assert result == -16

    def test_no_kev_severity_4_returns_minus_16(self):
        """Host with no KEV but severity 4 → priority -16."""
        host = self._make_host(up=True)
        mock_vuln = self._make_vuln_scan_doc_mock(kev_count=0, max_severity=4)

        with patch("cyhy_commander.scheduler.VulnScanDoc", mock_vuln):
            result = asyncio.run(_calculate_priority(host))

        assert result == -16

    def test_no_kev_severity_3_returns_minus_8(self):
        """Host with no KEV but severity 3 → priority -8."""
        host = self._make_host(up=True)
        mock_vuln = self._make_vuln_scan_doc_mock(kev_count=0, max_severity=3)

        with patch("cyhy_commander.scheduler.VulnScanDoc", mock_vuln):
            result = asyncio.run(_calculate_priority(host))

        assert result == -8

    def test_no_kev_severity_2_returns_minus_4(self):
        """Host with no KEV but severity 2 → priority -4."""
        host = self._make_host(up=True)
        mock_vuln = self._make_vuln_scan_doc_mock(kev_count=0, max_severity=2)

        with patch("cyhy_commander.scheduler.VulnScanDoc", mock_vuln):
            result = asyncio.run(_calculate_priority(host))

        assert result == -4

    def test_no_kev_severity_1_returns_minus_1(self):
        """Host with no KEV and only severity 1 → priority -1."""
        host = self._make_host(up=True)
        mock_vuln = self._make_vuln_scan_doc_mock(kev_count=0, max_severity=1)

        with patch("cyhy_commander.scheduler.VulnScanDoc", mock_vuln):
            result = asyncio.run(_calculate_priority(host))

        assert result == -1

    def test_no_kev_no_vulns_returns_minus_1(self):
        """Host with no KEV and no vulnerabilities (max severity = None) → priority -1."""
        host = self._make_host(up=True)
        # max() returns None when no documents match; the scheduler uses `or 0`
        mock_vuln = self._make_vuln_scan_doc_mock(kev_count=0, max_severity=None)

        with patch("cyhy_commander.scheduler.VulnScanDoc", mock_vuln):
            result = asyncio.run(_calculate_priority(host))

        assert result == -1

    def test_no_kev_severity_0_returns_minus_1(self):
        """Host with no KEV and severity 0 (no real vulns) → priority -1."""
        host = self._make_host(up=True)
        mock_vuln = self._make_vuln_scan_doc_mock(kev_count=0, max_severity=0)

        with patch("cyhy_commander.scheduler.VulnScanDoc", mock_vuln):
            result = asyncio.run(_calculate_priority(host))

        assert result == -1
