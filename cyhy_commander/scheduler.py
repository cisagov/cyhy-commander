"""Host scan scheduler for CyHy Commander.

This module provides the DefaultScheduler class, which maps host priority
values to scan intervals and assigns the next scan time for a host based
on its current vulnerability state.

Ported from cyhy-core/cyhy/db/scheduler.py with zero dependency on
cyhy.db, cyhy.core, or cyhy.util.
"""

# Standard Python Libraries
import logging
from datetime import datetime, timedelta, timezone

# Third-party libraries
import numpy as np
from cyhy_db.models import HostDoc, VulnScanDoc
from cyhy_logging import CYHY_ROOT_LOGGER

logger = logging.getLogger(CYHY_ROOT_LOGGER + ".commander.scheduler")

# Anchor points for priority-to-interval interpolation (design section 5.2).
# Each tuple is (priority, interval_in_hours).
#
# Priority | Scan Interval | Condition
# ---------|--------------|----------
#  1       | 90 days      | Host is down
#  0       | 14 days      | —
# -1       | 7 days       | Host is up, no vulnerabilities
# -4       | 4 days       | Severity 2 vulnerability
# -8       | 24 hours     | Severity 3 vulnerability
# -16      | 12 hours     | Severity 4 or KEV vulnerability
_PRIORITY_ANCHORS = np.array([1, 0, -1, -4, -8, -16], dtype=float)
_HOURS_ANCHORS = np.array(
    [
        90 * 24,  # 90 days  → 2160 hours
        14 * 24,  # 14 days  → 336 hours
        7 * 24,   # 7 days   → 168 hours
        4 * 24,   # 4 days   → 96 hours
        24,       # 24 hours
        12,       # 12 hours
    ],
    dtype=float,
)

# numpy.interp requires the x-coordinates to be increasing, but our priority
# anchors decrease from 1 to -16.  We flip both arrays so that x is
# monotonically increasing (from -16 to 1) and y follows accordingly.
_INTERP_X = _PRIORITY_ANCHORS[::-1]   # [-16, -8, -4, -1, 0, 1]
_INTERP_Y = _HOURS_ANCHORS[::-1]      # [12, 24, 96, 168, 336, 2160]


class DefaultScheduler:
    """Maps host priority values to scan intervals and schedules next scans.

    Priority range: -16 (highest urgency, shortest interval) to 1 (lowest
    urgency, longest interval).  Intermediate values are linearly interpolated
    using numpy.interp over the anchor points defined in design section 5.2.
    """

    def timedelta_for_priority(self, priority: int) -> timedelta:
        """Return the scan interval for a given priority value.

        Lower priority number = higher urgency = shorter interval.
        Priority range: -16 (highest) to 1 (lowest).

        Values outside the range [-16, 1] are clamped to the nearest anchor
        by numpy.interp's default left/right boundary behaviour.

        Args:
            priority: An integer priority value.

        Returns:
            A timedelta representing the scan interval for that priority.
        """
        hours = float(np.interp(float(priority), _INTERP_X, _INTERP_Y))
        return timedelta(hours=hours)

    async def schedule_host(self, host: HostDoc) -> None:
        """Set host.priority and host.next_scan based on current vulnerability state.

        Queries VulnScanDoc for max severity and KEV count, computes the
        priority, then sets:
          - host.priority  = computed priority integer
          - host.next_scan = utcnow() + timedelta_for_priority(host.priority)

        Does NOT save the host — the caller is responsible for host.save().

        Args:
            host: The HostDoc to schedule.  Modified in place.
        """
        priority = await _calculate_priority(host)
        host.priority = priority
        host.next_scan = datetime.now(timezone.utc) + self.timedelta_for_priority(
            priority
        )
        logger.debug(
            "Scheduled host %s: priority=%d, next_scan=%s",
            host.ip,
            priority,
            host.next_scan,
        )


async def _calculate_priority(host: HostDoc) -> int:
    """Compute the scheduling priority for a host.

    Priority is determined by the host's current vulnerability state:
      - Down host                        →  1  (90 days)
      - KEV vulnerability present        → -16 (12 hours)
      - Severity 4 vulnerability         → -16 (12 hours)
      - Severity 3 vulnerability         →  -8 (24 hours)
      - Severity 2 vulnerability         →  -4 (4 days)
      - Severity 1 / no vulnerabilities  →  -1 (7 days)

    Args:
        host: The HostDoc whose priority is being calculated.

    Returns:
        An integer priority value in the range [-16, 1].
    """
    if not host.state.up:
        return 1  # down host: 90 days

    # Check max severity across all latest vuln scans for this host.
    # Use sort+limit instead of aggregation for mongomock compatibility.
    top_vuln = await VulnScanDoc.find(
        VulnScanDoc.ip == host.ip,
        VulnScanDoc.latest == True,  # noqa: E712
    ).sort([("severity", -1)]).limit(1).first_or_none()

    max_severity = top_vuln.severity if top_vuln is not None else 0

    severity_to_priority = {4: -16, 3: -8, 2: -4, 1: -1}
    return severity_to_priority.get(int(max_severity), -1)
