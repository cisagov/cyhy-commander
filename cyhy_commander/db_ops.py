"""Database orchestration layer for CyHy Commander.

This module provides high-level async database operations that coordinate
host state transitions, scan scheduling, and tally updates.  It replaces
the commander-relevant methods from cyhy-core's CHDatabase class.

Requirements: FR-8.4, FR-3.1, FR-3.4, AC-5.4
"""

# Standard Python Libraries
import logging
from datetime import datetime, timezone
from ipaddress import IPv4Address

# Third-party libraries
from beanie.operators import In, Set
from cyhy_db.models import HostDoc, RequestDoc, TallyDoc, SystemControlDoc
from cyhy_db.models.enum import (
    ControlAction,
    ControlTarget,
    Scheduler,
    Stage,
    Status,
    ScanType,
)

from .host_state_manager import DefaultHostStateManager
from .scheduler import DefaultScheduler
from cyhy_logging import CYHY_ROOT_LOGGER

logger = logging.getLogger(CYHY_ROOT_LOGGER + ".commander.db_ops")

# The default owner for "ownerless" hosts (hosts whose IP is not claimed by
# any enrolled CyHy entity).
DEFAULT_OWNER: str = "FEDERAL"

_state_manager = DefaultHostStateManager()
_scheduler = DefaultScheduler()


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# fetch_ready_hosts
# ---------------------------------------------------------------------------


async def fetch_ready_hosts(
    count: int,
    stage: Stage,
    owner: str | None = None,
) -> list[HostDoc]:
    """Fetch up to *count* READY hosts for *stage* and atomically mark them RUNNING.

    Uses a sequential find-then-update pattern to prevent double-assignment.
    Hosts are selected in priority order (lowest priority value first, then
    by the random tiebreaker field ``r``).

    Args:
        count: Maximum number of hosts to fetch.
        stage: The scan stage to fetch hosts for.
        owner: If provided, restrict results to hosts owned by this org.

    Returns:
        A list of HostDoc objects whose status has been set to RUNNING and
        saved to the database.
    """
    query_filters = [
        HostDoc.status == Status.READY,
        HostDoc.stage == stage,
    ]
    if owner is not None:
        query_filters.append(HostDoc.owner == owner)

    hosts: list[HostDoc] = (
        await HostDoc.find(*query_filters)
        .sort(
            [
                (HostDoc.priority, 1),  # ascending: most urgent first
                (HostDoc.r, 1),         # random tiebreaker
            ]
        )
        .limit(count)
        .to_list()
    )

    if not hosts:
        return []

    # Atomically mark all fetched hosts as RUNNING.
    ip_list = [host.ip for host in hosts]
    await HostDoc.find(In(HostDoc.ip, ip_list)).update(
        Set({HostDoc.status: Status.RUNNING})
    )

    # Refresh the in-memory objects to reflect the saved status.
    for host in hosts:
        host.status = Status.RUNNING

    logger.debug(
        "Fetched %d READY hosts for stage %s (owner=%s)",
        len(hosts),
        stage,
        owner,
    )
    return hosts


# ---------------------------------------------------------------------------
# balance_ready_hosts
# ---------------------------------------------------------------------------


def _is_within_scan_window(window, now: datetime) -> bool:
    """Return True if *now* falls within the given scan *window*.

    A ``Window`` has three fields:
      - ``day``: the starting day of the week (DayOfWeek StrEnum, Monday=0)
      - ``start``: the time-of-day the window opens (datetime.time)
      - ``duration``: how many hours the window lasts (0–168)

    A duration of 168 means the window is always open.

    Args:
        window: A ``cyhy_db.models.request_doc.Window`` instance.
        now: The current UTC datetime.

    Returns:
        True if *now* is within the window.
    """
    if window.duration == 0:
        return False
    if window.duration >= 168:
        return True

    # Map DayOfWeek string to Python weekday integer (Monday=0 … Sunday=6).
    _DOW_MAP = {
        "monday": 0,
        "tuesday": 1,
        "wednesday": 2,
        "thursday": 3,
        "friday": 4,
        "saturday": 5,
        "sunday": 6,
    }
    window_start_dow = _DOW_MAP.get(str(window.day).lower(), 6)

    # Compute the absolute minute-of-week for the window start.
    window_start_minutes = (
        window_start_dow * 24 * 60
        + window.start.hour * 60
        + window.start.minute
    )
    window_end_minutes = window_start_minutes + window.duration * 60

    # Compute the current minute-of-week.
    now_minutes = now.weekday() * 24 * 60 + now.hour * 60 + now.minute

    # Handle wrap-around at the end of the week (168 * 60 = 10080 minutes).
    total_week_minutes = 7 * 24 * 60
    if window_end_minutes > total_week_minutes:
        # Window wraps around midnight Sunday → Monday.
        return now_minutes >= window_start_minutes or now_minutes < (
            window_end_minutes % total_week_minutes
        )

    return window_start_minutes <= now_minutes < window_end_minutes


async def balance_ready_hosts() -> None:
    """Ensure the correct number of hosts are in READY state.

    For each active (non-retired) organization, this function:
      1. Checks whether the current time falls within any of the org's scan
         windows.  If not, no hosts are moved to READY for that org.
      2. Reads the org's concurrent scan limit from ``RequestDoc.scan_limits``
         (for ``ScanType.CYHY``).  Defaults to 0 (unlimited) if not set.
      3. Counts how many hosts are currently RUNNING or READY for that org.
      4. Moves WAITING hosts to READY up to the configured limit.

    Hosts are selected in priority order (lowest value = highest urgency).
    """
    now = _utcnow()

    # Fetch all active (non-retired) request documents.
    requests: list[RequestDoc] = await RequestDoc.find(
        RequestDoc.retired == False  # noqa: E712
    ).to_list()

    for request in requests:
        owner = request.id

        # Check scan windows — skip this org if outside all windows.
        windows = request.windows or []
        if windows and not any(_is_within_scan_window(w, now) for w in windows):
            logger.debug("Owner %s is outside its scan window; skipping.", owner)
            continue

        # Determine the concurrent scan limit for CYHY scans.
        limit: int = 0  # 0 = unlimited
        for scan_limit in request.scan_limits:
            if scan_limit.scan_type == ScanType.CYHY:
                limit = scan_limit.concurrent
                break

        if limit == 0:
            # No limit configured — move all WAITING hosts to READY.
            waiting_hosts: list[HostDoc] = await HostDoc.find(
                HostDoc.owner == owner,
                HostDoc.status == Status.WAITING,
            ).to_list()
        else:
            # Count currently active (RUNNING + READY) hosts for this org.
            active_count: int = await HostDoc.find(
                HostDoc.owner == owner,
                In(HostDoc.status, [Status.RUNNING, Status.READY]),
            ).count()

            slots_available = limit - active_count
            if slots_available <= 0:
                logger.debug(
                    "Owner %s has reached its concurrent scan limit (%d); skipping.",
                    owner,
                    limit,
                )
                continue

            waiting_hosts = (
                await HostDoc.find(
                    HostDoc.owner == owner,
                    HostDoc.status == Status.WAITING,
                )
                .sort([(HostDoc.priority, 1), (HostDoc.r, 1)])
                .limit(slots_available)
                .to_list()
            )

        if not waiting_hosts:
            continue

        ip_list = [h.ip for h in waiting_hosts]
        await HostDoc.find(In(HostDoc.ip, ip_list)).update(
            Set({HostDoc.status: Status.READY})
        )
        logger.debug(
            "Moved %d WAITING hosts to READY for owner %s.",
            len(waiting_hosts),
            owner,
        )


# ---------------------------------------------------------------------------
# check_host_next_scans
# ---------------------------------------------------------------------------


async def check_host_next_scans() -> None:
    """Move hosts whose next_scan time has passed from DONE back to WAITING.

    Hosts that have completed their full scan cycle (status=DONE) are
    rescheduled by setting their next_scan time when they finish.  This
    function checks for DONE hosts whose next_scan has elapsed and moves
    them back into the scan queue:

      - Up hosts  (state.up=True)  → stage=PORTSCAN,  status=WAITING
      - Down hosts (state.up=False) → stage=NETSCAN1, status=WAITING
    """
    now = _utcnow()

    done_hosts: list[HostDoc] = await HostDoc.find(
        HostDoc.status == Status.DONE,
        HostDoc.next_scan <= now,
    ).to_list()

    if not done_hosts:
        return

    for host in done_hosts:
        new_stage = Stage.PORTSCAN if host.state.up else Stage.NETSCAN1
        host.stage = new_stage
        host.status = Status.WAITING
        host.next_scan = None
        await host.save()

    logger.debug(
        "Moved %d DONE hosts back to WAITING (next_scan elapsed).",
        len(done_hosts),
    )


# ---------------------------------------------------------------------------
# transition_host
# ---------------------------------------------------------------------------


async def transition_host(
    ip: str,
    up: bool,
    reason: str,
    has_open_ports: bool = False,
    was_failure: bool = False,
) -> None:
    """Apply the host state machine, update timestamps, schedule, and tally.

    This is the primary entry point called by job sinks after processing
    scan results.  It:

      1. Loads the HostDoc for *ip*.
      2. Applies ``DefaultHostStateManager.new_state()`` to determine the
         next (stage, status).
      3. Updates ``host.state`` (up/reason) and ``host.latest_scan`` for the
         finished stage.
      4. If the host reaches DONE, calls ``DefaultScheduler.schedule_host()``
         to set ``host.priority`` and ``host.next_scan``.
      5. Saves the updated HostDoc.
      6. Updates the TallyDoc for the host's owner.

    Args:
        ip: The IPv4 address string of the host.
        up: Whether the host was found to be up during this scan.
        reason: A short string describing why the host is up or down
            (e.g. ``"syn-ack"``, ``"no-response"``).
        has_open_ports: Whether the host has open ports (PORTSCAN only).
        was_failure: Whether the scan failed; causes revert to WAITING.
    """
    ip_addr = IPv4Address(ip)
    host: HostDoc | None = await HostDoc.find_one(HostDoc.ip == ip_addr)
    if host is None:
        logger.warning("transition_host: no HostDoc found for IP %s; skipping.", ip)
        return

    old_stage = host.stage
    old_status = host.status

    result = _state_manager.new_state(
        stage=host.stage,
        status=host.status,
        up=up,
        has_open_ports=has_open_ports,
        was_failure=was_failure,
    )

    if not result.was_changed and result.finished_stage is None:
        # Nothing to do (terminal DONE or unexpected state).
        logger.debug(
            "transition_host: no state change for %s (stage=%s, status=%s).",
            ip,
            host.stage,
            host.status,
        )
        return

    # Update host state fields.
    host.state = host.state.__class__(up=up, reason=reason)
    host.stage = result.new_stage
    host.status = result.new_status

    # Record the latest_scan timestamp for the finished stage.
    if result.finished_stage is not None:
        host.latest_scan[result.finished_stage] = _utcnow()

    # When the host reaches DONE, schedule its next scan.
    if result.new_status == Status.DONE:
        await _scheduler.schedule_host(host)

    await host.save()

    logger.debug(
        "Transitioned host %s: %s/%s → %s/%s (finished_stage=%s)",
        ip,
        old_stage,
        old_status,
        result.new_stage,
        result.new_status,
        result.finished_stage,
    )

    # Update the tally document for this host's owner.
    await _update_tally(
        owner=host.owner,
        old_stage=old_stage,
        old_status=old_status,
        new_stage=result.new_stage,
        new_status=result.new_status,
    )


async def _update_tally(
    owner: str,
    old_stage: Stage,
    old_status: Status,
    new_stage: Stage,
    new_status: Status,
) -> None:
    """Increment/decrement the TallyDoc counters for *owner*.

    Decrements the counter for (old_stage, old_status) and increments the
    counter for (new_stage, new_status).  Creates the TallyDoc if it does
    not yet exist.

    Args:
        owner: The org ID whose tally to update.
        old_stage: The stage before the transition.
        old_status: The status before the transition.
        new_stage: The stage after the transition.
        new_status: The status after the transition.
    """
    tally: TallyDoc | None = await TallyDoc.get(owner)
    if tally is None:
        tally = TallyDoc(id=owner)

    def _get_stage_counts(tally: TallyDoc, stage: Stage):
        """Return the StatusCounts object for *stage* on *tally*."""
        return getattr(tally.counts, stage.value, None)

    old_counts = _get_stage_counts(tally, old_stage)
    if old_counts is not None:
        current_val = getattr(old_counts, old_status.value, 0)
        setattr(old_counts, old_status.value, max(0, current_val - 1))

    new_counts = _get_stage_counts(tally, new_stage)
    if new_counts is not None:
        current_val = getattr(new_counts, new_status.value, 0)
        setattr(new_counts, new_status.value, current_val + 1)

    await tally.save()


# ---------------------------------------------------------------------------
# should_commander_pause
# ---------------------------------------------------------------------------


async def should_commander_pause() -> bool:
    """Check the SystemControlDoc for a PAUSE signal targeting COMMANDER.

    Returns:
        True if a PAUSE control document exists for the COMMANDER target,
        False otherwise.
    """
    doc = await SystemControlDoc.find_one(
        SystemControlDoc.action == ControlAction.PAUSE,
        SystemControlDoc.target == ControlTarget.COMMANDER,
    )
    return doc is not None


# ---------------------------------------------------------------------------
# setup_default_owner
# ---------------------------------------------------------------------------


async def setup_default_owner(scheduler: str = "PERSISTENT1") -> None:
    """Ensure a RequestDoc exists for the DEFAULT_OWNER.

    The default owner (``FEDERAL``) owns all "ownerless" HostDocs — hosts
    whose IP is not claimed by any enrolled CyHy entity.  This function
    checks whether a RequestDoc for the default owner already exists and
    creates one with sensible defaults if it does not.

    Args:
        scheduler: The scheduler value to assign to the default owner's
            RequestDoc.  Defaults to ``"PERSISTENT1"``.
    """
    existing: RequestDoc | None = await RequestDoc.get(DEFAULT_OWNER)
    if existing is not None:
        logger.debug(
            "RequestDoc for default owner '%s' already exists; skipping creation.",
            DEFAULT_OWNER,
        )
        return

    # Resolve the Scheduler enum value.
    try:
        scheduler_enum = Scheduler(scheduler)
    except ValueError:
        logger.warning(
            "Unknown scheduler value '%s'; falling back to PERSISTENT1.",
            scheduler,
        )
        scheduler_enum = Scheduler.PERSISTENT1

    # Import Agency/Contact models locally to avoid polluting the module
    # namespace — they are only needed here.
    from cyhy_db.models.request_doc import Agency  # noqa: PLC0415

    default_request = RequestDoc(
        id=DEFAULT_OWNER,
        agency=Agency(
            name="Federal (default owner)",
            acronym=DEFAULT_OWNER,
        ),
        scheduler=scheduler_enum,
        scan_types=[ScanType.CYHY],
        retired=False,
    )
    await default_request.save()
    logger.info(
        "Created default RequestDoc for owner '%s' with scheduler '%s'.",
        DEFAULT_OWNER,
        scheduler,
    )
