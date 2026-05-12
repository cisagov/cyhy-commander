"""Integration tests for db_ops against a real MongoDB instance.

These tests exercise fetch_ready_hosts, balance_ready_hosts,
check_host_next_scans, and transition_host against a live MongoDB
connection.  They are skipped automatically unless the environment
variable CYHY_TEST_MONGODB_URI is set.

Requirements: AC-8.2, AC-8.3
"""

# Standard Python Libraries
import asyncio
import os
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address

# Third-party libraries
import beanie
import pytest
from cyhy_db import initialize_db
from cyhy_db.models import (
    CVEDoc,
    HostDoc,
    HostScanDoc,
    KEVDoc,
    NotificationDoc,
    PlaceDoc,
    PortScanDoc,
    ReportDoc,
    RequestDoc,
    ScanDoc,
    SnapshotDoc,
    SystemControlDoc,
    TallyDoc,
    TicketDoc,
    VulnScanDoc,
)
from cyhy_db.models.enum import DayOfWeek, ScanType, Stage, Status
from cyhy_db.models.request_doc import Agency, ScanLimit, Window

import cyhy_commander.db_ops as db_ops

# ---------------------------------------------------------------------------
# Skip marker — all tests in this module are skipped unless the env var is set
# ---------------------------------------------------------------------------

MONGODB_URI_ENV = "CYHY_TEST_MONGODB_URI"
MONGODB_URI = os.environ.get(MONGODB_URI_ENV)

pytestmark = pytest.mark.skipif(
    MONGODB_URI is None,
    reason=f"{MONGODB_URI_ENV} environment variable is not set",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEST_DB_NAME = "cyhy_integration_test"
OWNER = "INTEGRATION_TEST_ORG"

_ALL_DOCUMENT_MODELS = [
    CVEDoc,
    HostDoc,
    HostScanDoc,
    KEVDoc,
    NotificationDoc,
    PlaceDoc,
    PortScanDoc,
    ReportDoc,
    RequestDoc,
    ScanDoc,
    SnapshotDoc,
    SystemControlDoc,
    TallyDoc,
    TicketDoc,
    VulnScanDoc,
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_host(
    ip: str,
    stage: Stage = Stage.NETSCAN1,
    status: Status = Status.READY,
    owner: str = OWNER,
    up: bool = False,
    next_scan: datetime | None = None,
    priority: int = 0,
) -> HostDoc:
    """Create a HostDoc with sensible defaults for testing."""
    host = HostDoc(
        ip=ip,
        owner=owner,
        stage=stage,
        status=status,
        priority=priority,
    )
    host.state = host.state.__class__(up=up, reason="new")
    if next_scan is not None:
        host.next_scan = next_scan
    return host


def _make_request(
    owner: str = OWNER,
    windows: list | None = None,
    scan_limits: list | None = None,
    retired: bool = False,
) -> RequestDoc:
    """Create a RequestDoc with sensible defaults for testing."""
    return RequestDoc(
        id=owner,
        agency=Agency(name=f"Test Org {owner}", acronym=owner),
        scan_types=[ScanType.CYHY],
        windows=windows or [],
        scan_limits=scan_limits or [],
        retired=retired,
    )


async def _get_host(ip: str) -> HostDoc | None:
    return await HostDoc.find_one(HostDoc.ip == IPv4Address(ip))


async def _cleanup_test_data() -> None:
    """Remove all documents created by integration tests."""
    await HostDoc.find(HostDoc.owner == OWNER).delete()
    await RequestDoc.find(RequestDoc.id == OWNER).delete()
    await TallyDoc.find(TallyDoc.id == OWNER).delete()


# ---------------------------------------------------------------------------
# Module-level fixture: initialise Beanie once for the whole test session
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def real_db():
    """Initialise Beanie against the real MongoDB instance.

    Runs once per module.  All tests share the same connection.
    Each test is responsible for cleaning up its own data via
    _cleanup_test_data().
    """
    if MONGODB_URI is None:
        pytest.skip(f"{MONGODB_URI_ENV} is not set")

    async def _init():
        await initialize_db(MONGODB_URI, TEST_DB_NAME)

    asyncio.run(_init())
    yield


# ---------------------------------------------------------------------------
# fetch_ready_hosts
# ---------------------------------------------------------------------------


class TestFetchReadyHostsIntegration:
    """fetch_ready_hosts against a real MongoDB instance."""

    def setup_method(self):
        asyncio.run(_cleanup_test_data())

    def test_returns_empty_list_when_no_hosts(self):
        """No READY hosts in DB → empty list returned."""

        async def _run():
            result = await db_ops.fetch_ready_hosts(count=10, stage=Stage.NETSCAN1)
            assert result == []

        asyncio.run(_run())

    def test_marks_fetched_hosts_as_running(self):
        """Fetched hosts are atomically marked RUNNING in the real DB."""

        async def _run():
            host = _make_host("10.100.0.1", stage=Stage.NETSCAN1, status=Status.READY)
            await host.save()

            result = await db_ops.fetch_ready_hosts(count=5, stage=Stage.NETSCAN1)
            assert len(result) == 1
            assert result[0].status == Status.RUNNING

            # Verify the DB was updated
            db_host = await _get_host("10.100.0.1")
            assert db_host is not None
            assert db_host.status == Status.RUNNING

        asyncio.run(_run())

    def test_respects_count_limit(self):
        """Returns at most `count` hosts even when more are available."""

        async def _run():
            for i in range(5):
                host = _make_host(
                    f"10.100.1.{i + 1}", stage=Stage.NETSCAN1, status=Status.READY
                )
                await host.save()

            result = await db_ops.fetch_ready_hosts(count=3, stage=Stage.NETSCAN1)
            assert len(result) == 3
            for h in result:
                assert h.status == Status.RUNNING

        asyncio.run(_run())

    def test_filters_by_stage(self):
        """Only hosts in the requested stage are returned."""

        async def _run():
            netscan1 = _make_host(
                "10.100.2.1", stage=Stage.NETSCAN1, status=Status.READY
            )
            portscan = _make_host(
                "10.100.2.2", stage=Stage.PORTSCAN, status=Status.READY
            )
            await netscan1.save()
            await portscan.save()

            result = await db_ops.fetch_ready_hosts(count=10, stage=Stage.NETSCAN1)
            assert len(result) == 1
            assert str(result[0].ip) == "10.100.2.1"

            # PORTSCAN host should still be READY
            db_portscan = await _get_host("10.100.2.2")
            assert db_portscan.status == Status.READY

        asyncio.run(_run())

    def test_filters_by_owner(self):
        """When owner is specified, only hosts for that owner are returned."""

        async def _run():
            org_a = _make_host(
                "10.100.3.1",
                stage=Stage.NETSCAN1,
                status=Status.READY,
                owner=OWNER,
            )
            org_b = _make_host(
                "10.100.3.2",
                stage=Stage.NETSCAN1,
                status=Status.READY,
                owner="OTHER_ORG",
            )
            await org_a.save()
            await org_b.save()

            result = await db_ops.fetch_ready_hosts(
                count=10, stage=Stage.NETSCAN1, owner=OWNER
            )
            assert len(result) == 1
            assert result[0].owner == OWNER

            # Clean up the other org's host
            await HostDoc.find(HostDoc.owner == "OTHER_ORG").delete()

        asyncio.run(_run())

    def test_only_fetches_ready_status(self):
        """WAITING and RUNNING hosts are not fetched."""

        async def _run():
            ready = _make_host(
                "10.100.4.1", stage=Stage.NETSCAN1, status=Status.READY
            )
            waiting = _make_host(
                "10.100.4.2", stage=Stage.NETSCAN1, status=Status.WAITING
            )
            running = _make_host(
                "10.100.4.3", stage=Stage.NETSCAN1, status=Status.RUNNING
            )
            for h in [ready, waiting, running]:
                await h.save()

            result = await db_ops.fetch_ready_hosts(count=10, stage=Stage.NETSCAN1)
            assert len(result) == 1
            assert str(result[0].ip) == "10.100.4.1"

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# balance_ready_hosts
# ---------------------------------------------------------------------------


class TestBalanceReadyHostsIntegration:
    """balance_ready_hosts against a real MongoDB instance."""

    def setup_method(self):
        asyncio.run(_cleanup_test_data())

    def test_moves_waiting_hosts_to_ready_within_open_window(self):
        """WAITING hosts are moved to READY when the org is within its scan window."""

        async def _run():
            # Create a request with an always-open window (duration=168)
            request = _make_request(
                owner=OWNER,
                windows=[Window(duration=168)],
            )
            await request.save()

            # Create WAITING hosts
            for i in range(3):
                host = _make_host(
                    f"10.101.0.{i + 1}",
                    stage=Stage.NETSCAN1,
                    status=Status.WAITING,
                )
                await host.save()

            await db_ops.balance_ready_hosts()

            # All WAITING hosts should now be READY
            hosts = await HostDoc.find(HostDoc.owner == OWNER).to_list()
            for h in hosts:
                assert h.status == Status.READY

        asyncio.run(_run())

    def test_respects_concurrent_scan_limit(self):
        """balance_ready_hosts respects the concurrent scan limit from RequestDoc."""

        async def _run():
            limit = 2
            request = _make_request(
                owner=OWNER,
                windows=[Window(duration=168)],
                scan_limits=[ScanLimit(scan_type=ScanType.CYHY, concurrent=limit)],
            )
            await request.save()

            # Create 5 WAITING hosts
            for i in range(5):
                host = _make_host(
                    f"10.101.1.{i + 1}",
                    stage=Stage.NETSCAN1,
                    status=Status.WAITING,
                )
                await host.save()

            await db_ops.balance_ready_hosts()

            ready_count = await HostDoc.find(
                HostDoc.owner == OWNER,
                HostDoc.status == Status.READY,
            ).count()
            # Only `limit` hosts should be READY
            assert ready_count == limit

        asyncio.run(_run())

    def test_skips_org_outside_scan_window(self):
        """WAITING hosts are not moved to READY when the org is outside its window."""

        async def _run():
            # Create a request with a zero-duration window (always closed)
            request = _make_request(
                owner=OWNER,
                windows=[Window(duration=0)],
            )
            await request.save()

            host = _make_host(
                "10.101.2.1",
                stage=Stage.NETSCAN1,
                status=Status.WAITING,
            )
            await host.save()

            await db_ops.balance_ready_hosts()

            db_host = await _get_host("10.101.2.1")
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_skips_retired_org(self):
        """Retired organizations are not processed."""

        async def _run():
            request = _make_request(
                owner=OWNER,
                windows=[Window(duration=168)],
                retired=True,
            )
            await request.save()

            host = _make_host(
                "10.101.3.1",
                stage=Stage.NETSCAN1,
                status=Status.WAITING,
            )
            await host.save()

            await db_ops.balance_ready_hosts()

            db_host = await _get_host("10.101.3.1")
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_accounts_for_already_running_hosts_in_limit(self):
        """Already RUNNING hosts count against the concurrent limit."""

        async def _run():
            limit = 3
            request = _make_request(
                owner=OWNER,
                windows=[Window(duration=168)],
                scan_limits=[ScanLimit(scan_type=ScanType.CYHY, concurrent=limit)],
            )
            await request.save()

            # 2 already RUNNING
            for i in range(2):
                host = _make_host(
                    f"10.101.4.{i + 1}",
                    stage=Stage.NETSCAN1,
                    status=Status.RUNNING,
                )
                await host.save()

            # 3 WAITING
            for i in range(3):
                host = _make_host(
                    f"10.101.4.{i + 10}",
                    stage=Stage.NETSCAN1,
                    status=Status.WAITING,
                )
                await host.save()

            await db_ops.balance_ready_hosts()

            # Only 1 slot available (limit=3, 2 already running)
            ready_count = await HostDoc.find(
                HostDoc.owner == OWNER,
                HostDoc.status == Status.READY,
            ).count()
            assert ready_count == 1

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# check_host_next_scans
# ---------------------------------------------------------------------------


class TestCheckHostNextScansIntegration:
    """check_host_next_scans against a real MongoDB instance."""

    def setup_method(self):
        asyncio.run(_cleanup_test_data())

    def test_done_host_with_past_next_scan_becomes_waiting(self):
        """DONE host whose next_scan is in the past is moved to WAITING."""

        async def _run():
            past = _utcnow() - timedelta(hours=1)
            host = _make_host(
                "10.102.0.1",
                stage=Stage.NETSCAN1,
                status=Status.DONE,
                next_scan=past,
            )
            await host.save()

            await db_ops.check_host_next_scans()

            db_host = await _get_host("10.102.0.1")
            assert db_host.status == Status.WAITING
            assert db_host.next_scan is None

        asyncio.run(_run())

    def test_done_host_with_future_next_scan_stays_done(self):
        """DONE host whose next_scan is in the future is not moved."""

        async def _run():
            future = _utcnow() + timedelta(hours=1)
            host = _make_host(
                "10.102.1.1",
                stage=Stage.NETSCAN1,
                status=Status.DONE,
                next_scan=future,
            )
            await host.save()

            await db_ops.check_host_next_scans()

            db_host = await _get_host("10.102.1.1")
            assert db_host.status == Status.DONE

        asyncio.run(_run())

    def test_up_host_goes_to_portscan_stage(self):
        """DONE up host → stage=PORTSCAN, status=WAITING."""

        async def _run():
            past = _utcnow() - timedelta(hours=1)
            host = _make_host(
                "10.102.2.1",
                stage=Stage.NETSCAN1,
                status=Status.DONE,
                up=True,
                next_scan=past,
            )
            await host.save()

            await db_ops.check_host_next_scans()

            db_host = await _get_host("10.102.2.1")
            assert db_host.stage == Stage.PORTSCAN
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_down_host_goes_to_netscan1_stage(self):
        """DONE down host → stage=NETSCAN1, status=WAITING."""

        async def _run():
            past = _utcnow() - timedelta(hours=1)
            host = _make_host(
                "10.102.3.1",
                stage=Stage.NETSCAN2,
                status=Status.DONE,
                up=False,
                next_scan=past,
            )
            await host.save()

            await db_ops.check_host_next_scans()

            db_host = await _get_host("10.102.3.1")
            assert db_host.stage == Stage.NETSCAN1
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_multiple_done_hosts_all_transitioned(self):
        """Multiple DONE hosts with elapsed next_scan are all moved to WAITING."""

        async def _run():
            past = _utcnow() - timedelta(hours=1)
            for i in range(4):
                host = _make_host(
                    f"10.102.4.{i + 1}",
                    stage=Stage.NETSCAN1,
                    status=Status.DONE,
                    next_scan=past,
                )
                await host.save()

            await db_ops.check_host_next_scans()

            hosts = await HostDoc.find(HostDoc.owner == OWNER).to_list()
            assert len(hosts) == 4
            for h in hosts:
                assert h.status == Status.WAITING

        asyncio.run(_run())

    def test_non_done_hosts_not_affected(self):
        """WAITING and RUNNING hosts are not affected even if next_scan is past."""

        async def _run():
            past = _utcnow() - timedelta(hours=1)
            waiting = _make_host(
                "10.102.5.1",
                stage=Stage.NETSCAN1,
                status=Status.WAITING,
                next_scan=past,
            )
            running = _make_host(
                "10.102.5.2",
                stage=Stage.NETSCAN1,
                status=Status.RUNNING,
                next_scan=past,
            )
            for h in [waiting, running]:
                await h.save()

            await db_ops.check_host_next_scans()

            db_waiting = await _get_host("10.102.5.1")
            db_running = await _get_host("10.102.5.2")
            assert db_waiting.status == Status.WAITING
            assert db_running.status == Status.RUNNING

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# transition_host
# ---------------------------------------------------------------------------


class TestTransitionHostIntegration:
    """transition_host against a real MongoDB instance."""

    def setup_method(self):
        asyncio.run(_cleanup_test_data())

    def test_netscan1_running_up_transitions_to_portscan_waiting(self):
        """NETSCAN1/RUNNING + up=True → PORTSCAN/WAITING."""

        async def _run():
            host = _make_host(
                "10.103.0.1", stage=Stage.NETSCAN1, status=Status.RUNNING
            )
            await host.save()

            await db_ops.transition_host("10.103.0.1", up=True, reason="syn-ack")

            db_host = await _get_host("10.103.0.1")
            assert db_host.stage == Stage.PORTSCAN
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_netscan1_running_down_transitions_to_netscan2_waiting(self):
        """NETSCAN1/RUNNING + up=False → NETSCAN2/WAITING."""

        async def _run():
            host = _make_host(
                "10.103.1.1", stage=Stage.NETSCAN1, status=Status.RUNNING
            )
            await host.save()

            await db_ops.transition_host(
                "10.103.1.1", up=False, reason="no-response"
            )

            db_host = await _get_host("10.103.1.1")
            assert db_host.stage == Stage.NETSCAN2
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_netscan2_running_down_transitions_to_done(self):
        """NETSCAN2/RUNNING + up=False → NETSCAN2/DONE."""

        async def _run():
            host = _make_host(
                "10.103.2.1", stage=Stage.NETSCAN2, status=Status.RUNNING
            )
            await host.save()

            await db_ops.transition_host(
                "10.103.2.1", up=False, reason="no-response"
            )

            db_host = await _get_host("10.103.2.1")
            assert db_host.stage == Stage.NETSCAN2
            assert db_host.status == Status.DONE

        asyncio.run(_run())

    def test_portscan_running_with_open_ports_transitions_to_vulnscan(self):
        """PORTSCAN/RUNNING + has_open_ports=True → VULNSCAN/WAITING."""

        async def _run():
            host = _make_host(
                "10.103.3.1", stage=Stage.PORTSCAN, status=Status.RUNNING
            )
            await host.save()

            await db_ops.transition_host(
                "10.103.3.1", up=True, reason="open-port", has_open_ports=True
            )

            db_host = await _get_host("10.103.3.1")
            assert db_host.stage == Stage.VULNSCAN
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_portscan_running_no_open_ports_transitions_to_done(self):
        """PORTSCAN/RUNNING + has_open_ports=False → PORTSCAN/DONE."""

        async def _run():
            host = _make_host(
                "10.103.4.1", stage=Stage.PORTSCAN, status=Status.RUNNING
            )
            await host.save()

            await db_ops.transition_host(
                "10.103.4.1", up=False, reason="no-open", has_open_ports=False
            )

            db_host = await _get_host("10.103.4.1")
            assert db_host.stage == Stage.PORTSCAN
            assert db_host.status == Status.DONE

        asyncio.run(_run())

    def test_vulnscan_running_transitions_to_done(self):
        """VULNSCAN/RUNNING → VULNSCAN/DONE."""

        async def _run():
            host = _make_host(
                "10.103.5.1", stage=Stage.VULNSCAN, status=Status.RUNNING
            )
            await host.save()

            await db_ops.transition_host("10.103.5.1", up=True, reason="syn-ack")

            db_host = await _get_host("10.103.5.1")
            assert db_host.stage == Stage.VULNSCAN
            assert db_host.status == Status.DONE

        asyncio.run(_run())

    def test_failure_reverts_to_waiting(self):
        """was_failure=True reverts any RUNNING host to WAITING in the same stage."""

        async def _run():
            host = _make_host(
                "10.103.6.1", stage=Stage.PORTSCAN, status=Status.RUNNING
            )
            await host.save()

            await db_ops.transition_host(
                "10.103.6.1", up=False, reason="timeout", was_failure=True
            )

            db_host = await _get_host("10.103.6.1")
            assert db_host.stage == Stage.PORTSCAN
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_state_up_and_reason_updated(self):
        """transition_host updates host.state.up and host.state.reason."""

        async def _run():
            host = _make_host(
                "10.103.7.1",
                stage=Stage.NETSCAN1,
                status=Status.RUNNING,
                up=False,
            )
            await host.save()

            await db_ops.transition_host("10.103.7.1", up=True, reason="syn-ack")

            db_host = await _get_host("10.103.7.1")
            assert db_host.state.up is True
            assert db_host.state.reason == "syn-ack"

        asyncio.run(_run())

    def test_latest_scan_timestamp_set_for_finished_stage(self):
        """transition_host records a latest_scan timestamp for the finished stage."""

        async def _run():
            host = _make_host(
                "10.103.8.1", stage=Stage.NETSCAN1, status=Status.RUNNING
            )
            await host.save()

            await db_ops.transition_host("10.103.8.1", up=True, reason="syn-ack")

            db_host = await _get_host("10.103.8.1")
            assert Stage.NETSCAN1 in db_host.latest_scan
            ts = db_host.latest_scan[Stage.NETSCAN1]
            assert isinstance(ts, datetime)

        asyncio.run(_run())

    def test_done_host_gets_next_scan_scheduled(self):
        """When a host reaches DONE, next_scan is set by the scheduler."""

        async def _run():
            host = _make_host(
                "10.103.9.1", stage=Stage.NETSCAN2, status=Status.RUNNING
            )
            await host.save()

            await db_ops.transition_host(
                "10.103.9.1", up=False, reason="no-response"
            )

            db_host = await _get_host("10.103.9.1")
            assert db_host.status == Status.DONE
            assert db_host.next_scan is not None
            assert isinstance(db_host.next_scan, datetime)

        asyncio.run(_run())

    def test_tally_updated_after_transition(self):
        """transition_host creates or updates the TallyDoc for the host's owner."""

        async def _run():
            host = _make_host(
                "10.103.10.1",
                stage=Stage.NETSCAN1,
                status=Status.RUNNING,
                owner=OWNER,
            )
            await host.save()

            await db_ops.transition_host("10.103.10.1", up=True, reason="syn-ack")

            tally = await TallyDoc.get(OWNER)
            assert tally is not None

        asyncio.run(_run())

    def test_nonexistent_ip_does_not_raise(self):
        """transition_host with an IP not in the DB logs a warning and returns."""

        async def _run():
            # Should not raise — just logs a warning
            await db_ops.transition_host("1.2.3.4", up=True, reason="syn-ack")

        asyncio.run(_run())
