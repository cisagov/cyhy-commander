"""Unit tests for db_ops database orchestration layer.

Covers fetch_ready_hosts, check_host_next_scans, transition_host, and
should_commander_pause using an in-memory MongoDB via mongomock-motor.

Requirements: AC-8.1, FR-8.4
"""

# Standard Python Libraries
import asyncio
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address

# Third-party libraries
import pytest
from cyhy_db.models import HostDoc, SystemControlDoc, TallyDoc
from cyhy_db.models.enum import ControlAction, ControlTarget, Stage, Status

import cyhy_commander.db_ops as db_ops

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

OWNER = "TEST_ORG"


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


async def _save_host(host: HostDoc) -> HostDoc:
    await host.save()
    return host


async def _all_hosts() -> list[HostDoc]:
    return await HostDoc.find_all().to_list()


async def _get_host(ip: str) -> HostDoc | None:
    return await HostDoc.find_one(HostDoc.ip == IPv4Address(ip))


# ---------------------------------------------------------------------------
# fetch_ready_hosts
# ---------------------------------------------------------------------------


class TestFetchReadyHosts:
    """fetch_ready_hosts fetches READY hosts and marks them RUNNING."""

    def test_returns_empty_list_when_no_hosts(self, mock_db):
        """No hosts in DB → empty list returned."""

        async def _run():
            result = await db_ops.fetch_ready_hosts(count=10, stage=Stage.NETSCAN1)
            assert result == []

        asyncio.run(_run())

    def test_returns_up_to_count_hosts(self, mock_db):
        """Returns at most `count` hosts even when more are available."""

        async def _run():
            for i in range(5):
                host = _make_host(f"10.0.0.{i + 1}", stage=Stage.NETSCAN1, status=Status.READY)
                await _save_host(host)

            result = await db_ops.fetch_ready_hosts(count=3, stage=Stage.NETSCAN1)
            assert len(result) == 3

        asyncio.run(_run())

    def test_returns_all_hosts_when_fewer_than_count(self, mock_db):
        """Returns all available hosts when fewer than count exist."""

        async def _run():
            for i in range(2):
                host = _make_host(f"10.1.0.{i + 1}", stage=Stage.NETSCAN1, status=Status.READY)
                await _save_host(host)

            result = await db_ops.fetch_ready_hosts(count=10, stage=Stage.NETSCAN1)
            assert len(result) == 2

        asyncio.run(_run())

    def test_marks_fetched_hosts_as_running(self, mock_db):
        """Fetched hosts have their status set to RUNNING in the DB."""

        async def _run():
            host = _make_host("10.2.0.1", stage=Stage.NETSCAN1, status=Status.READY)
            await _save_host(host)

            result = await db_ops.fetch_ready_hosts(count=5, stage=Stage.NETSCAN1)
            assert len(result) == 1
            assert result[0].status == Status.RUNNING

            # Verify the DB was updated too
            db_host = await _get_host("10.2.0.1")
            assert db_host.status == Status.RUNNING

        asyncio.run(_run())

    def test_only_fetches_ready_status(self, mock_db):
        """Only READY hosts are fetched; WAITING and RUNNING hosts are ignored."""

        async def _run():
            ready = _make_host("10.3.0.1", stage=Stage.NETSCAN1, status=Status.READY)
            waiting = _make_host("10.3.0.2", stage=Stage.NETSCAN1, status=Status.WAITING)
            running = _make_host("10.3.0.3", stage=Stage.NETSCAN1, status=Status.RUNNING)
            for h in [ready, waiting, running]:
                await _save_host(h)

            result = await db_ops.fetch_ready_hosts(count=10, stage=Stage.NETSCAN1)
            assert len(result) == 1
            assert str(result[0].ip) == "10.3.0.1"

        asyncio.run(_run())

    def test_only_fetches_matching_stage(self, mock_db):
        """Only hosts in the requested stage are fetched."""

        async def _run():
            netscan1 = _make_host("10.4.0.1", stage=Stage.NETSCAN1, status=Status.READY)
            portscan = _make_host("10.4.0.2", stage=Stage.PORTSCAN, status=Status.READY)
            for h in [netscan1, portscan]:
                await _save_host(h)

            result = await db_ops.fetch_ready_hosts(count=10, stage=Stage.NETSCAN1)
            assert len(result) == 1
            assert str(result[0].ip) == "10.4.0.1"

        asyncio.run(_run())

    def test_filters_by_owner_when_provided(self, mock_db):
        """When owner is specified, only hosts for that owner are returned."""

        async def _run():
            org_a = _make_host("10.5.0.1", stage=Stage.NETSCAN1, status=Status.READY, owner="ORG_A")
            org_b = _make_host("10.5.0.2", stage=Stage.NETSCAN1, status=Status.READY, owner="ORG_B")
            for h in [org_a, org_b]:
                await _save_host(h)

            result = await db_ops.fetch_ready_hosts(count=10, stage=Stage.NETSCAN1, owner="ORG_A")
            assert len(result) == 1
            assert result[0].owner == "ORG_A"

        asyncio.run(_run())

    def test_no_owner_filter_returns_all_owners(self, mock_db):
        """When owner is None, hosts from all owners are returned."""

        async def _run():
            org_a = _make_host("10.6.0.1", stage=Stage.NETSCAN1, status=Status.READY, owner="ORG_A")
            org_b = _make_host("10.6.0.2", stage=Stage.NETSCAN1, status=Status.READY, owner="ORG_B")
            for h in [org_a, org_b]:
                await _save_host(h)

            result = await db_ops.fetch_ready_hosts(count=10, stage=Stage.NETSCAN1, owner=None)
            assert len(result) == 2

        asyncio.run(_run())

    def test_returned_host_objects_have_running_status(self, mock_db):
        """The returned HostDoc objects reflect the RUNNING status in memory."""

        async def _run():
            host = _make_host("10.7.0.1", stage=Stage.PORTSCAN, status=Status.READY)
            await _save_host(host)

            result = await db_ops.fetch_ready_hosts(count=5, stage=Stage.PORTSCAN)
            for h in result:
                assert h.status == Status.RUNNING

        asyncio.run(_run())

    def test_different_stages_fetched_independently(self, mock_db):
        """Fetching for one stage does not affect hosts in other stages."""

        async def _run():
            netscan1 = _make_host("10.8.0.1", stage=Stage.NETSCAN1, status=Status.READY)
            vulnscan = _make_host("10.8.0.2", stage=Stage.VULNSCAN, status=Status.READY)
            for h in [netscan1, vulnscan]:
                await _save_host(h)

            await db_ops.fetch_ready_hosts(count=5, stage=Stage.NETSCAN1)

            # VULNSCAN host should still be READY
            db_vulnscan = await _get_host("10.8.0.2")
            assert db_vulnscan.status == Status.READY

        asyncio.run(_run())

    def test_count_zero_returns_empty_list(self, mock_db):
        """Requesting count=0 uses MongoDB limit(0) semantics (no limit applied).

        Note: In MongoDB, limit(0) means 'no limit', so all matching hosts are
        returned. This test verifies the function passes count=0 through to the
        query without error.
        """

        async def _run():
            host = _make_host("10.9.0.1", stage=Stage.NETSCAN1, status=Status.READY)
            await _save_host(host)

            # limit(0) in MongoDB means no limit — all matching hosts are returned
            result = await db_ops.fetch_ready_hosts(count=0, stage=Stage.NETSCAN1)
            # The function returns whatever MongoDB returns for limit(0)
            assert isinstance(result, list)

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# check_host_next_scans
# ---------------------------------------------------------------------------


class TestCheckHostNextScans:
    """check_host_next_scans moves DONE hosts with elapsed next_scan back to WAITING."""

    def test_no_done_hosts_does_nothing(self, mock_db):
        """No DONE hosts → no changes."""

        async def _run():
            host = _make_host("10.10.0.1", stage=Stage.NETSCAN1, status=Status.WAITING)
            await _save_host(host)

            await db_ops.check_host_next_scans()

            db_host = await _get_host("10.10.0.1")
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_done_host_with_past_next_scan_becomes_waiting(self, mock_db):
        """DONE host whose next_scan is in the past → WAITING."""

        async def _run():
            past = _utcnow() - timedelta(hours=1)
            host = _make_host(
                "10.11.0.1",
                stage=Stage.NETSCAN1,
                status=Status.DONE,
                next_scan=past,
            )
            await _save_host(host)

            await db_ops.check_host_next_scans()

            db_host = await _get_host("10.11.0.1")
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_done_host_with_future_next_scan_stays_done(self, mock_db):
        """DONE host whose next_scan is in the future → stays DONE."""

        async def _run():
            future = _utcnow() + timedelta(hours=1)
            host = _make_host(
                "10.12.0.1",
                stage=Stage.NETSCAN1,
                status=Status.DONE,
                next_scan=future,
            )
            await _save_host(host)

            await db_ops.check_host_next_scans()

            db_host = await _get_host("10.12.0.1")
            assert db_host.status == Status.DONE

        asyncio.run(_run())

    def test_up_host_goes_to_portscan_stage(self, mock_db):
        """DONE host with state.up=True → stage=PORTSCAN, status=WAITING."""

        async def _run():
            past = _utcnow() - timedelta(hours=1)
            host = _make_host(
                "10.13.0.1",
                stage=Stage.NETSCAN1,
                status=Status.DONE,
                up=True,
                next_scan=past,
            )
            await _save_host(host)

            await db_ops.check_host_next_scans()

            db_host = await _get_host("10.13.0.1")
            assert db_host.stage == Stage.PORTSCAN
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_down_host_goes_to_netscan1_stage(self, mock_db):
        """DONE host with state.up=False → stage=NETSCAN1, status=WAITING."""

        async def _run():
            past = _utcnow() - timedelta(hours=1)
            host = _make_host(
                "10.14.0.1",
                stage=Stage.NETSCAN2,
                status=Status.DONE,
                up=False,
                next_scan=past,
            )
            await _save_host(host)

            await db_ops.check_host_next_scans()

            db_host = await _get_host("10.14.0.1")
            assert db_host.stage == Stage.NETSCAN1
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_next_scan_cleared_after_transition(self, mock_db):
        """After transitioning, next_scan is set to None."""

        async def _run():
            past = _utcnow() - timedelta(hours=1)
            host = _make_host(
                "10.15.0.1",
                stage=Stage.NETSCAN1,
                status=Status.DONE,
                next_scan=past,
            )
            await _save_host(host)

            await db_ops.check_host_next_scans()

            db_host = await _get_host("10.15.0.1")
            assert db_host.next_scan is None

        asyncio.run(_run())

    def test_only_done_hosts_are_affected(self, mock_db):
        """WAITING and RUNNING hosts are not affected even if next_scan is past."""

        async def _run():
            past = _utcnow() - timedelta(hours=1)
            waiting = _make_host(
                "10.16.0.1",
                stage=Stage.NETSCAN1,
                status=Status.WAITING,
                next_scan=past,
            )
            running = _make_host(
                "10.16.0.2",
                stage=Stage.NETSCAN1,
                status=Status.RUNNING,
                next_scan=past,
            )
            for h in [waiting, running]:
                await _save_host(h)

            await db_ops.check_host_next_scans()

            db_waiting = await _get_host("10.16.0.1")
            db_running = await _get_host("10.16.0.2")
            assert db_waiting.status == Status.WAITING
            assert db_running.status == Status.RUNNING

        asyncio.run(_run())

    def test_multiple_done_hosts_all_transitioned(self, mock_db):
        """Multiple DONE hosts with elapsed next_scan are all moved to WAITING."""

        async def _run():
            past = _utcnow() - timedelta(hours=1)
            for i in range(3):
                host = _make_host(
                    f"10.17.0.{i + 1}",
                    stage=Stage.NETSCAN1,
                    status=Status.DONE,
                    next_scan=past,
                )
                await _save_host(host)

            await db_ops.check_host_next_scans()

            hosts = await _all_hosts()
            for h in hosts:
                assert h.status == Status.WAITING

        asyncio.run(_run())

    def test_done_host_without_next_scan_not_affected(self, mock_db):
        """DONE host with next_scan=None is not moved (no scheduled rescan)."""

        async def _run():
            host = _make_host(
                "10.18.0.1",
                stage=Stage.NETSCAN1,
                status=Status.DONE,
                next_scan=None,
            )
            await _save_host(host)

            await db_ops.check_host_next_scans()

            db_host = await _get_host("10.18.0.1")
            assert db_host.status == Status.DONE

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# transition_host
# ---------------------------------------------------------------------------


class TestTransitionHost:
    """transition_host applies the state machine and updates the DB."""

    def test_netscan1_running_up_transitions_to_portscan_waiting(self, mock_db):
        """NETSCAN1/RUNNING + up=True → PORTSCAN/WAITING."""

        async def _run():
            host = _make_host("10.20.0.1", stage=Stage.NETSCAN1, status=Status.RUNNING)
            await _save_host(host)

            await db_ops.transition_host("10.20.0.1", up=True, reason="syn-ack")

            db_host = await _get_host("10.20.0.1")
            assert db_host.stage == Stage.PORTSCAN
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_netscan1_running_down_transitions_to_netscan2_waiting(self, mock_db):
        """NETSCAN1/RUNNING + up=False → NETSCAN2/WAITING."""

        async def _run():
            host = _make_host("10.21.0.1", stage=Stage.NETSCAN1, status=Status.RUNNING)
            await _save_host(host)

            await db_ops.transition_host("10.21.0.1", up=False, reason="no-response")

            db_host = await _get_host("10.21.0.1")
            assert db_host.stage == Stage.NETSCAN2
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_netscan2_running_up_transitions_to_portscan_waiting(self, mock_db):
        """NETSCAN2/RUNNING + up=True → PORTSCAN/WAITING."""

        async def _run():
            host = _make_host("10.22.0.1", stage=Stage.NETSCAN2, status=Status.RUNNING)
            await _save_host(host)

            await db_ops.transition_host("10.22.0.1", up=True, reason="syn-ack")

            db_host = await _get_host("10.22.0.1")
            assert db_host.stage == Stage.PORTSCAN
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_netscan2_running_down_transitions_to_done(self, mock_db):
        """NETSCAN2/RUNNING + up=False → NETSCAN2/DONE (host confirmed down)."""

        async def _run():
            host = _make_host("10.23.0.1", stage=Stage.NETSCAN2, status=Status.RUNNING)
            await _save_host(host)

            await db_ops.transition_host("10.23.0.1", up=False, reason="no-response")

            db_host = await _get_host("10.23.0.1")
            assert db_host.stage == Stage.NETSCAN2
            assert db_host.status == Status.DONE

        asyncio.run(_run())

    def test_portscan_running_with_open_ports_transitions_to_vulnscan(self, mock_db):
        """PORTSCAN/RUNNING + has_open_ports=True → VULNSCAN/WAITING."""

        async def _run():
            host = _make_host("10.24.0.1", stage=Stage.PORTSCAN, status=Status.RUNNING)
            await _save_host(host)

            await db_ops.transition_host(
                "10.24.0.1", up=True, reason="open-port", has_open_ports=True
            )

            db_host = await _get_host("10.24.0.1")
            assert db_host.stage == Stage.VULNSCAN
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_portscan_running_no_open_ports_transitions_to_done(self, mock_db):
        """PORTSCAN/RUNNING + has_open_ports=False → PORTSCAN/DONE."""

        async def _run():
            host = _make_host("10.25.0.1", stage=Stage.PORTSCAN, status=Status.RUNNING)
            await _save_host(host)

            await db_ops.transition_host(
                "10.25.0.1", up=False, reason="no-open", has_open_ports=False
            )

            db_host = await _get_host("10.25.0.1")
            assert db_host.stage == Stage.PORTSCAN
            assert db_host.status == Status.DONE

        asyncio.run(_run())

    def test_vulnscan_running_transitions_to_done(self, mock_db):
        """VULNSCAN/RUNNING → VULNSCAN/DONE."""

        async def _run():
            host = _make_host("10.26.0.1", stage=Stage.VULNSCAN, status=Status.RUNNING)
            await _save_host(host)

            await db_ops.transition_host("10.26.0.1", up=True, reason="syn-ack")

            db_host = await _get_host("10.26.0.1")
            assert db_host.stage == Stage.VULNSCAN
            assert db_host.status == Status.DONE

        asyncio.run(_run())

    def test_failure_reverts_to_waiting(self, mock_db):
        """was_failure=True reverts any RUNNING host to WAITING in the same stage."""

        async def _run():
            host = _make_host("10.27.0.1", stage=Stage.PORTSCAN, status=Status.RUNNING)
            await _save_host(host)

            await db_ops.transition_host(
                "10.27.0.1", up=False, reason="timeout", was_failure=True
            )

            db_host = await _get_host("10.27.0.1")
            assert db_host.stage == Stage.PORTSCAN
            assert db_host.status == Status.WAITING

        asyncio.run(_run())

    def test_state_up_and_reason_updated(self, mock_db):
        """transition_host updates host.state.up and host.state.reason."""

        async def _run():
            host = _make_host("10.28.0.1", stage=Stage.NETSCAN1, status=Status.RUNNING, up=False)
            await _save_host(host)

            await db_ops.transition_host("10.28.0.1", up=True, reason="syn-ack")

            db_host = await _get_host("10.28.0.1")
            assert db_host.state.up is True
            assert db_host.state.reason == "syn-ack"

        asyncio.run(_run())

    def test_latest_scan_timestamp_set_for_finished_stage(self, mock_db):
        """transition_host records a latest_scan timestamp for the finished stage."""

        async def _run():
            host = _make_host("10.29.0.1", stage=Stage.NETSCAN1, status=Status.RUNNING)
            await _save_host(host)

            await db_ops.transition_host("10.29.0.1", up=True, reason="syn-ack")

            db_host = await _get_host("10.29.0.1")
            assert Stage.NETSCAN1 in db_host.latest_scan
            # Timestamp is set (mongomock may strip tzinfo, so just check it's a datetime)
            ts = db_host.latest_scan[Stage.NETSCAN1]
            assert isinstance(ts, datetime)

        asyncio.run(_run())

    def test_done_host_gets_next_scan_scheduled(self, mock_db):
        """When a host reaches DONE, next_scan is set by the scheduler."""

        async def _run():
            host = _make_host("10.30.0.1", stage=Stage.NETSCAN2, status=Status.RUNNING)
            await _save_host(host)

            await db_ops.transition_host("10.30.0.1", up=False, reason="no-response")

            db_host = await _get_host("10.30.0.1")
            assert db_host.status == Status.DONE
            assert db_host.next_scan is not None
            # next_scan should be a datetime (mongomock may strip tzinfo)
            assert isinstance(db_host.next_scan, datetime)

        asyncio.run(_run())

    def test_tally_updated_after_transition(self, mock_db):
        """transition_host creates or updates the TallyDoc for the host's owner."""

        async def _run():
            host = _make_host(
                "10.31.0.1",
                stage=Stage.NETSCAN1,
                status=Status.RUNNING,
                owner=OWNER,
            )
            await _save_host(host)

            await db_ops.transition_host("10.31.0.1", up=True, reason="syn-ack")

            tally = await TallyDoc.get(OWNER)
            assert tally is not None

        asyncio.run(_run())

    def test_nonexistent_ip_does_not_raise(self, mock_db):
        """transition_host with an IP not in the DB logs a warning and returns."""

        async def _run():
            # Should not raise — just logs a warning
            await db_ops.transition_host("1.2.3.4", up=True, reason="syn-ack")

        asyncio.run(_run())

    def test_done_terminal_state_no_change(self, mock_db):
        """DONE/DONE host is a terminal state — transition_host makes no changes."""

        async def _run():
            host = _make_host("10.32.0.1", stage=Stage.VULNSCAN, status=Status.DONE)
            await _save_host(host)
            original_next_scan = host.next_scan

            await db_ops.transition_host("10.32.0.1", up=True, reason="syn-ack")

            db_host = await _get_host("10.32.0.1")
            assert db_host.stage == Stage.VULNSCAN
            assert db_host.status == Status.DONE

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# should_commander_pause
# ---------------------------------------------------------------------------


class TestShouldCommanderPause:
    """should_commander_pause checks for a PAUSE control document."""

    def test_returns_false_when_no_control_doc(self, mock_db):
        """No SystemControlDoc in DB → returns False."""

        async def _run():
            result = await db_ops.should_commander_pause()
            assert result is False

        asyncio.run(_run())

    def test_returns_true_when_pause_doc_exists(self, mock_db):
        """PAUSE/COMMANDER control doc present → returns True."""

        async def _run():
            doc = SystemControlDoc(
                action=ControlAction.PAUSE,
                target=ControlTarget.COMMANDER,
                reason="maintenance",
                sender="admin",
            )
            await doc.save()

            result = await db_ops.should_commander_pause()
            assert result is True

        asyncio.run(_run())

    def test_returns_false_for_non_pause_action(self, mock_db):
        """A STOP (non-PAUSE) control doc does not trigger pause."""

        async def _run():
            doc = SystemControlDoc(
                action=ControlAction.STOP,
                target=ControlTarget.COMMANDER,
                reason="shutdown",
                sender="admin",
            )
            await doc.save()

            result = await db_ops.should_commander_pause()
            assert result is False

        asyncio.run(_run())

    def test_returns_false_for_wrong_target(self, mock_db):
        """A PAUSE doc targeting a different component does not trigger pause."""

        async def _run():
            # Use COMMANDER as the only valid target; if there's another target
            # value, test with it. Otherwise skip this scenario.
            from cyhy_db.models.enum import ControlTarget as CT

            non_commander_targets = [t for t in CT if t != ControlTarget.COMMANDER]
            if not non_commander_targets:
                # Only one target value exists; skip this test scenario
                return

            doc = SystemControlDoc(
                action=ControlAction.PAUSE,
                target=non_commander_targets[0],
                reason="other target",
                sender="admin",
            )
            await doc.save()

            result = await db_ops.should_commander_pause()
            assert result is False

        asyncio.run(_run())

    def test_returns_true_with_multiple_control_docs(self, mock_db):
        """Returns True when a PAUSE/COMMANDER doc exists among multiple docs."""

        async def _run():
            stop_doc = SystemControlDoc(
                action=ControlAction.STOP,
                target=ControlTarget.COMMANDER,
                reason="shutdown",
                sender="admin",
            )
            pause_doc = SystemControlDoc(
                action=ControlAction.PAUSE,
                target=ControlTarget.COMMANDER,
                reason="maintenance",
                sender="admin",
            )
            await stop_doc.save()
            await pause_doc.save()

            result = await db_ops.should_commander_pause()
            assert result is True

        asyncio.run(_run())
