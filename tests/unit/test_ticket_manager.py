"""Unit tests for ticket lifecycle managers.

Covers VulnTicketManager, IPPortTicketManager, and IPTicketManager
lifecycle transitions using an in-memory MongoDB via mongomock-motor.

Requirements: AC-8.1, FR-8.3
"""

# Standard Python Libraries
import asyncio
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address

# Third-party libraries
from bson import ObjectId
from cyhy_db.models import (
    KEVDoc,
    NotificationDoc,
    PortScanDoc,
    TicketDoc,
    VulnScanDoc,
)
from cyhy_db.models.enum import Protocol, TicketAction

from cyhy_commander.ticket_manager import (
    IPPortTicketManager,
    IPTicketManager,
    VulnTicketManager,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

IP = "192.168.1.1"
OWNER = "TEST"
SOURCE = "nessus"
PORT_SOURCE = "nmap"


def _utcnow():
    return datetime.now(timezone.utc)


def _make_vuln(
    ip=IP,
    owner=OWNER,
    source=SOURCE,
    plugin_id=12345,
    port=80,
    protocol=Protocol.TCP,
    severity=2,
    plugin_name="Test Plugin",
):
    now = _utcnow()
    return VulnScanDoc(
        ip=ip,
        ip_int=int(IPv4Address(ip)),
        owner=owner,
        source=source,
        cvss_base_score=5.0,
        cvss_vector="AV:N/AC:L/Au:N/C:P/I:P/A:P",
        description="Test vulnerability",
        fname="test.nasl",
        plugin_family="General",
        plugin_id=plugin_id,
        plugin_modification_date=now,
        plugin_name=plugin_name,
        plugin_publication_date=now,
        plugin_type="remote",
        port=port,
        protocol=protocol,
        risk_factor="Medium",
        service="www",
        severity=severity,
        solution="Update software",
        synopsis="Test synopsis",
    )


def _make_port_scan(
    ip=IP,
    owner=OWNER,
    source=PORT_SOURCE,
    port=80,
    protocol=Protocol.TCP,
):
    return PortScanDoc(
        ip=ip,
        ip_int=int(IPv4Address(ip)),
        owner=owner,
        source=source,
        port=port,
        protocol=protocol,
        reason="syn-ack",
        service={"name": "http"},
        state="open",
    )


async def _save_vuln(vuln):
    await vuln.save()
    return vuln


async def _all_tickets():
    return await TicketDoc.find_all().to_list()


async def _open_tickets(ip=IP):
    return await TicketDoc.find(
        TicketDoc.ip == IPv4Address(ip),
        TicketDoc.open is True,
    ).to_list()


async def _all_notifications():
    return await NotificationDoc.find_all().to_list()


# ---------------------------------------------------------------------------
# VulnTicketManager tests
# ---------------------------------------------------------------------------


class TestVulnTicketManagerOpen:
    """VulnTicketManager opens a new ticket for a newly detected vulnerability."""

    def test_open_creates_ticket(self, mock_db):
        """New vuln with no existing ticket → one open ticket with OPENED event."""

        async def _run():
            vuln = _make_vuln()
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])
            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is True
            assert tickets[0].source == SOURCE
            assert tickets[0].source_id == vuln.plugin_id
            assert tickets[0].port == vuln.port
            assert tickets[0].protocol == vuln.protocol
            assert tickets[0].owner == OWNER
            events = tickets[0].events
            assert len(events) == 1
            assert events[0].action == TicketAction.OPENED

        asyncio.run(_run())

    def test_open_sets_ticket_details(self, mock_db):
        """Opened ticket details contain the vulnerability fields."""

        async def _run():
            vuln = _make_vuln(severity=3)
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])
            tickets = await _all_tickets()
            assert tickets[0].details["severity"] == 3
            assert tickets[0].details["plugin_id"] == vuln.plugin_id

        asyncio.run(_run())

    def test_open_sets_snapshot(self, mock_db):
        """Opened ticket includes the snapshot_id when provided."""

        async def _run():
            vuln = _make_vuln()
            await _save_vuln(vuln)
            snap_id = ObjectId()
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln], snapshot_id=snap_id)
            tickets = await _all_tickets()
            snap_ids = [s.ref.id for s in tickets[0].snapshots]
            assert snap_id in snap_ids

        asyncio.run(_run())

    def test_open_no_notification_for_low_severity(self, mock_db):
        """Severity < 3 and no KEV → no NotificationDoc created."""

        async def _run():
            vuln = _make_vuln(severity=2)
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])
            notifications = await _all_notifications()
            assert len(notifications) == 0

        asyncio.run(_run())

    def test_open_creates_notification_for_high_severity(self, mock_db):
        """Severity >= 3 → NotificationDoc created on open."""

        async def _run():
            vuln = _make_vuln(severity=3)
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])
            notifications = await _all_notifications()
            assert len(notifications) == 1
            tickets = await _all_tickets()
            assert notifications[0].ticket_id == tickets[0].id
            assert notifications[0].ticket_owner == OWNER

        asyncio.run(_run())

    def test_open_creates_notification_for_critical_severity(self, mock_db):
        """Severity 4 (critical) → NotificationDoc created on open."""

        async def _run():
            vuln = _make_vuln(severity=4)
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])
            notifications = await _all_notifications()
            assert len(notifications) == 1

        asyncio.run(_run())

    def test_open_creates_notification_for_kev(self, mock_db):
        """CVE in KEV catalogue → NotificationDoc created even for low severity."""

        async def _run():
            # Insert a KEV entry
            kev = KEVDoc(id="CVE-2021-44228", known_ransomware=True)
            await kev.save()
            # Vuln with low severity but CVE in plugin_name
            vuln = _make_vuln(
                severity=1, plugin_name="CVE-2021-44228 Apache Log4j"
            )
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])
            notifications = await _all_notifications()
            assert len(notifications) == 1

        asyncio.run(_run())

    def test_open_no_duplicate_notification(self, mock_db):
        """Running process_tickets twice does not create duplicate notifications."""

        async def _run():
            vuln = _make_vuln(severity=3)
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])
            await mgr.process_tickets(IP, [vuln])
            notifications = await _all_notifications()
            assert len(notifications) == 1

        asyncio.run(_run())

    def test_open_multiple_vulns_creates_multiple_tickets(self, mock_db):
        """Multiple distinct vulns → one ticket per vuln."""

        async def _run():
            vuln1 = _make_vuln(plugin_id=1001, port=80)
            vuln2 = _make_vuln(plugin_id=1002, port=443)
            await _save_vuln(vuln1)
            await _save_vuln(vuln2)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln1, vuln2])
            tickets = await _all_tickets()
            assert len(tickets) == 2
            assert all(t.open for t in tickets)

        asyncio.run(_run())


class TestVulnTicketManagerVerify:
    """VulnTicketManager verifies an existing open ticket when vuln is re-detected."""

    def test_verify_adds_verified_event(self, mock_db):
        """Re-detected vuln + open ticket → VERIFIED event added."""

        async def _run():
            vuln = _make_vuln()
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            # First scan: open
            await mgr.process_tickets(IP, [vuln])
            # Second scan: verify
            await mgr.process_tickets(IP, [vuln])
            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is True
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.OPENED in actions
            assert TicketAction.VERIFIED in actions

        asyncio.run(_run())

    def test_verify_updates_details(self, mock_db):
        """Verify updates ticket details with latest scan data."""

        async def _run():
            vuln = _make_vuln(severity=2)
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])

            # Second scan with updated severity
            vuln2 = _make_vuln(severity=3)
            await _save_vuln(vuln2)
            await mgr.process_tickets(IP, [vuln2])

            tickets = await _all_tickets()
            assert tickets[0].details["severity"] == 3

        asyncio.run(_run())

    def test_verify_escalated_severity_creates_notification(self, mock_db):
        """Severity escalates to >= 3 on verify → NotificationDoc created."""

        async def _run():
            vuln_low = _make_vuln(severity=2)
            await _save_vuln(vuln_low)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln_low])
            # No notification yet
            assert len(await _all_notifications()) == 0

            vuln_high = _make_vuln(severity=3)
            await _save_vuln(vuln_high)
            await mgr.process_tickets(IP, [vuln_high])
            notifications = await _all_notifications()
            assert len(notifications) == 1

        asyncio.run(_run())

    def test_verify_no_notification_when_severity_already_high(self, mock_db):
        """Severity stays >= 3 on re-verify → no duplicate notification."""

        async def _run():
            vuln = _make_vuln(severity=3)
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])
            await mgr.process_tickets(IP, [vuln])
            notifications = await _all_notifications()
            assert len(notifications) == 1

        asyncio.run(_run())

    def test_verify_adds_snapshot(self, mock_db):
        """Verify appends new snapshot_id to ticket.snapshots."""

        async def _run():
            vuln = _make_vuln()
            await _save_vuln(vuln)
            snap1 = ObjectId()
            snap2 = ObjectId()
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln], snapshot_id=snap1)
            await mgr.process_tickets(IP, [vuln], snapshot_id=snap2)
            tickets = await _all_tickets()
            snap_ids = [s.ref.id for s in tickets[0].snapshots]
            assert snap1 in snap_ids
            assert snap2 in snap_ids

        asyncio.run(_run())


class TestVulnTicketManagerReopen:
    """VulnTicketManager reopens a recently closed ticket."""

    def _make_closed_ticket(self, vuln, days_ago=1):
        """Create a closed TicketDoc for the given vuln, closed N days ago."""
        now = _utcnow()
        closed_at = now - timedelta(days=days_ago)
        ticket = TicketDoc(
            details={"severity": vuln.severity, "plugin_id": vuln.plugin_id},
            false_positive=False,
            ip=vuln.ip,
            ip_int=int(vuln.ip),
            open=False,
            owner=vuln.owner,
            port=vuln.port,
            protocol=vuln.protocol,
            source=vuln.source,
            source_id=vuln.plugin_id,
            time_opened=closed_at - timedelta(days=1),
            time_closed=closed_at,
        )
        ticket.add_event(
            action=TicketAction.OPENED,
            reason="new vulnerability detected",
            time=closed_at - timedelta(days=1),
        )
        ticket.add_event(
            action=TicketAction.CLOSED,
            reason="vulnerability no longer detected",
            time=closed_at,
        )
        return ticket

    def test_reopen_within_window(self, mock_db):
        """Re-detected vuln + closed ticket within 90 days → REOPENED event.

        Ticket open=True after reopen.
        """

        async def _run():
            vuln = _make_vuln()
            await _save_vuln(vuln)
            ticket = self._make_closed_ticket(vuln, days_ago=30)
            await ticket.save()

            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])

            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is True
            assert tickets[0].time_closed is None
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.REOPENED in actions

        asyncio.run(_run())

    def test_reopen_outside_window_creates_new_ticket(self, mock_db):
        """Re-detected vuln + closed ticket older than 90 days → new ticket opened."""

        async def _run():
            vuln = _make_vuln()
            await _save_vuln(vuln)
            ticket = self._make_closed_ticket(vuln, days_ago=91)
            await ticket.save()

            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])

            tickets = await _all_tickets()
            # Old closed ticket + new open ticket
            assert len(tickets) == 2
            open_tickets = [t for t in tickets if t.open]
            assert len(open_tickets) == 1
            actions = [e.action for e in open_tickets[0].events]
            assert TicketAction.OPENED in actions
            assert TicketAction.REOPENED not in actions

        asyncio.run(_run())

    def test_reopen_at_window_boundary(self, mock_db):
        """Ticket closed just inside the 90-day reopen window is still reopened."""

        async def _run():
            vuln = _make_vuln()
            await _save_vuln(vuln)
            # Use 89 days to stay safely within the 90-day window regardless
            # of sub-second timing differences between ticket creation and the
            # process_tickets call.
            ticket = self._make_closed_ticket(vuln, days_ago=89)
            await ticket.save()

            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])

            tickets = await _all_tickets()
            open_tickets = [t for t in tickets if t.open]
            assert len(open_tickets) == 1
            actions = [e.action for e in open_tickets[0].events]
            assert TicketAction.REOPENED in actions

        asyncio.run(_run())

    def test_reopen_creates_notification_for_high_severity(self, mock_db):
        """Reopened ticket with severity >= 3 → NotificationDoc created."""

        async def _run():
            vuln = _make_vuln(severity=3)
            await _save_vuln(vuln)
            ticket = self._make_closed_ticket(vuln, days_ago=30)
            await ticket.save()

            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])

            notifications = await _all_notifications()
            assert len(notifications) == 1

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# VulnTicketManager close tests
# ---------------------------------------------------------------------------


class TestVulnTicketManagerClose:
    """VulnTicketManager closes open tickets for vulns no longer detected."""

    def test_close_undetected_vuln(self, mock_db):
        """Not-detected vuln + open ticket + false_positive=False → CLOSED event.

        Ticket open=False after close.
        """

        async def _run():
            vuln = _make_vuln()
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            # Open the ticket
            await mgr.process_tickets(IP, [vuln])
            tickets = await _all_tickets()
            assert tickets[0].open is True

            # Second scan: vuln not detected
            await mgr.process_tickets(IP, [])
            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is False
            assert tickets[0].time_closed is not None
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.CLOSED in actions

        asyncio.run(_run())

    def test_close_false_positive_adds_unverified_not_closed(self, mock_db):
        """Not-detected vuln + open ticket + false_positive=True → UNVERIFIED event.

        Ticket stays open.
        """

        async def _run():
            vuln = _make_vuln()
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            # Open the ticket
            await mgr.process_tickets(IP, [vuln])
            tickets = await _all_tickets()
            # Mark as false positive
            tickets[0].false_positive = True
            await tickets[0].save()

            # Second scan: vuln not detected
            await mgr.process_tickets(IP, [])
            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is True
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.UNVERIFIED in actions
            assert TicketAction.CLOSED not in actions

        asyncio.run(_run())

    def test_close_only_undetected_vulns(self, mock_db):
        """Multiple vulns: some detected, some not → only undetected ones closed."""

        async def _run():
            vuln1 = _make_vuln(plugin_id=1001, port=80)
            vuln2 = _make_vuln(plugin_id=1002, port=443)
            await _save_vuln(vuln1)
            await _save_vuln(vuln2)
            mgr = VulnTicketManager()
            # Open both tickets
            await mgr.process_tickets(IP, [vuln1, vuln2])
            tickets = await _all_tickets()
            assert len(tickets) == 2

            # Second scan: only vuln1 detected
            await mgr.process_tickets(IP, [vuln1])
            tickets = await _all_tickets()
            assert len(tickets) == 2

            open_tickets = [t for t in tickets if t.open]
            closed_tickets = [t for t in tickets if not t.open]
            assert len(open_tickets) == 1
            assert len(closed_tickets) == 1
            assert open_tickets[0].source_id == 1001
            assert closed_tickets[0].source_id == 1002

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# VulnTicketManager false-positive handling tests
# ---------------------------------------------------------------------------


class TestVulnTicketManagerFalsePositive:
    """VulnTicketManager handles false-positive tickets correctly."""

    def test_false_positive_not_closed_when_vuln_not_detected(self, mock_db):
        """False-positive ticket not closed when vuln not detected.

        UNVERIFIED event added instead.
        """

        async def _run():
            vuln = _make_vuln()
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])
            tickets = await _all_tickets()
            tickets[0].false_positive = True
            await tickets[0].save()

            # Vuln not detected in next scan
            await mgr.process_tickets(IP, [])
            tickets = await _all_tickets()
            assert tickets[0].open is True
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.UNVERIFIED in actions
            assert TicketAction.CLOSED not in actions

        asyncio.run(_run())

    def test_false_positive_expiration_flips_flag_and_closes(self, mock_db):
        """Expired false_positive_expiration_date → flip false_positive=False.

        CHANGED event added, then ticket closed.
        """

        async def _run():
            vuln = _make_vuln()
            await _save_vuln(vuln)
            mgr = VulnTicketManager()
            await mgr.process_tickets(IP, [vuln])
            tickets = await _all_tickets()

            # Set false_positive with an expiration date in the past
            past_date = _utcnow() - timedelta(days=1)
            tickets[0].false_positive = True
            tickets[0].fp_expiration_date = past_date
            await tickets[0].save()

            # Vuln not detected → expiration should trigger
            await mgr.process_tickets(IP, [])
            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is False
            assert tickets[0].false_positive is False
            assert tickets[0].fp_expiration_date is None
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.CHANGED in actions
            assert TicketAction.CLOSED in actions

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# IPPortTicketManager full-scan tests
# ---------------------------------------------------------------------------


class TestIPPortTicketManagerFullScan:
    """IPPortTicketManager handles full-scan close logic."""

    def test_full_scan_port_present_stays_open(self, mock_db):
        """Port present in full scan → ticket stays open (VERIFIED event)."""

        async def _run():
            port_scan = _make_port_scan(port=80)
            await port_scan.save()
            mgr = IPPortTicketManager()
            # First scan: open ticket
            await mgr.process_tickets(IP, [port_scan], is_full_scan=True)
            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is True

            # Second full scan: port still present
            await mgr.process_tickets(IP, [port_scan], is_full_scan=True)
            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is True
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.VERIFIED in actions

        asyncio.run(_run())

    def test_full_scan_port_absent_closes_ticket(self, mock_db):
        """Port absent from full scan → ticket closed (CLOSED event)."""

        async def _run():
            port_scan = _make_port_scan(port=80)
            await port_scan.save()
            mgr = IPPortTicketManager()
            # First scan: open ticket
            await mgr.process_tickets(IP, [port_scan], is_full_scan=True)
            tickets = await _all_tickets()
            assert tickets[0].open is True

            # Second full scan: port not present
            await mgr.process_tickets(IP, [], is_full_scan=True)
            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is False
            assert tickets[0].time_closed is not None
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.CLOSED in actions

        asyncio.run(_run())

    def test_full_scan_new_port_opens_ticket(self, mock_db):
        """New port detected in full scan → new ticket opened."""

        async def _run():
            port_scan = _make_port_scan(port=8080)
            await port_scan.save()
            mgr = IPPortTicketManager()
            await mgr.process_tickets(IP, [port_scan], is_full_scan=True)
            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is True
            assert tickets[0].port == 8080
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.OPENED in actions

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# IPPortTicketManager partial-scan tests
# ---------------------------------------------------------------------------


class TestIPPortTicketManagerPartialScan:
    """IPPortTicketManager handles partial-scan close logic."""

    def test_partial_scan_absent_port_not_closed(self, mock_db):
        """Port absent from partial scan → ticket NOT closed.

        Partial scan cannot close tickets.
        """

        async def _run():
            port_scan = _make_port_scan(port=80)
            await port_scan.save()
            mgr = IPPortTicketManager()
            # Open the ticket via a full scan first
            await mgr.process_tickets(IP, [port_scan], is_full_scan=True)
            tickets = await _all_tickets()
            assert tickets[0].open is True

            # Partial scan: port 80 not in results
            await mgr.process_tickets(IP, [], is_full_scan=False)
            tickets = await _all_tickets()
            assert len(tickets) == 1
            # Ticket should remain open — partial scan cannot close tickets
            assert tickets[0].open is True
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.CLOSED not in actions

        asyncio.run(_run())

    def test_partial_scan_present_port_verified(self, mock_db):
        """Port present in partial scan → ticket verified (VERIFIED event)."""

        async def _run():
            port_scan = _make_port_scan(port=443)
            await port_scan.save()
            mgr = IPPortTicketManager()
            # Open the ticket
            await mgr.process_tickets(IP, [port_scan], is_full_scan=True)

            # Partial scan: port 443 still present
            await mgr.process_tickets(IP, [port_scan], is_full_scan=False)
            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is True
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.VERIFIED in actions

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# IPTicketManager tests
# ---------------------------------------------------------------------------


class TestIPTicketManager:
    """IPTicketManager handles host-down close logic."""

    def _make_host_ticket(self, ip=IP, owner=OWNER, false_positive=False):
        """Create an open host-level (netscan) TicketDoc."""
        now = _utcnow()
        ticket = TicketDoc(
            details={},
            false_positive=false_positive,
            ip=IPv4Address(ip),
            ip_int=int(IPv4Address(ip)),
            open=True,
            owner=owner,
            port=0,
            protocol=Protocol.TCP,
            source="netscan",
            source_id=0,
            time_opened=now,
        )
        ticket.add_event(
            action=TicketAction.OPENED,
            reason="host detected as up",
            time=now,
        )
        return ticket

    def test_host_up_tickets_stay_open(self, mock_db):
        """is_up=True → open host tickets stay open (no action taken)."""

        async def _run():
            ticket = self._make_host_ticket()
            await ticket.save()

            mgr = IPTicketManager()
            await mgr.process_tickets(IP, is_up=True)

            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is True
            # No new events added
            assert len(tickets[0].events) == 1

        asyncio.run(_run())

    def test_host_down_closes_open_tickets(self, mock_db):
        """is_up=False → open host tickets closed (CLOSED event)."""

        async def _run():
            ticket = self._make_host_ticket()
            await ticket.save()

            mgr = IPTicketManager()
            await mgr.process_tickets(IP, is_up=False)

            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is False
            assert tickets[0].time_closed is not None
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.CLOSED in actions

        asyncio.run(_run())

    def test_false_positive_host_ticket_not_closed_when_host_down(
        self, mock_db
    ):
        """False-positive host ticket not closed when host is down.

        UNVERIFIED event added instead.
        """

        async def _run():
            ticket = self._make_host_ticket(false_positive=True)
            await ticket.save()

            mgr = IPTicketManager()
            await mgr.process_tickets(IP, is_up=False)

            tickets = await _all_tickets()
            assert len(tickets) == 1
            assert tickets[0].open is True
            actions = [e.action for e in tickets[0].events]
            assert TicketAction.UNVERIFIED in actions
            assert TicketAction.CLOSED not in actions

        asyncio.run(_run())

    def test_host_down_only_closes_netscan_tickets(self, mock_db):
        """is_up=False → only netscan-source tickets are closed, not vuln tickets."""

        async def _run():
            # Create a host-level (netscan) ticket
            host_ticket = self._make_host_ticket()
            await host_ticket.save()

            # Create a vuln ticket for the same IP (different source)
            vuln = _make_vuln()
            await _save_vuln(vuln)
            mgr_vuln = VulnTicketManager()
            await mgr_vuln.process_tickets(IP, [vuln])

            all_before = await _all_tickets()
            assert len(all_before) == 2

            mgr = IPTicketManager()
            await mgr.process_tickets(IP, is_up=False)

            tickets = await _all_tickets()
            netscan_tickets = [t for t in tickets if t.source == "netscan"]
            vuln_tickets = [t for t in tickets if t.source == SOURCE]
            assert len(netscan_tickets) == 1
            assert netscan_tickets[0].open is False
            assert len(vuln_tickets) == 1
            assert vuln_tickets[0].open is True

        asyncio.run(_run())
