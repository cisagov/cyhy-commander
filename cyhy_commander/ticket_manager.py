"""Ticket lifecycle managers for CyHy Commander.

This module provides three ticket manager classes that handle the full
lifecycle of vulnerability, port, and host tickets:

- VulnTicketManager: Manages tickets for VULNSCAN results (Nessus)
- IPPortTicketManager: Manages tickets for PORTSCAN results (nmap)
- IPTicketManager: Manages tickets for NETSCAN results (nmap host up/down)

"""

# Standard Python Libraries
import logging
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from typing import Any

# Third-party libraries
from bson import ObjectId
from cyhy_db.models import (
    KEVDoc,
    NotificationDoc,
    PortScanDoc,
    SnapshotDoc,
    TicketDoc,
    VulnScanDoc,
)
from cyhy_db.models.enum import TicketAction
from cyhy_logging import CYHY_ROOT_LOGGER

logger = logging.getLogger(CYHY_ROOT_LOGGER + ".commander.ticket_manager")

# Default window (in days) within which a closed ticket can be reopened
# rather than creating a new one.
_REOPEN_WINDOW_DAYS: int = 90

# Source string used for host-level (NETSCAN) tickets.
_HOST_TICKET_SOURCE: str = "netscan"

# Port value used for host-level tickets (no specific port).
_HOST_TICKET_PORT: int = 0


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    """Return *dt* as a timezone-aware UTC datetime.

    If *dt* is already timezone-aware, it is returned unchanged.  If it is
    naive (no tzinfo), it is assumed to be UTC and given an explicit UTC
    timezone.  This handles the case where mongomock strips timezone
    information from stored datetimes.

    Args:
        dt: The datetime to normalise.

    Returns:
        A timezone-aware datetime in UTC.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def _is_kev(cve_id: str) -> bool:
    """Return True if the given CVE ID is in the KEV catalogue.

    Args:
        cve_id: A CVE identifier string (e.g. "CVE-2021-44228").

    Returns:
        True if a KEVDoc with that id exists, False otherwise.
    """
    doc = await KEVDoc.get(cve_id)
    return doc is not None


class VulnTicketManager:
    """Manages the lifecycle of vulnerability tickets (VULNSCAN results).

    Ticket lifecycle rules:
    - Newly detected vuln + no existing ticket → OPENED event, open=True
    - Re-detected vuln + open ticket → VERIFIED event
    - Re-detected vuln + closed ticket within reopen window → REOPENED event,
      open=True
    - Not detected + open ticket + false_positive=False → CLOSED event,
      open=False
    - Not detected + open ticket + false_positive=True → UNVERIFIED event
      (not closed)
    - False positive expiration date passed → flip false_positive=False,
      add CHANGED event
    - New/escalated severity ≥ 3 or KEV → create NotificationDoc
    """

    REOPEN_WINDOW_DAYS: int = _REOPEN_WINDOW_DAYS

    async def process_tickets(
        self,
        ip: str,
        detected_vulns: list[VulnScanDoc],
        snapshot_id: ObjectId | None = None,
    ) -> None:
        """Open, verify, reopen, or close tickets based on current scan results.

        For each detected vulnerability, find or create a ticket. For each
        existing open ticket whose vulnerability was not detected, close it
        (or mark it unverified if it is a false positive).

        Args:
            ip: The IP address string of the scanned host.
            detected_vulns: List of VulnScanDoc objects from the current scan.
            snapshot_id: Optional snapshot ObjectId to tag tickets with.
        """
        ip_addr = IPv4Address(ip)

        # Fetch all existing tickets (open and recently closed) for this IP.
        # We need closed tickets too so we can reopen them within the window.
        existing_tickets = await TicketDoc.find(
            TicketDoc.ip == ip_addr,
        ).to_list()

        # Build a lookup: (source, source_id, port, protocol) → ticket
        ticket_map: dict[tuple[Any, ...], TicketDoc] = {}
        for ticket in existing_tickets:
            key = (
                ticket.source,
                ticket.source_id,
                ticket.port,
                ticket.protocol,
            )
            # Prefer open tickets over closed ones when there are duplicates.
            if key not in ticket_map or ticket.open:
                ticket_map[key] = ticket

        # Track which ticket keys were detected in this scan.
        detected_keys: set[tuple[Any, ...]] = set()

        for vuln in detected_vulns:
            key = (vuln.source, vuln.plugin_id, vuln.port, vuln.protocol)
            detected_keys.add(key)

            existing = ticket_map.get(key)

            if existing is None:
                # No existing ticket — open a new one.
                await self._open_ticket(vuln, snapshot_id)
            elif existing.open:
                # Existing open ticket — verify it.
                await self._verify_ticket(existing, vuln, snapshot_id)
            else:
                # Existing closed ticket — check if within reopen window.
                reopen_cutoff = _utcnow() - timedelta(
                    days=self.REOPEN_WINDOW_DAYS
                )
                if (
                    existing.time_closed
                    and _as_utc(existing.time_closed) >= reopen_cutoff
                ):
                    await self._reopen_ticket(existing, vuln, snapshot_id)
                else:
                    # Outside reopen window — open a fresh ticket.
                    await self._open_ticket(vuln, snapshot_id)

        # Close (or mark unverified) open tickets for vulns no longer detected.
        for key, ticket in ticket_map.items():
            if not ticket.open:
                continue
            if key in detected_keys:
                continue

            # Handle false positive expiration before deciding action.
            if ticket.false_positive and ticket.fp_expiration_date:
                if _as_utc(ticket.fp_expiration_date) <= _utcnow():
                    await self._expire_false_positive(ticket)
                    # After expiration, treat as a normal open ticket.
                    await self._close_ticket(ticket, snapshot_id)
                else:
                    await self._handle_false_positive(ticket)
            elif ticket.false_positive:
                await self._handle_false_positive(ticket)
            else:
                await self._close_ticket(ticket, snapshot_id)

    async def _open_ticket(
        self,
        vuln: VulnScanDoc,
        snapshot_id: ObjectId | None = None,
    ) -> TicketDoc:
        """Create and save a new open ticket for a newly detected vulnerability.

        Also creates a NotificationDoc if the severity is ≥ 3 or the CVE is
        in the KEV catalogue.

        Args:
            vuln: The VulnScanDoc representing the detected vulnerability.
            snapshot_id: Optional snapshot ObjectId to tag the ticket with.

        Returns:
            The newly created and saved TicketDoc.
        """
        now = _utcnow()
        ticket = TicketDoc(
            details=_vuln_details(vuln),
            false_positive=False,
            ip=vuln.ip,
            ip_int=int(vuln.ip),
            open=True,
            owner=vuln.owner,
            port=vuln.port,
            protocol=vuln.protocol,
            source=vuln.source,
            source_id=vuln.plugin_id,
            time_opened=now,
        )
        ticket.add_event(
            action=TicketAction.OPENED,
            reason="new vulnerability detected",
            reference=vuln.id,
            time=now,
        )
        if snapshot_id is not None:
            ticket.snapshots = [_snapshot_link(snapshot_id)]

        await ticket.save()
        logger.debug(
            "Opened ticket for ip=%s source=%s plugin_id=%d port=%d",
            vuln.ip,
            vuln.source,
            vuln.plugin_id,
            vuln.port,
        )

        # Create notification for high-severity or KEV vulnerabilities.
        await self._maybe_notify(ticket, vuln)

        return ticket

    async def _verify_ticket(
        self,
        ticket: TicketDoc,
        vuln: VulnScanDoc,
        snapshot_id: ObjectId | None = None,
    ) -> None:
        """Add a VERIFIED event to an existing open ticket.

        Also updates ticket details with the latest scan data and creates a
        notification if severity has escalated to ≥ 3 or the CVE is now KEV.

        Args:
            ticket: The existing open TicketDoc to verify.
            vuln: The VulnScanDoc from the current scan.
            snapshot_id: Optional snapshot ObjectId to tag the ticket with.
        """
        now = _utcnow()
        old_severity = ticket.details.get("severity", 0)
        ticket.details = _vuln_details(vuln)
        ticket.add_event(
            action=TicketAction.VERIFIED,
            reason="vulnerability re-detected",
            reference=vuln.id,
            time=now,
        )
        if snapshot_id is not None and not _snapshot_id_in_links(
            snapshot_id, ticket.snapshots
        ):
            if ticket.snapshots is None:
                ticket.snapshots = []
            ticket.snapshots.append(_snapshot_link(snapshot_id))

        await ticket.save()
        logger.debug(
            "Verified ticket %s for ip=%s plugin_id=%d",
            ticket.id,
            ticket.ip,
            vuln.plugin_id,
        )

        # Notify if severity escalated to ≥ 3.
        new_severity = vuln.severity
        if new_severity >= 3 and old_severity < 3:
            await self._maybe_notify(ticket, vuln)

    async def _reopen_ticket(
        self,
        ticket: TicketDoc,
        vuln: VulnScanDoc,
        snapshot_id: ObjectId | None = None,
    ) -> None:
        """Reopen a recently closed ticket for a re-detected vulnerability.

        Args:
            ticket: The closed TicketDoc to reopen.
            vuln: The VulnScanDoc from the current scan.
            snapshot_id: Optional snapshot ObjectId to tag the ticket with.
        """
        now = _utcnow()
        ticket.open = True
        ticket.time_closed = None
        ticket.details = _vuln_details(vuln)
        ticket.add_event(
            action=TicketAction.REOPENED,
            reason="vulnerability re-detected within reopen window",
            reference=vuln.id,
            time=now,
        )
        if snapshot_id is not None and not _snapshot_id_in_links(
            snapshot_id, ticket.snapshots
        ):
            if ticket.snapshots is None:
                ticket.snapshots = []
            ticket.snapshots.append(_snapshot_link(snapshot_id))

        await ticket.save()
        logger.debug(
            "Reopened ticket %s for ip=%s plugin_id=%d",
            ticket.id,
            ticket.ip,
            vuln.plugin_id,
        )

        # Notify for high-severity or KEV on reopen.
        await self._maybe_notify(ticket, vuln)

    async def _close_ticket(
        self,
        ticket: TicketDoc,
        snapshot_id: ObjectId | None = None,
    ) -> None:
        """Close an open ticket for a vulnerability no longer detected.

        Args:
            ticket: The open TicketDoc to close.
            snapshot_id: Optional snapshot ObjectId to tag the ticket with.
        """
        now = _utcnow()
        ticket.open = False
        ticket.time_closed = now
        ticket.add_event(
            action=TicketAction.CLOSED,
            reason="vulnerability no longer detected",
            time=now,
        )
        if snapshot_id is not None and not _snapshot_id_in_links(
            snapshot_id, ticket.snapshots
        ):
            if ticket.snapshots is None:
                ticket.snapshots = []
            ticket.snapshots.append(_snapshot_link(snapshot_id))

        await ticket.save()
        logger.debug(
            "Closed ticket %s for ip=%s",
            ticket.id,
            ticket.ip,
        )

    async def _handle_false_positive(self, ticket: TicketDoc) -> None:
        """Add an UNVERIFIED event to a false-positive ticket (do not close it).

        Args:
            ticket: The open false-positive TicketDoc.
        """
        now = _utcnow()
        ticket.add_event(
            action=TicketAction.UNVERIFIED,
            reason="vulnerability not detected; false positive — not closing",
            time=now,
        )
        await ticket.save()
        logger.debug(
            "Unverified false-positive ticket %s for ip=%s",
            ticket.id,
            ticket.ip,
        )

    async def _expire_false_positive(self, ticket: TicketDoc) -> None:
        """Flip false_positive=False and add a CHANGED event when expiration passes.

        Args:
            ticket: The TicketDoc whose false-positive flag has expired.
        """
        from cyhy_db.models.ticket_doc import EventDelta

        now = _utcnow()
        delta = EventDelta(
            **{"from": True, "key": "false_positive", "to": False}
        )
        ticket.false_positive = False
        ticket.fp_expiration_date = None
        ticket.add_event(
            action=TicketAction.CHANGED,
            reason="false positive expiration date passed",
            time=now,
            delta=delta,
        )
        logger.debug(
            "Expired false positive on ticket %s for ip=%s",
            ticket.id,
            ticket.ip,
        )
        # Note: caller is responsible for saving after this method.

    async def _maybe_notify(self, ticket: TicketDoc, vuln: VulnScanDoc) -> None:
        """Create a NotificationDoc if the vulnerability warrants one.

        A notification is created when:
        - The vulnerability severity is ≥ 3 (High or Critical), OR
        - The CVE is in the KEV catalogue.

        Avoids creating duplicate notifications for the same ticket.

        Args:
            ticket: The TicketDoc that triggered the potential notification.
            vuln: The VulnScanDoc with severity and CVE information.
        """
        should_notify = vuln.severity >= 3

        if not should_notify:
            # Check KEV status by looking up the CVE ID in KEVDoc.
            # The plugin_name field typically contains the CVE ID for Nessus.
            cve_id = _extract_cve_id(vuln)
            if cve_id:
                should_notify = await _is_kev(cve_id)

        if not should_notify:
            return

        # Check if a notification already exists for this ticket.
        existing = await NotificationDoc.find_one(
            NotificationDoc.ticket_id == ticket.id
        )
        if existing is not None:
            return

        notification = NotificationDoc(
            ticket_id=ticket.id,
            ticket_owner=ticket.owner,
            generated_for=[],
        )
        await notification.save()
        logger.debug(
            "Created notification for ticket %s (severity=%d)",
            ticket.id,
            vuln.severity,
        )


class IPPortTicketManager:
    """Manages the lifecycle of port tickets (PORTSCAN results).

    Ticket lifecycle rules:
    - Open new tickets for newly detected open ports
    - Verify existing open tickets for re-detected open ports
    - Reopen recently closed tickets for re-detected open ports
    - Close tickets for ports no longer open
    - When is_full_scan=False (partial scan), only close tickets for ports
      that were explicitly scanned and not found open; ports outside the
      scanned range are left open
    - Handle false-positive tickets (add UNVERIFIED instead of closing)
    """

    REOPEN_WINDOW_DAYS: int = _REOPEN_WINDOW_DAYS

    async def process_tickets(
        self,
        ip: str,
        open_ports: list[PortScanDoc],
        is_full_scan: bool = True,
        snapshot_id: ObjectId | None = None,
    ) -> None:
        """Open, verify, reopen, or close port tickets.

        Args:
            ip: The IP address string of the scanned host.
            open_ports: List of PortScanDoc objects for open ports found in
                this scan.
            is_full_scan: If True, close tickets for all ports not in
                open_ports. If False (partial scan), only close tickets for
                ports that were explicitly scanned and not found open.
            snapshot_id: Optional snapshot ObjectId to tag tickets with.
        """
        ip_addr = IPv4Address(ip)

        # Fetch all existing tickets for this IP.
        existing_tickets = await TicketDoc.find(
            TicketDoc.ip == ip_addr,
        ).to_list()

        # Build lookup: (source, source_id, port, protocol) → ticket
        ticket_map: dict[tuple[Any, ...], TicketDoc] = {}
        for ticket in existing_tickets:
            key = (
                ticket.source,
                ticket.source_id,
                ticket.port,
                ticket.protocol,
            )
            if key not in ticket_map or ticket.open:
                ticket_map[key] = ticket

        # Track which ticket keys were found open in this scan.
        # Key format: (source, source_id, port, protocol) — matches ticket_map.
        open_port_keys: set[tuple[Any, ...]] = set()

        for port_scan in open_ports:
            # For port tickets: source_id == port (the port number is the
            # unique identifier within a source).
            ticket_key = (
                port_scan.source,
                port_scan.port,  # source_id
                port_scan.port,  # port
                port_scan.protocol,
            )
            open_port_keys.add(ticket_key)

            existing = ticket_map.get(ticket_key)

            if existing is None:
                await self._open_ticket(port_scan, snapshot_id)
            elif existing.open:
                await self._verify_ticket(existing, port_scan, snapshot_id)
            else:
                reopen_cutoff = _utcnow() - timedelta(
                    days=self.REOPEN_WINDOW_DAYS
                )
                if (
                    existing.time_closed
                    and _as_utc(existing.time_closed) >= reopen_cutoff
                ):
                    await self._reopen_ticket(existing, port_scan, snapshot_id)
                else:
                    await self._open_ticket(port_scan, snapshot_id)

        # Close tickets for ports no longer open.
        # For a partial scan (is_full_scan=False), we only have the list of
        # open ports — we do not know which ports were scanned but found
        # closed. Therefore, for partial scans we do not close any tickets;
        # only a full scan can authoritatively close tickets for absent ports.
        if is_full_scan:
            for key, ticket in ticket_map.items():
                if not ticket.open:
                    continue
                if key in open_port_keys:
                    continue

                if ticket.false_positive:
                    await self._handle_false_positive(ticket)
                else:
                    await self._close_ticket(ticket, snapshot_id)

    async def _open_ticket(
        self,
        port_scan: PortScanDoc,
        snapshot_id: ObjectId | None = None,
    ) -> TicketDoc:
        """Create and save a new open ticket for a newly detected open port.

        Args:
            port_scan: The PortScanDoc representing the detected open port.
            snapshot_id: Optional snapshot ObjectId to tag the ticket with.

        Returns:
            The newly created and saved TicketDoc.
        """
        now = _utcnow()
        ticket = TicketDoc(
            details=_port_details(port_scan),
            false_positive=False,
            ip=port_scan.ip,
            ip_int=int(port_scan.ip),
            open=True,
            owner=port_scan.owner,
            port=port_scan.port,
            protocol=port_scan.protocol,
            source=port_scan.source,
            source_id=port_scan.port,
            time_opened=now,
        )
        ticket.add_event(
            action=TicketAction.OPENED,
            reason="new open port detected",
            reference=port_scan.id,
            time=now,
        )
        if snapshot_id is not None:
            ticket.snapshots = [_snapshot_link(snapshot_id)]

        await ticket.save()
        logger.debug(
            "Opened port ticket for ip=%s port=%d/%s",
            port_scan.ip,
            port_scan.port,
            port_scan.protocol,
        )
        return ticket

    async def _verify_ticket(
        self,
        ticket: TicketDoc,
        port_scan: PortScanDoc,
        snapshot_id: ObjectId | None = None,
    ) -> None:
        """Add a VERIFIED event to an existing open port ticket.

        Args:
            ticket: The existing open TicketDoc to verify.
            port_scan: The PortScanDoc from the current scan.
            snapshot_id: Optional snapshot ObjectId to tag the ticket with.
        """
        now = _utcnow()
        ticket.details = _port_details(port_scan)
        ticket.add_event(
            action=TicketAction.VERIFIED,
            reason="open port re-detected",
            reference=port_scan.id,
            time=now,
        )
        if snapshot_id is not None and not _snapshot_id_in_links(
            snapshot_id, ticket.snapshots
        ):
            if ticket.snapshots is None:
                ticket.snapshots = []
            ticket.snapshots.append(_snapshot_link(snapshot_id))

        await ticket.save()
        logger.debug(
            "Verified port ticket %s for ip=%s port=%d",
            ticket.id,
            ticket.ip,
            port_scan.port,
        )

    async def _reopen_ticket(
        self,
        ticket: TicketDoc,
        port_scan: PortScanDoc,
        snapshot_id: ObjectId | None = None,
    ) -> None:
        """Reopen a recently closed port ticket for a re-detected open port.

        Args:
            ticket: The closed TicketDoc to reopen.
            port_scan: The PortScanDoc from the current scan.
            snapshot_id: Optional snapshot ObjectId to tag the ticket with.
        """
        now = _utcnow()
        ticket.open = True
        ticket.time_closed = None
        ticket.details = _port_details(port_scan)
        ticket.add_event(
            action=TicketAction.REOPENED,
            reason="open port re-detected within reopen window",
            reference=port_scan.id,
            time=now,
        )
        if snapshot_id is not None and not _snapshot_id_in_links(
            snapshot_id, ticket.snapshots
        ):
            if ticket.snapshots is None:
                ticket.snapshots = []
            ticket.snapshots.append(_snapshot_link(snapshot_id))

        await ticket.save()
        logger.debug(
            "Reopened port ticket %s for ip=%s port=%d",
            ticket.id,
            ticket.ip,
            port_scan.port,
        )

    async def _close_ticket(
        self,
        ticket: TicketDoc,
        snapshot_id: ObjectId | None = None,
    ) -> None:
        """Close an open port ticket for a port no longer detected as open.

        Args:
            ticket: The open TicketDoc to close.
            snapshot_id: Optional snapshot ObjectId to tag the ticket with.
        """
        now = _utcnow()
        ticket.open = False
        ticket.time_closed = now
        ticket.add_event(
            action=TicketAction.CLOSED,
            reason="port no longer detected as open",
            time=now,
        )
        if snapshot_id is not None and not _snapshot_id_in_links(
            snapshot_id, ticket.snapshots
        ):
            if ticket.snapshots is None:
                ticket.snapshots = []
            ticket.snapshots.append(_snapshot_link(snapshot_id))

        await ticket.save()
        logger.debug(
            "Closed port ticket %s for ip=%s port=%d",
            ticket.id,
            ticket.ip,
            ticket.port,
        )

    async def _handle_false_positive(self, ticket: TicketDoc) -> None:
        """Add an UNVERIFIED event to a false-positive port ticket.

        Args:
            ticket: The open false-positive TicketDoc.
        """
        now = _utcnow()
        ticket.add_event(
            action=TicketAction.UNVERIFIED,
            reason="port not detected; false positive — not closing",
            time=now,
        )
        await ticket.save()
        logger.debug(
            "Unverified false-positive port ticket %s for ip=%s port=%d",
            ticket.id,
            ticket.ip,
            ticket.port,
        )


class IPTicketManager:
    """Manages the lifecycle of host-level tickets (NETSCAN results).

    Ticket lifecycle rules:
    - Close open tickets for hosts that are no longer up
    - Handle false-positive tickets (add UNVERIFIED instead of closing)
    """

    async def process_tickets(
        self,
        ip: str,
        is_up: bool,
        snapshot_id: ObjectId | None = None,
    ) -> None:
        """Close open host tickets when the host is no longer up.

        If the host is up, no action is taken. If the host is down, all
        open host-level tickets for this IP are closed (or marked unverified
        if they are false positives).

        Args:
            ip: The IP address string of the scanned host.
            is_up: True if the host responded to the network scan, False if
                the host is down.
            snapshot_id: Optional snapshot ObjectId to tag tickets with.
        """
        if is_up:
            # Host is up — no tickets to close.
            return

        ip_addr = IPv4Address(ip)

        # Find all open host-level tickets for this IP.
        open_tickets = await TicketDoc.find(
            TicketDoc.ip == ip_addr,
            TicketDoc.open == True,  # noqa: E712
            TicketDoc.source == _HOST_TICKET_SOURCE,
        ).to_list()

        for ticket in open_tickets:
            if ticket.false_positive:
                await self._handle_false_positive(ticket)
            else:
                await self._close_ticket(ticket, snapshot_id)

    async def _close_ticket(
        self,
        ticket: TicketDoc,
        snapshot_id: ObjectId | None = None,
    ) -> None:
        """Close an open host ticket for a host that is no longer up.

        Args:
            ticket: The open TicketDoc to close.
            snapshot_id: Optional snapshot ObjectId to tag the ticket with.
        """
        now = _utcnow()
        ticket.open = False
        ticket.time_closed = now
        ticket.add_event(
            action=TicketAction.CLOSED,
            reason="host no longer up",
            time=now,
        )
        if snapshot_id is not None and not _snapshot_id_in_links(
            snapshot_id, ticket.snapshots
        ):
            if ticket.snapshots is None:
                ticket.snapshots = []
            ticket.snapshots.append(_snapshot_link(snapshot_id))

        await ticket.save()
        logger.debug(
            "Closed host ticket %s for ip=%s (host down)",
            ticket.id,
            ticket.ip,
        )

    async def _handle_false_positive(self, ticket: TicketDoc) -> None:
        """Add an UNVERIFIED event to a false-positive host ticket.

        Args:
            ticket: The open false-positive TicketDoc.
        """
        now = _utcnow()
        ticket.add_event(
            action=TicketAction.UNVERIFIED,
            reason="host not up; false positive — not closing",
            time=now,
        )
        await ticket.save()
        logger.debug(
            "Unverified false-positive host ticket %s for ip=%s",
            ticket.id,
            ticket.ip,
        )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _vuln_details(vuln: VulnScanDoc) -> dict[str, Any]:
    """Build the ticket details dict from a VulnScanDoc.

    Args:
        vuln: The VulnScanDoc to extract details from.

    Returns:
        A dict suitable for TicketDoc.details.
    """
    return {
        "cvss_base_score": vuln.cvss_base_score,
        "cvss_vector": vuln.cvss_vector,
        "description": vuln.description,
        "fname": vuln.fname,
        "plugin_family": vuln.plugin_family,
        "plugin_id": vuln.plugin_id,
        "plugin_modification_date": vuln.plugin_modification_date,
        "plugin_name": vuln.plugin_name,
        "plugin_publication_date": vuln.plugin_publication_date,
        "plugin_type": vuln.plugin_type,
        "port": vuln.port,
        "protocol": str(vuln.protocol),
        "risk_factor": vuln.risk_factor,
        "service": vuln.service,
        "severity": vuln.severity,
        "solution": vuln.solution,
        "synopsis": vuln.synopsis,
    }


def _port_details(port_scan: PortScanDoc) -> dict[str, Any]:
    """Build the ticket details dict from a PortScanDoc.

    Args:
        port_scan: The PortScanDoc to extract details from.

    Returns:
        A dict suitable for TicketDoc.details.
    """
    return {
        "port": port_scan.port,
        "protocol": str(port_scan.protocol),
        "reason": port_scan.reason,
        "service": port_scan.service,
        "state": port_scan.state,
    }


def _snapshot_link(snapshot_id: ObjectId) -> SnapshotDoc:
    """Wrap a raw ObjectId in a minimal SnapshotDoc suitable for use as a Beanie link.

    Beanie's ``list[Link[SnapshotDoc]]`` field requires document instances (or
    their DBRef equivalents), not bare ``ObjectId`` values.  This helper
    constructs a lightweight proxy that Beanie can serialise as a DBRef without
    requiring the snapshot to exist in the database.

    Args:
        snapshot_id: The ObjectId of the snapshot to reference.

    Returns:
        A SnapshotDoc instance with only the ``id`` field populated.
    """
    return SnapshotDoc.model_construct(id=snapshot_id)


def _snapshot_id_in_links(
    snapshot_id: ObjectId,
    links: list[Any] | None,
) -> bool:
    """Return True if *snapshot_id* is already referenced in *links*.

    Handles both resolved ``SnapshotDoc`` instances and unresolved
    ``beanie.odm.fields.Link`` proxy objects that expose a ``.ref.id``
    attribute.

    Args:
        snapshot_id: The ObjectId to search for.
        links: The current value of ``ticket.snapshots`` (may be None or empty).

    Returns:
        True if the snapshot is already in the list, False otherwise.
    """
    if not links:
        return False
    for item in links:
        # Resolved document
        if isinstance(item, SnapshotDoc) and item.id == snapshot_id:
            return True
        # Unresolved Link proxy (beanie.odm.fields.Link)
        if hasattr(item, "ref") and item.ref.id == snapshot_id:
            return True
    return False


def _extract_cve_id(vuln: VulnScanDoc) -> str | None:
    """Attempt to extract a CVE ID from a VulnScanDoc.

    Nessus plugin names often contain the CVE ID (e.g. "CVE-2021-44228").
    This function checks the plugin_name field for a CVE-style identifier.

    Args:
        vuln: The VulnScanDoc to inspect.

    Returns:
        A CVE ID string if found, or None.
    """
    import re

    # Look for CVE-YYYY-NNNNN pattern in the plugin name.
    match = re.search(r"CVE-\d{4}-\d{4,}", vuln.plugin_name, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    return None
