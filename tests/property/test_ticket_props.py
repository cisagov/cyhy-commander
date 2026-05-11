"""Property-based tests for VulnTicketManager ticket close invariant.

Verifies Property 5 (MR-8.5): after VulnTicketManager.process_tickets()
completes, no ticket that was absent from the detected set and has
false_positive=False remains open=True.

**Validates: Requirements MR-8.5, AC-11.5**
"""

# Standard Python Libraries
import asyncio
from datetime import datetime, timezone
from ipaddress import IPv4Address

# Third-party libraries
import beanie
import mongomock_motor
import pytest
from cyhy_db.models import KEVDoc, PortScanDoc, TicketDoc, VulnScanDoc
from cyhy_db.models.enum import Protocol, TicketAction
from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander.ticket_manager import VulnTicketManager

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP = "10.0.0.1"
_OWNER = "TEST"
_SOURCE = "nessus"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _fresh_db():
    """Create and initialise a fresh in-memory MongoDB for one test run."""
    client = mongomock_motor.AsyncMongoMockClient()
    db = client["prop_test_db"]

    all_models = [KEVDoc, PortScanDoc, TicketDoc, VulnScanDoc]

    async def _init():
        await beanie.init_beanie(database=db, document_models=all_models)

    asyncio.run(_init())
    return db


def _make_vuln(plugin_id: int, port: int = 80) -> VulnScanDoc:
    """Build an unsaved VulnScanDoc with the given plugin_id."""
    now = _utcnow()
    return VulnScanDoc(
        ip=_IP,
        ip_int=int(IPv4Address(_IP)),
        owner=_OWNER,
        source=_SOURCE,
        cvss_base_score=5.0,
        cvss_vector="AV:N/AC:L/Au:N/C:P/I:P/A:P",
        description="Test vulnerability",
        fname="test.nasl",
        plugin_family="General",
        plugin_id=plugin_id,
        plugin_modification_date=now,
        plugin_name=f"Plugin {plugin_id}",
        plugin_publication_date=now,
        plugin_type="remote",
        port=port,
        protocol=Protocol.TCP,
        risk_factor="Medium",
        service="www",
        severity=2,
        solution="Update software",
        synopsis="Test synopsis",
    )


def _make_open_ticket(plugin_id: int, port: int = 80) -> TicketDoc:
    """Build an unsaved open TicketDoc for the given plugin_id."""
    now = _utcnow()
    ticket = TicketDoc(
        details={"plugin_id": plugin_id, "severity": 2},
        false_positive=False,
        ip=IPv4Address(_IP),
        ip_int=int(IPv4Address(_IP)),
        open=True,
        owner=_OWNER,
        port=port,
        protocol=Protocol.TCP,
        source=_SOURCE,
        source_id=plugin_id,
        time_opened=now,
    )
    ticket.add_event(
        action=TicketAction.OPENED,
        reason="new vulnerability detected",
        time=now,
    )
    return ticket


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# A small pool of plugin IDs to keep the search space tractable.
_PLUGIN_IDS = list(range(1001, 1011))  # 10 distinct plugin IDs

# Strategy: a non-empty set of plugin IDs representing pre-existing tickets.
_pre_existing_ids_st = st.frozensets(
    st.sampled_from(_PLUGIN_IDS),
    min_size=1,
    max_size=len(_PLUGIN_IDS),
)

# Strategy: a (possibly empty) subset of plugin IDs representing detected vulns.
_detected_ids_st = st.frozensets(
    st.sampled_from(_PLUGIN_IDS),
    min_size=0,
    max_size=len(_PLUGIN_IDS),
)


# ---------------------------------------------------------------------------
# Property 5 (MR-8.5): Ticket close invariant
# ---------------------------------------------------------------------------


@given(
    pre_existing_ids=_pre_existing_ids_st,
    detected_ids=_detected_ids_st,
)
@settings(max_examples=200)
def test_ticket_close_invariant(
    pre_existing_ids: frozenset,
    detected_ids: frozenset,
) -> None:
    """Property MR-8.5: Ticket close invariant.

    After VulnTicketManager.process_tickets() completes, no ticket that was
    absent from the detected set and has false_positive=False remains
    open=True.

    For every pre-existing open ticket whose plugin_id is NOT in the
    detected set, the ticket must be closed (open=False) after
    process_tickets() returns — provided the ticket is not a false positive.

    **Validates: Requirements MR-8.5, AC-11.5**
    """
    _fresh_db()  # Initialise a clean in-memory DB for this test run.

    async def _run() -> None:
        # 1. Insert pre-existing open tickets (all false_positive=False).
        for pid in pre_existing_ids:
            ticket = _make_open_ticket(plugin_id=pid)
            await ticket.save()

        # 2. Build the detected-vuln list (save each VulnScanDoc first so it
        #    has a valid ObjectId for ticket event references).
        detected_vulns: list[VulnScanDoc] = []
        for pid in detected_ids:
            vuln = _make_vuln(plugin_id=pid)
            await vuln.save()
            detected_vulns.append(vuln)

        # 3. Run process_tickets.
        mgr = VulnTicketManager()
        await mgr.process_tickets(_IP, detected_vulns)

        # 4. Verify the invariant: for every pre-existing ticket whose
        #    plugin_id was NOT in the detected set, open must be False.
        absent_ids = pre_existing_ids - detected_ids
        all_tickets = await TicketDoc.find_all().to_list()

        for ticket in all_tickets:
            if ticket.source_id not in absent_ids:
                # This ticket was either detected (verified/reopened) or
                # newly opened — not subject to the close invariant.
                continue
            if ticket.false_positive:
                # False-positive tickets are intentionally left open.
                continue
            assert ticket.open is False, (
                f"Invariant violated: ticket for plugin_id={ticket.source_id} "
                f"was absent from detected set {detected_ids!r} and has "
                f"false_positive=False, but remains open=True. "
                f"pre_existing_ids={pre_existing_ids!r}, "
                f"detected_ids={detected_ids!r}"
            )

    asyncio.run(_run())
