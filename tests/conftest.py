"""Shared pytest fixtures for cyhy-commander tests.

Provides an in-memory async MongoDB fixture using mongomock-motor and Beanie,
suitable for unit tests that exercise database-backed business logic without
requiring a real MongoDB instance.

Requirements: AC-8.3, AC-8.4
"""

import asyncio

import beanie
import mongomock_motor
import pytest
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

# All document models that Beanie needs to register.
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


@pytest.fixture
def mock_db():
    """Provide an initialised in-memory async MongoDB via mongomock-motor.

    Each test gets a fresh database with all Beanie document models
    registered.  The fixture is synchronous so it can be used from both
    sync and async test functions via ``asyncio.run()``.

    Usage in a test::

        def test_something(mock_db):
            async def _run():
                # Beanie models are ready to use here
                ticket = TicketDoc(...)
                await ticket.save()
            asyncio.run(_run())
    """
    client = mongomock_motor.AsyncMongoMockClient()
    db = client["test_db"]

    async def _init():
        await beanie.init_beanie(
            database=db, document_models=_ALL_DOCUMENT_MODELS
        )

    asyncio.run(_init())
    yield db
