"""Property-based tests for job sizing bounds.

Verifies Property 4 (MR-8.4): for any configured limit >= 1,
fetch_ready_hosts(count=limit, ...) never returns more than limit hosts,
regardless of how many READY hosts exist in the database.

**Validates: Requirements MR-8.4, AC-11.4**
"""

import asyncio

import beanie
import mongomock_motor
from cyhy_db.models import HostDoc
from cyhy_db.models.enum import Stage, Status
from hypothesis import given, settings
from hypothesis import strategies as st

from cyhy_commander import db_ops


def _fresh_db():
    """Create and initialise a fresh in-memory MongoDB."""
    client = mongomock_motor.AsyncMongoMockClient()
    db = client["prop_job_sizing_db"]

    _orig = db.delegate.list_collection_names

    def _patched(*args, **kwargs):
        kwargs.pop("authorizedCollections", None)
        kwargs.pop("nameOnly", None)
        return _orig(*args, **kwargs)

    db.delegate.list_collection_names = _patched

    async def _init():
        await beanie.init_beanie(database=db, document_models=[HostDoc])

    asyncio.run(_init())
    return db


@given(
    host_count=st.integers(min_value=0, max_value=300),
    limit=st.integers(min_value=1, max_value=256),
)
@settings(max_examples=50, deadline=None)
def test_fetch_ready_hosts_never_exceeds_limit(
    host_count: int, limit: int
) -> None:
    """fetch_ready_hosts returns at most `limit` hosts."""
    _fresh_db()

    async def _run():
        await HostDoc.delete_all()

        for i in range(host_count):
            host = HostDoc(
                ip=f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}",
                owner="TEST",
                stage=Stage.NETSCAN1,
                status=Status.READY,
                priority=0,
            )
            await host.save()

        result = await db_ops.fetch_ready_hosts(
            count=limit, stage=Stage.NETSCAN1
        )
        assert len(result) <= limit

    asyncio.run(_run())
