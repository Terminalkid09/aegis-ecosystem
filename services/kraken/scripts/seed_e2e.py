"""Create a fresh deterministic Kraken event for the compose E2E.

Run inside the Kraken container after the stack is healthy:

    docker compose --profile kraken exec -T aegis-kraken \
        python scripts/seed_e2e.py

The Playwright Kraken vertical looks for ``203.0.113.77`` in the Aegis
read-only view and in the Kraken UI. Demo data is random and may be older than
the 24-hour window, so the gate must create its own recent event. The event is
written through the normal service path, which also queues the signed outbox
delivery to the Brain.
"""
from __future__ import annotations

import asyncio
import os
import sys
from uuid import uuid4

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import AsyncSessionLocal
from app.schemas.schemas import SensorEventIn
from app.services.attack_service import ingest_sensor_event
from app.services.outbox import process_outbox_once

E2E_ATTACKER_IP = "203.0.113.77"


async def seed() -> None:
    payload = SensorEventIn(
        sensor_type="ssh",
        attacker_ip=E2E_ATTACKER_IP,
        attacker_port=51234,
        sensor_port=2222,
        session_id=f"e2e-phase0-{uuid4().hex[:12]}",
        username="e2e-admin",
        commands=["id"],
    )
    async with AsyncSessionLocal() as db:
        event = await ingest_sensor_event(db, payload)
        print(f"created Kraken event {event.id} from {E2E_ATTACKER_IP}")

    # Drain immediately instead of waiting for the worker's poll interval. If
    # the worker already claimed the row, process_outbox_once reports zero and
    # the event is still delivered by the worker.
    summary = await process_outbox_once()
    print(f"outbox drain: {summary}")
    if summary.get("failed"):
        raise SystemExit("Kraken event created but outbox delivery failed")


if __name__ == "__main__":
    asyncio.run(seed())
