"""Rimette in coda eventi Kraken falliti, senza duplicare quelli consegnati.

Uso tipico dopo aver corretto un payload o un errore di contratto:

    docker compose --profile kraken exec -T aegis-kraken \
        python scripts/replay_outbox.py --event-id kraken:ssh:abc:0
    docker compose --profile kraken exec -T aegis-kraken \
        python scripts/replay_outbox.py --all-failed --limit 100

Il comando cambia solo righe `failed` (o l'event_id scelto se è fallito):
riporta `attempts` a zero e `next_attempt_at` a now. Non invia nulla: il worker
normale o `process_outbox_once` eseguono la consegna, così il replay usa lo
stesso percorso e la stessa deduplicazione del Brain.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import UTC, datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import update  # noqa: E402

from app.db.session import AsyncSessionLocal  # noqa: E402
from app.models.models import Outbox  # noqa: E402


async def replay(
    *,
    event_id: str | None = None,
    all_failed: bool = False,
    limit: int = 500,
) -> int:
    if not event_id and not all_failed:
        raise SystemExit("specifica --event-id oppure --all-failed")
    now = datetime.now(UTC)
    stmt = update(Outbox).where(Outbox.status == "failed")
    if event_id:
        stmt = stmt.where(Outbox.event_id == event_id)
    stmt = stmt.values(
        status="pending",
        attempts=0,
        next_attempt_at=now,
        claimed_at=None,
        last_error=None,
    )
    async with AsyncSessionLocal() as db:
        result = await db.execute(stmt)
        await db.commit()
    return int(result.rowcount or 0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-id", help="rimetti in coda un singolo evento")
    parser.add_argument("--all-failed", action="store_true",
                        help="rimetti in coda tutti gli eventi failed")
    parser.add_argument("--limit", type=int, default=500,
                        help="massimo numero di righe da reclamare (default 500)")
    args = parser.parse_args(argv)
    if args.limit < 1 or args.limit > 5000:
        parser.error("--limit deve essere tra 1 e 5000")
    count = asyncio.run(replay(
        event_id=args.event_id,
        all_failed=args.all_failed,
        limit=args.limit,
    ))
    print(f"replay: {count} evento/i rimessi in coda")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
