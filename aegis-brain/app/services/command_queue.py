"""Coda comandi agente: FIFO, bounded, senza perdite silenziose.

Prima ogni producer faceva `RPUSH` seguito da `LTRIM 0 99`: a coda piena il
trim conservava i 100 comandi PIU' VECCHI e scartava quello appena inserito,
mentre il chiamante rispondeva "completed". Per un playbook di contenimento
questo significa dichiarare eseguita un'azione che l'agente non ricevera' mai.

Qui il comando viene rifiutato con `queue_full` prima dell'inserimento. Il
`LTRIM -limit -1` resta come rete di sicurezza per un race tra LLEN e RPUSH:
mantiene i PIU' RECENTI, coerente con RPUSH + LPOP.
"""
from __future__ import annotations

import json
from typing import Any, Dict


def command_queue_name(agent_id: Any) -> str:
    return f"aegis:commands:{agent_id}"


async def enqueue_command(
    client,
    agent_id: Any,
    command: Dict[str, Any],
    *,
    max_length: int | None = None,
) -> Dict[str, Any]:
    """Accoda un comando o restituisce `queued=False` a coda piena.

    `client` e' un client Redis asincrono (reale o fake nei test). Il chiamante
    decide se il fallimento e' un 503 o un esito `failed` del playbook.
    """
    from app.core.config import settings

    limit = max(1, int(max_length or settings.COMMAND_QUEUE_MAX))
    queue = command_queue_name(agent_id)
    depth = int(await client.llen(queue))
    if depth >= limit:
        try:
            from app.core.metrics import inc
            inc("aegis_commands_dropped_total", 1, 'reason="queue_full"')
        except Exception:
            pass
        return {"queued": False, "reason": "queue_full", "depth": depth, "limit": limit}

    await client.rpush(queue, json.dumps(command))
    # Race LLEN/RPUSH: se due producer superano il controllo, il trim tiene i
    # comandi piu' recenti invece di quelli piu' vecchi.
    await client.ltrim(queue, -limit, -1)
    return {"queued": True, "depth": min(depth + 1, limit), "limit": limit}
