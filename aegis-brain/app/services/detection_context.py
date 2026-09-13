"""Contesto arricchente per detection (Fase 4).

Raccoglie evidenze disponibili in modo puro/testabile:
- parent-child lineage già in EventSchema;
- firma/publisher (Authenticode) per pesare i trusted;
- prevalenza file (quanti host hanno visto lo stesso hash/path);
- first-seen/last-seen per il medesimo hash;
- ruolo utente (admin vs standard);
- reputazione hash/destinazione (placeholder, alimentata da OSINT cache).

Tutto best-effort: DB non disponibile o campi assenti => evidenza parziale,
mai eccezioni. La detection resta deterministica sui dati presenti.
"""
from typing import Any, Dict, Optional

# Publisher fidati (MIcrosoft) che abbassano la confidence se firmati validi.
TRUSTED_PUBLISHERS = {
    "microsoft windows",
    "microsoft corporation",
    "microsoft windows publisher",
}

# Utenti privilegiati (Windows + Linux) per flag ruolo.
PRIVILEGED_USERS = {
    "system", "nt authority\\system", "nt authority\\local service",
    "nt authority\\network service", "administrator", "root",
}

# Stati di firma emessi dal sensore (WindowsProcessMonitor: "authenticode-trusted"
# oppure "unsigned:<errore>" oppure assente). Solo uguaglianza esatta conta:
# il match per sottostringa scambiava "untrusted"/"distrusted" per trusted (audit).
TRUSTED_SIGNATURE_STATES = frozenset({"authenticode-trusted"})

def is_trusted_signed(event: Any) -> bool:
    """True se firma valida E publisher fidato (entrambi match esatto).

    Niente fallback su file_hash (un hash identifica, non certifica) e niente
    substring ("evil microsoft corporation" non e' Microsoft).
    """
    sig = (getattr(event, "signature", None) or "")
    publisher = (getattr(event, "publisher", None) or "")
    sig_s = str(sig).lower().strip()
    pub_s = str(publisher).lower().strip()
    return sig_s in TRUSTED_SIGNATURE_STATES and pub_s in TRUSTED_PUBLISHERS

def user_role(event: Any) -> str:
    """Ruolo inferito dal nome utente (privileged vs standard). Puro."""
    user = (getattr(event, "user", None) or "")
    if str(user).lower().strip() in PRIVILEGED_USERS:
        return "privileged"
    return "standard"

def build_evidence(event: Any, triggered: list, ctx: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Evidenza strutturata per ogni detection (evidence first, no marker)."""
    ctx = ctx or {}
    ev = {
        "process": {
            "name": getattr(event, "process_name", None),
            "path": getattr(event, "process_path", None),
            "pid": getattr(event, "pid", None),
            "parent": getattr(event, "parent_process_name", None),
            "parent_pid": getattr(event, "parent_pid", None),
            "user": getattr(event, "user", None),
            "role": user_role(event),
            "cmdline": getattr(event, "command_line", None) or getattr(event, "process_path", None),
        },
        "identity": {
            "signature": getattr(event, "signature", None),
            "publisher": getattr(event, "publisher", None),
            "trusted": is_trusted_signed(event),
            "hash": getattr(event, "file_hash", None),
        },
        "network": {
            "connections": getattr(event, "network_connections", None),
            "proto": getattr(event, "proto", None),
            "direction": getattr(event, "direction", None),
        },
        "provenance": {
            "provenance": getattr(event, "provenance", None),
            "quality": getattr(event, "quality", None),
            "sampling": getattr(event, "sampling", None),
        },
        "rules": [
            {
                "id": getattr(r, "rule_id", "unknown"),
                "version": getattr(r, "version", "1.0"),
                "severity": getattr(r, "severity", "LOW"),
                "confidence": getattr(r, "confidence", "medium"),
                "description": getattr(r, "description", ""),
                "mitre": getattr(r, "mitre_technique_id", None),
            }
            for r in triggered
        ],
        "prevalence": ctx.get("prevalence"),
        "first_seen": ctx.get("first_seen"),
        "last_seen": ctx.get("last_seen"),
        "reputation": ctx.get("reputation"),
    }
    # Compattezza: rimuove None top-level, non dentro process/identity.
    return {k: v for k, v in ev.items() if v is not None}

async def fetch_context(db, event) -> Dict[str, Any]:
    """Arricchimento best-effort da DB (prevalenza, first/last seen).

    Se il DB è assente o la query fallisce, ritorna {} (nessun blocco).
    Per pilot 100 host usiamo proxy process_name (tabella dedicata hash in
    futuro)."""
    ctx: Dict[str, Any] = {}
    try:
        from sqlalchemy import select, func
        from app.database.models import Alert

        proc = getattr(event, "process_name", "") or ""
        if proc:
            result = await db.execute(
                select(func.count(Alert.id)).where(Alert.process_name == proc)
            )
            count = result.scalar() or 0
            # prevalence solo se abbiamo anche un hash/path per distinguere
            file_hash = getattr(event, "file_hash", None)
            ctx["prevalence"] = {"process": proc, "seen_count": int(count), "hash": file_hash}
            first = await db.execute(
                select(Alert.timestamp).where(Alert.process_name == proc).order_by(Alert.timestamp.asc()).limit(1)
            )
            row = first.scalars().first()
            if row:
                ctx["first_seen"] = row.isoformat() if hasattr(row, "isoformat") else str(row)
            last = await db.execute(
                select(Alert.timestamp).where(Alert.process_name == proc).order_by(Alert.timestamp.desc()).limit(1)
            )
            row2 = last.scalars().first()
            if row2:
                ctx["last_seen"] = row2.isoformat() if hasattr(row2, "isoformat") else str(row2)
    except Exception:
        pass
    return ctx
