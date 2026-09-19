"""Impostazioni di deployment editabili dalla dashboard (valori non segreti).

Perché esiste
-------------
Provider AI, modello e comportamento dell'arricchimento automatico erano
fissati nel `.env`: cambiarli voleva dire modificare un file e riavviare il
container. Per un parametro che si sceglie in base a cosa sta girando sulla
macchina (un Ollama locale? una chiave Gemini? niente AI?) è il posto
sbagliato: ora si scelgono dalla UI e valgono subito.

Perché NON in `integration_settings`: quella tabella è cifrata e maschera i
valori, perché contiene chiavi API. Qui i valori sono leggibili per scelta
(debug, supporto, display in dashboard).

Precedenza — una regola per chiave, dichiarata e non dedotta
-----------------------------------------------------------
  ai.provider          env ESPLICITO (≠ "auto", ≠ vuoto) > DB > "auto"
  ai.model             env AI_MODEL non vuoto > DB > "" (default del provider)
  ai.automatic_enrich  DB > env AI_AUTOMATIC_ENRICH

L'env vince dove esprime una scelta; `AI_PROVIDER=auto` è il default del
compose, non una scelta, e non deve bloccare la dashboard (altrimenti il
selettore in UI sarebbe decorativo). `ai.automatic_enrich` fa eccezione:
l'env non può distinguere "false esplicito" da "false di default", quindi il
valore in DB, quando c'è, vince — ed è il comportamento che l'operatore si
aspetta da un interruttore che ha appena mosso.

Il default di `AI_AUTOMATIC_ENRICH` è **false**: nessun contenuto di alert
lascia la rete verso un provider cloud senza che qualcuno lo abbia scelto.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.database.models import AppSetting


# Provider selezionabili. "auto" = usa ciò che risponde davvero.
AI_PROVIDERS = ("auto", "disabled", "ollama", "gemini", "openai")
LOCAL_PROVIDERS = frozenset({"ollama"})
CLOUD_PROVIDERS = frozenset({"gemini", "openai"})

# Labels shown in the dashboard: English, like the rest of the UI.
PROVIDER_LABELS: Dict[str, str] = {
    "auto": "Auto (use whatever responds)",
    "disabled": "Disabled",
    "ollama": "Ollama (local or your own server)",
    "gemini": "Google Gemini (cloud)",
    "openai": "OpenAI / OpenAI-compatible (cloud)",
}

# Chiavi gestite. Una riga qui = un campo in UI.
KEY_PROVIDER = "ai.provider"
KEY_MODEL = "ai.model"
KEY_AUTOMATIC = "ai.automatic_enrich"

# Notifiche Telegram (non segrete: il bot token sta in integration_settings).
KEY_TG_ENABLED = "telegram.enabled"
KEY_TG_CHAT = "telegram.chat_id"
KEY_TG_MIN_SEV = "telegram.min_severity"
KEY_TG_HEARTBEAT = "telegram.heartbeat_minutes"
TELEGRAM_KEYS = (KEY_TG_ENABLED, KEY_TG_CHAT, KEY_TG_MIN_SEV, KEY_TG_HEARTBEAT)
AI_KEYS = (KEY_PROVIDER, KEY_MODEL, KEY_AUTOMATIC)

MAX_VALUE_LEN = 200


def default_models() -> Dict[str, str]:
    """Modello di default per provider (mostrato in UI come placeholder)."""
    return {
        "ollama": settings.OLLAMA_DEFAULT_MODEL,
        "gemini": settings.GEMINI_MODEL,
        "openai": settings.OPENAI_MODEL,
    }


def validate_provider(value: str) -> bool:
    return value in AI_PROVIDERS


# ------------------------------------------------------------------ storage

async def get_value(db: AsyncSession, key: str) -> Optional[str]:
    """Valore dal DB, o None se mai impostato (distinto da '')."""
    if key not in AI_KEYS and key not in TELEGRAM_KEYS:
        return None
    row = await db.get(AppSetting, key)
    return None if row is None else (row.value or "")


async def set_value(db: AsyncSession, key: str, value: str,
                    updated_by: Optional[int] = None) -> bool:
    """Upsert. Stringa vuota = rimuove la riga (torna al default/env).

    Il chiamante committa: qui non si decide la transazione.
    """
    if key not in AI_KEYS and key not in TELEGRAM_KEYS:
        return False
    value = (value or "").strip()[:MAX_VALUE_LEN]
    row = await db.get(AppSetting, key)
    if not value:
        if row is not None:
            await db.delete(row)
        return True
    if row is not None:
        row.value = value
        row.updated_by = updated_by
    else:
        db.add(AppSetting(key=key, value=value, updated_by=updated_by))
    return True


# ------------------------------------------------------------------ telegram

_TG_CACHE: Dict[str, str] = {}


def invalidate_telegram_cache() -> None:
    _TG_CACHE.clear()


def get_cached(key: str) -> Optional[str]:
    """Valore telegram dalla cache del notifier (popolata lazy).

    Il notifier gira nel request path dell'ingest: non puo' fare una query per
    alert. La cache e' popolata al primo accesso e invalidata dalla UI (PUT
    /telegram/settings -> invalidate_cache).
    """
    return _TG_CACHE.get(key)


async def refresh_telegram_cache(db: AsyncSession) -> None:
    """Ricarica i valori telegram dal DB nella cache del notifier."""
    _TG_CACHE.clear()
    for key in TELEGRAM_KEYS:
        val = await get_value(db, key)
        if val is not None:
            _TG_CACHE[key] = val


async def get_value_with_origin(db: AsyncSession, key: str,
                                default: str = "") -> tuple[str, str]:
    """Valore + origine ('database' | 'default') per la UI."""
    val = await get_value(db, key)
    if val is not None and val != "":
        return val, "database"
    return default, "default"


# ------------------------------------------------------------------ resolve

def _env_provider_explicit() -> str:
    """Provider scelto esplicitamente nell'env (auto/vuoto = non è una scelta)."""
    v = (getattr(settings, "AI_PROVIDER", "") or "").strip().lower()
    return "" if v in ("", "auto") else v


def _env_model() -> str:
    return (getattr(settings, "AI_MODEL", "") or "").strip()


async def resolve_ai(db: AsyncSession) -> Dict[str, Any]:
    """Provider/modello/auto-enrich effettivi + l'origine di ciascuno.

    L'origine (`*_source`) è esposta dalla UI: l'operatore deve sapere se sta
    guardando un valore scelto dalla dashboard o imposto dal `.env`, invece di
    cambiare un campo e non capire perché non ha effetto.
    """
    db_provider = await get_value(db, KEY_PROVIDER)
    db_model = await get_value(db, KEY_MODEL)
    db_auto = await get_value(db, KEY_AUTOMATIC)

    env_provider = _env_provider_explicit()
    if env_provider:
        provider, provider_source = env_provider, "env"
    elif db_provider:
        provider, provider_source = db_provider.lower(), "database"
    else:
        provider, provider_source = "auto", "default"

    env_model = _env_model()
    if env_model:
        model, model_source = env_model, "env"
    elif db_model:
        model, model_source = db_model, "database"
    else:
        model, model_source = "", "default"

    if db_auto is not None:
        automatic = db_auto.strip().lower() in ("1", "true", "yes", "on")
        automatic_source = "database"
    else:
        automatic = bool(getattr(settings, "AI_AUTOMATIC_ENRICH", False))
        automatic_source = "env"

    return {
        "provider": provider,
        "provider_source": provider_source,
        "model": model,
        "model_source": model_source,
        "automatic_enrich": automatic,
        "automatic_source": automatic_source,
        "cloud": provider in CLOUD_PROVIDERS,
        "local": provider in LOCAL_PROVIDERS,
    }


async def settings_payload(db: AsyncSession) -> Dict[str, Any]:
    """Tutto ciò che serve alla UI per disegnare la sezione AI."""
    current = await resolve_ai(db)
    return {
        "current": current,
        "providers": [
            {"value": p, "label": PROVIDER_LABELS[p]} for p in AI_PROVIDERS
        ],
        "default_models": default_models(),
        "cloud_providers": sorted(CLOUD_PROVIDERS),
    }
