"""Chiavi API delle integrazioni (provider OSINT): env -> override DB.

Perché esiste
-------------
Le chiavi Shodan/AbuseIPDB/VirusTotal vivevano solo nell'env, lette a import
time: cambiarle richiedeva modificare .env e riavviare il container. Ora sono
configurabili dalla dashboard (tabella `integration_settings`, cifrate con il
KEK), e la UI costruisce i suoi campi **dinamicamente** dal catalogo che questo
modulo dichiara: aggiungere un provider qui lo fa comparire in UI senza
toccare il frontend.

Precedenza: l'env vince sull'override DB (12-factor: il .env resta la fonte
di verità operativa); il DB serve quando non vuoi toccare il .env o riavviare
il container. In UI l'origine è dichiarata (`env` / `database` / `not set`).
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import encrypt_value, decrypt_value
from app.database.models import IntegrationSetting


class ProviderSpec:
    """Dichiarazione di un provider: la UI genera il campo da qui."""

    def __init__(self, key: str, label: str, env_var: str, help_text: str,
                 docs_url: str, optional: bool = True):
        self.key = key
        self.label = label
        self.env_var = env_var
        self.help_text = help_text
        self.docs_url = docs_url
        self.optional = optional


# Catalogo: una riga qui = un campo in UI. Le chiavi gestite oggi.
PROVIDERS: Dict[str, ProviderSpec] = {
    spec.key: spec
    for spec in (
        ProviderSpec(
            key="shodan", label="Shodan", env_var="SHODAN_API_KEY",
            help_text="IP enrichment: ISP, organization, geolocation, exposed ports.",
            docs_url="https://account.shodan.io/",
        ),
        ProviderSpec(
            key="abuseipdb", label="AbuseIPDB", env_var="ABUSEIPDB_API_KEY",
            help_text="IP reputation: abuse confidence score and reports.",
            docs_url="https://www.abuseipdb.com/account/api",
        ),
        ProviderSpec(
            key="virustotal", label="VirusTotal", env_var="VIRUSTOTAL_API_KEY",
            help_text="IP/domain reputation: community analysis and sentiment.",
            docs_url="https://www.virustotal.com/gui/my-apikey",
        ),
        ProviderSpec(
            key="gemini", label="Google Gemini (AI)", env_var="GEMINI_API_KEY",
            help_text=("AI API key (free tier): alert summaries and analysis WITHOUT a local "
                       "LLM container. Anonymized data leaves the network only when you ask "
                       "for it, unless automatic enrichment is enabled."),
            docs_url="https://aistudio.google.com/apikey",
        ),
        ProviderSpec(
            key="openai", label="OpenAI / compatible", env_var="OPENAI_API_KEY",
            help_text=("Key for any OpenAI-compatible endpoint (OPENAI_BASE_URL: OpenAI, "
                       "Azure, vLLM, LM Studio, your own server...)."),
            docs_url="https://platform.openai.com/api-keys",
        ),
        ProviderSpec(
            key="telegram_bot_token", label="Telegram Bot Token",
            env_var="TELEGRAM_BOT_TOKEN",
            help_text=("Token of the Telegram bot for alert notifications (from @BotFather). "
                       "Paste it WHOLE: the full format is '123456789:ABCdef...' — the part "
                       "after the colon matters, it is not optional. Then pair a chat_id in "
                       "Telegram Notifications (use the Detect button there); alerts at or "
                       "above your chosen minimum severity and the heartbeat are delivered "
                       "even when the dashboard is closed."),
            docs_url="https://core.telegram.org/bots/tutorial#obtain-your-bot-token",
        ),
    )
}


def _env_value(spec: ProviderSpec) -> str:
    return (getattr(settings, spec.env_var, "") or "").strip()


def _placeholder(v: str) -> bool:
    return (not v) or v.startswith("your_") or v == "replace-with"


def _db_row(db: AsyncSession, key: str) -> Optional[IntegrationSetting]:
    return db.get(IntegrationSetting, key)


async def get_provider_status(db: AsyncSession) -> list[Dict[str, Any]]:
    """Stato di tutti i provider: la UI costruisce i campi da questo elenco.

    Non restituisce MAI la chiave: al massimo il mascheramento (`sha…39f1`
    prime 3 + ultime 4) per far riconoscere all'operatore quale chiave è
    attiva senza esporla.
    """
    out = []
    for spec in PROVIDERS.values():
        env_val = _env_value(spec)
        row = await _db_row(db, spec.key)
        db_val = ""
        if row:
            try:
                db_val = decrypt_value(row.value_encrypted).strip()
            except Exception:
                db_val = ""
        if _placeholder(env_val):
            env_val = ""
        if _placeholder(db_val):
            db_val = ""

        if env_val:
            source, active, masked = "env", True, _mask(env_val)
        elif db_val:
            source, active, masked = "database", True, _mask(db_val)
        else:
            source, active, masked = "not set", False, ""
        out.append({
            "key": spec.key,
            "label": spec.label,
            "env_var": spec.env_var,
            "help_text": spec.help_text,
            "docs_url": spec.docs_url,
            "source": source,        # env | database | not set
            "active": active,
            "masked": masked,        # mai la chiave piena
            "overridable": not env_val,  # se c'è l'env, il DB non conta
        })
    return out


def _mask(v: str) -> str:
    # ASCII puro di proposito: la maschera finisce in log e console Windows,
    # dove un carattere non-ASCII (es. ellisse) viene mostrato come mojibake
    # e fa sembrare corrotta una chiave che e' integra.
    if len(v) <= 8:
        return "****"
    return f"{v[:3]}...{v[-4:]}"


async def get_key(db: AsyncSession, key: str) -> str:
    """Chiave effettiva per un provider: env vince, poi DB, poi vuoto."""
    spec = PROVIDERS.get(key)
    if spec is None:
        return ""
    env_val = _env_value(spec)
    if not _placeholder(env_val):
        return env_val
    row = await _db_row(db, key)
    if not row:
        return ""
    try:
        db_val = decrypt_value(row.value_encrypted).strip()
    except Exception:
        return ""
    return "" if _placeholder(db_val) else db_val


async def get_key_with_origin(db: AsyncSession, key: str) -> tuple[str, str]:
    """Chiave + origine ('env' | 'database' | '') per la UI."""
    spec = PROVIDERS.get(key)
    if spec is None:
        return "", ""
    env_val = _env_value(spec)
    if not _placeholder(env_val):
        return env_val, "env"
    row = await _db_row(db, key)
    if not row:
        return "", ""
    try:
        db_val = decrypt_value(row.value_encrypted).strip()
    except Exception:
        return "", ""
    if _placeholder(db_val):
        return "", ""
    return db_val, "database"


async def set_key(db: AsyncSession, key: str, value: str,
                  updated_by: Optional[int]) -> bool:
    """Scrive (o cancella con value='') l'override DB, cifrato."""
    if key not in PROVIDERS:
        return False
    value = (value or "").strip()
    row = await _db_row(db, key)
    if not value:
        if row:
            await db.delete(row)
        return True
    if row:
        row.value_encrypted = encrypt_value(value)
        row.updated_by = updated_by
    else:
        db.add(IntegrationSetting(key=key, value_encrypted=encrypt_value(value),
                                  updated_by=updated_by))
    return True
