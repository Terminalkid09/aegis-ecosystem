"""Policy di rischio e triage: quando creare alert vs log-only, muting post-resolve."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Optional

from app.services.detection_context import is_signed_verified

# Regole rumorose su binari Authenticode validi: log-only, niente alert SOC.
TRUSTED_SUPPRESS_RULE_IDS = frozenset({
    "AEGIS-S004",  # user-writable path (VS Code portable, installer in Downloads)
    "AEGIS-S009",
    "AEGIS-S010",
    "AEGIS-S012",
    "AEGIS-S014",
})

# Basename noti: path user-writable + firmati = rumore dev workstation (non alert).
_KNOWN_SIGNED_APP_NAMES = frozenset({
    "code.exe", "code - insiders.exe", "cursor.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "slack.exe", "discord.exe", "teams.exe", "zoom.exe",
    "devenv.exe", "idea64.exe", "pycharm64.exe", "webstorm64.exe",
    "spotify.exe", "steam.exe", "discordptb.exe",
})


def _basename(name: Optional[str]) -> str:
    if not name:
        return ""
    n = name.replace("\\", "/").lower().strip()
    return n.rsplit("/", 1)[-1]


def should_skip_trusted_noisy_rule(rule_id: str, rule_result: Any, event: Any) -> bool:
    """True => regola ha matchato ma non deve contribuire a un alert."""
    if rule_id not in TRUSTED_SUPPRESS_RULE_IDS:
        return False
    if not is_signed_verified(event):
        return False
    conf = getattr(rule_result, "confidence", None) or "medium"
    return conf == "low"


def should_skip_known_signed_app_path(event: Any, rule_id: str) -> bool:
    """IDE/browser firmati da Downloads/AppData: S004/S014 path-only."""
    if rule_id not in ("AEGIS-S004", "AEGIS-S014"):
        return False
    if not is_signed_verified(event):
        return False
    base = _basename(getattr(event, "process_name", None) or getattr(event, "process_path", None))
    return base in _KNOWN_SIGNED_APP_NAMES


def triage_mute_fingerprint(alert: Any) -> str:
    """Chiave stabile per 'l'analista ha chiuso questo tipo di rumore'."""
    parts = [
        (getattr(alert, "event_type", None) or "unknown").lower(),
        _basename(getattr(alert, "process_name", None)),
    ]
    ev = getattr(alert, "evidence", None)
    if isinstance(ev, dict):
        rules = ev.get("rules") or []
        ids = sorted(
            str(r.get("id"))
            for r in rules
            if isinstance(r, dict) and r.get("id")
        )
        if ids:
            parts.append(",".join(ids))
        identity = ev.get("identity") if isinstance(ev.get("identity"), dict) else {}
        fh = identity.get("hash") or ev.get("file_hash")
        if fh:
            parts.append(str(fh)[:32])
        # `type` e' il nome del rilevatore NodeTrace, `tag` quello del Guard:
        # senza uno dei due il fingerprint cade su event_type+tipo di processo
        # e il resolve silenzierebbe TUTTE le anomalie di quell'host.
        tag = ev.get("tag") or ev.get("type")
        if tag:
            parts.append(str(tag))
        # Anomalie statistiche: la metrica distingue CPU da rete da disco.
        if ev.get("metric"):
            parts.append(str(ev["metric"]))
    else:
        mitre = getattr(alert, "mitre_technique_id", None)
        if mitre:
            parts.append(str(mitre))
    raw = "|".join(p for p in parts if p)
    if len(raw) > 200:
        raw = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]
    safe = re.sub(r"[^a-zA-Z0-9_|,.:-]", "_", raw)
    return safe[:220] or "generic"
