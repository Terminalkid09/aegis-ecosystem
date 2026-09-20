"""OCSF (Open Cybersecurity Schema Framework) export — mappatura schema.

Perché esiste questo modulo: un EDR/SIEM che non parla OCSF obbliga ogni
cliente a scrivere un parser custom prima di poter portare i propri dati in
Splunk, Elastic, AWS Security Lake, Microsoft Sentinel o in un altro SIEM.
OCSF 1.4.0 è lo schema che questi prodotti ingeriscono nativamente. Esporre
qui la conversione significa che l'aggancio a un SIEM reale è una pipeline
(configurazione), non un progetto di integrazione da mesi.

Mappa:
  Alert   → Detection Finding  (class_uid 2004, category_uid 2 Findings)
  evento  → Process Activity   (class_uid 1007, category_uid 1 System Activity)

Tutto è funzione pura e deterministica: nessun DB, nessuna rete, nessun tempo
se non quello dell'evento. Testabile con un dizionario.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

OCSF_VERSION = "1.4.0"

# metadata.product: identifica chi ha prodotto il finding. Serve al SIEM per
# attribuire la detection al vendor giusto (richiesto da OCSF).
PRODUCT = {
    "name": "Aegis Brain",
    "vendor_name": "Aegis Ecosystem",
    "version": "4.0.0",
    "feature": {"name": "Static + behavioral detection"},
}

# OCSF Severity ID: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High,
# 5 Critical, 6 Fatal.
_SEVERITY_IDS = {
    "INFO": 1, "INFORMATIONAL": 1, "LOW": 2, "MEDIUM": 3,
    "HIGH": 4, "CRITICAL": 5, "FATAL": 6,
}
_SEVERITY_NAMES = {
    0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium",
    4: "High", 5: "Critical", 6: "Fatal",
}

# OCSF Status ID: 1 New, 2 In Progress, 3 Suppressed, 4 Resolved.
_STATUS_NEW = 1
_STATUS_RESOLVED = 4

# OCSF Activity ID per Process Activity (class 1007): 1 Launch, 2 Terminate,
# 3 Open, 4 Inject, 5 Set Attribute, 6 Other.
_ACTIVITY_LAUNCH = 1
_ACTIVITY_TERMINATE = 2
_ACTIVITY_OTHER = 6


def severity_to_ocsf(severity: Optional[str]) -> int:
    """Stringa Aegis → OCSF Severity ID (0 se sconosciuta, mai eccezione)."""
    return _SEVERITY_IDS.get((severity or "").strip().upper(), 0)


def _iso(value: Any) -> str:
    """Datetime → RFC3339 UTC. OCSF richiede `time` in millisecondi epoch e
    `time_dt` in ISO, quindi produciamo entrambi."""
    if value is None:
        value = datetime.now(timezone.utc)
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        # Epoch (secondi o millisecondi) → ISO UTC.
        seconds = value / 1000 if value >= 1e11 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _epoch_ms(value: Any) -> int:
    if value is None:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    if isinstance(value, (int, float)):
        return int(value * 1000 if value < 1e11 else value)
    try:
        if getattr(value, "tzinfo", None) is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp() * 1000)
    except Exception:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _os_object(os_type: Optional[str]) -> Dict[str, Any]:
    """OCSF device.os: name/platform. Normalizza i nomi usati dagli agenti."""
    low = (os_type or "").strip().lower()
    if not low:
        return {}
    platform = "Windows" if "win" in low else \
        "Linux" if ("linux" in low or "deb" in low or "ubuntu" in low) else \
        "macOS" if ("mac" in low or "darwin" in low) else \
        "Android" if "android" in low else \
        "iOS" if "ios" in low else low
    return {"name": platform, "type": low}


def _device(agent: Any) -> Dict[str, Any]:
    if agent is None:
        return {}
    hostname = getattr(agent, "hostname", None)
    ip = getattr(agent, "ip_address", None)
    os_type = getattr(agent, "os_type", None)
    device: Dict[str, Any] = {
        "hostname": hostname,
        "uid": str(getattr(agent, "agent_id", "") or ""),
        "type_id": 1,  # 1 = Server/Endpoint (OCSF Device type: generico host)
        "type": "Endpoint",
    }
    if ip:
        device["ip"] = ip
    os_obj = _os_object(os_type)
    if os_obj:
        device["os"] = os_obj
    version = getattr(agent, "agent_version", None)
    if version:
        device["agent_list"] = [{
            "name": "aegis-agent", "version": version,
            "type_id": 1, "type": "Endpoint Detection and Response",
        }]
    return {k: v for k, v in device.items() if v not in (None, "")}


def _attacks(alert: Any) -> List[Dict[str, Any]]:
    """MITRE ATT&CK → OCSF `attacks[]` (technique.uid = Txxxx)."""
    tid = getattr(alert, "mitre_technique_id", None)
    tname = getattr(alert, "mitre_technique_name", None)
    tactic_id = getattr(alert, "mitre_tactic_id", None)
    tactic_name = getattr(alert, "mitre_tactic_name", None)
    if not (tid or tactic_id):
        return []
    attack: Dict[str, Any] = {}
    if tid:
        attack["technique"] = {"uid": tid, "name": tname or tid}
    if tactic_id or tactic_name:
        attack["tactic"] = {"uid": tactic_id or "", "name": tactic_name or (tactic_id or "")}
    return [attack]


def alert_to_ocsf(alert: Any, agent: Any = None) -> Dict[str, Any]:
    """Alert Aegis → OCSF Detection Finding (class_uid 2004).

    Accetta un oggetto con attributi (ORM) o un dict: la funzione non assume
    SQLAlchemy, così è testabile e riusabile in un worker esterno.
    """
    def g(name: str, default: Any = None) -> Any:
        if isinstance(alert, dict):
            return alert.get(name, default)
        return getattr(alert, name, default)

    sev_id = severity_to_ocsf(g("severity"))
    resolved = bool(g("is_resolved", False))
    alert_id = g("id")

    finding_info: Dict[str, Any] = {
        "title": g("description") or g("process_name") or "Aegis detection",
        "uid": str(alert_id),
        "types": ["Detection Finding"],
    }
    tid = g("mitre_technique_id")
    if tid:
        finding_info["analytic"] = {"name": "static-rule", "type_id": 1, "type": "Rule"}
        finding_info["related_analytics"] = [{
            "name": g("description") or "aegis-rule",
            "uid": tid, "type_id": 1, "type": "Rule",
        }]

    process: Dict[str, Any] = {}
    if g("process_name"):
        process["name"] = g("process_name")
    if g("pid") is not None:
        process["pid"] = g("pid")
    if g("process_path"):
        process["file"] = {"path": g("process_path"), "name": g("process_name")}
    if g("parent_pid") is not None or g("parent_process_name"):
        process["parent_process"] = {
            k: v for k, v in {
                "pid": g("parent_pid"),
                "name": g("parent_process_name"),
            }.items() if v is not None
        }

    ocsf: Dict[str, Any] = {
        "metadata": {
            "version": OCSF_VERSION,
            "product": PRODUCT,
            "event_code": "aegis.alert",
            "log_name": "Aegis Alerts",
            "log_provider": PRODUCT["vendor_name"],
            "uid": f"aegis-alert-{alert_id}",
        },
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,  # activity 1 within class 2004
        "type_name": "Detection Finding: Create",
        "severity_id": sev_id,
        "severity": _SEVERITY_NAMES.get(sev_id, "Unknown"),
        "time": _epoch_ms(g("timestamp")),
        "time_dt": _iso(g("timestamp")),
        "status_id": _STATUS_RESOLVED if resolved else _STATUS_NEW,
        "status": "Resolved" if resolved else "New",
        "is_alert": True,
        "finding_info": finding_info,
        "device": _device(agent),
        "timezone_offset": 0,
    }
    if process:
        ocsf["actor"] = {"process": process}
    attacks = _attacks(alert)
    if attacks:
        ocsf["attacks"] = attacks
    # Dati Aegis-specifici che non hanno un campo OCSF 1:4: vanno in `unmapped`
    # (lo schema prevede esplicitamente un contenitore per l'extra vendor).
    ocsf["unmapped"] = {
        "aegis": {
            "event_type": g("event_type"),
            "agent_id": str(g("agent_id") or ""),
            "resolved": resolved,
        }
    }
    if agent is not None:
        ocsf["unmapped"]["aegis"]["hostname"] = getattr(agent, "hostname", None)
    return ocsf


def _activity_from_event_type(event_type: Optional[str]) -> Dict[str, Any]:
    et = (event_type or "").upper()
    if any(k in et for k in ("TERMINATE", "EXIT", "KILL", "STOP")):
        return {"activity_id": _ACTIVITY_TERMINATE, "activity_name": "Terminate"}
    if any(k in et for k in ("CREATE", "START", "LAUNCH", "SPAWN", "EXEC")):
        return {"activity_id": _ACTIVITY_LAUNCH, "activity_name": "Launch"}
    return {"activity_id": _ACTIVITY_OTHER, "activity_name": "Other"}


def process_activity_to_ocsf(event: Any, agent: Any = None) -> Dict[str, Any]:
    """Evento di processo Aegis → OCSF Process Activity (class_uid 1007).

    Usato per esportare la telemetria grezza (non solo gli alert) verso un
    SIEM: senza questo, il SIEM riceve le detection ma non il contesto per
    correlare.
    """
    def g(name: str, default: Any = None) -> Any:
        if isinstance(event, dict):
            return event.get(name, default)
        return getattr(event, name, default)

    activity = _activity_from_event_type(g("event_type"))
    process: Dict[str, Any] = {"name": g("process_name") or "unknown"}
    if g("pid") is not None:
        process["pid"] = g("pid")
    if g("process_path"):
        process["file"] = {"path": g("process_path"), "name": g("process_name")}
    if g("parent_pid") is not None or g("parent_process_name"):
        process["parent_process"] = {
            k: v for k, v in {
                "pid": g("parent_pid"),
                "name": g("parent_process_name"),
            }.items() if v is not None
        }
    # OCSF class 1007 type_uid = 1007 * 100 + activity_id
    return {
        "metadata": {
            "version": OCSF_VERSION,
            "product": PRODUCT,
            "event_code": "aegis.process",
            "log_name": "Aegis Process Telemetry",
        },
        "class_uid": 1007,
        "class_name": "Process Activity",
        "category_uid": 1,
        "category_name": "System Activity",
        "activity_id": activity["activity_id"],
        "activity_name": activity["activity_name"],
        "type_uid": 1007 * 100 + activity["activity_id"],
        "type_name": f"Process Activity: {activity['activity_name']}",
        "severity_id": severity_to_ocsf(g("severity") or "INFO"),
        "time": _epoch_ms(g("timestamp")),
        "time_dt": _iso(g("timestamp")),
        "device": _device(agent),
        "actor": {"process": process},
        "unmapped": {
            "aegis": {
                "event_type": g("event_type"),
                "agent_id": str(g("agent_id") or ""),
            }
        },
    }


def schema_description() -> Dict[str, Any]:
    """Descrizione leggibile della mappatura (per docs/UI/integratori)."""
    return {
        "ocsf_version": OCSF_VERSION,
        "product": PRODUCT,
        "mappings": [
            {"source": "alerts", "target_class_uid": 2004,
             "target_class_name": "Detection Finding",
             "target_category": "Findings",
             "fields": ["severity→severity_id", "description→finding_info.title",
                        "mitre_*→attacks[]", "process_*→actor.process",
                        "agent→device", "is_resolved→status_id"]},
            {"source": "process telemetry", "target_class_uid": 1007,
             "target_class_name": "Process Activity",
             "target_category": "System Activity",
             "fields": ["event_type→activity_id", "process_*→actor.process",
                        "agent→device"]},
        ],
        "endpoints": {
            "alerts": "/api/v1/ocsf/alerts",
            "single_alert": "/api/v1/ocsf/alerts/{id}",
            "convert": "/api/v1/ocsf/convert",
            "schema": "/api/v1/ocsf/schema",
        },
        "notes": "Campi non coperti da OCSF 1.4.0 finiscono in `unmapped.aegis`.",
    }
