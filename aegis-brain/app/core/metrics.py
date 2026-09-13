"""Metriche applicative per osservabilita' (Fase 1, audit F3).

Espone contatori e istogrammi in memoria, senza dipendere da
prometheus_client (evita dipendenza extra per pilot 100 host).
Il formato Prometheus text e' generato manualmente e servito su /metrics.

Robustezza (audit F3):
- HELP + TYPE emessi una sola volta per famiglia (niente duplicati);
- escaping dei valori label (backslash, virgolette, newline);
- `normalize_path_label` per limitare la cardinalita' (UUID/numeri -> placeholder);
- float non-finiti resi come letterali Prometheus validi (NaN/+Inf/-Inf);
- accesso thread-safe (lock unico); i caller devono usare `fmt_labels`.

Metriche:
- aegis_events_received_total
- aegis_events_lost_total
- aegis_events_duplicate_total
- aegis_events_dropped_total
- aegis_ingestion_latency_seconds (sum/count per avg)
- aegis_detection_latency_seconds
- aegis_queue_depth (gauge)
- aegis_agent_errors_total
- aegis_sensor_state (gauge per agent)
- aegis_mtls_handshakes_total / failures
- aegis_db_errors_total / redis_errors_total
- aegis_query_duration_seconds (per query principale)
"""
import math
import re
import time
import threading
from collections import defaultdict

_counters = defaultdict(int)
_histograms = defaultdict(lambda: {"sum": 0.0, "count": 0})
_gauges = {}
_lock = threading.Lock()

_HELP = {
    "aegis_events_received_total": "Events accepted by the ingestion pipeline.",
    "aegis_events_lost_total": "Events lost due to consumer/queue errors.",
    "aegis_events_duplicate_total": "Duplicate events discarded by dedup.",
    "aegis_events_dropped_total": "Events rejected before persistence (rate limit, size, schema).",
    "aegis_ingestion_latency_seconds": "Ingestion latency observations.",
    "aegis_detection_latency_seconds": "Detection latency observations.",
    "aegis_http_request_seconds": "HTTP request latency observations.",
    "aegis_http_requests_total": "HTTP requests served.",
    "aegis_queue_depth": "Pending events in queue.",
    "aegis_agent_errors_total": "Per-agent processing errors.",
    "aegis_sensor_state": "Sensor state per agent (1 ok, 0 stale).",
    "aegis_mtls_handshakes_total": "mTLS handshakes attempted.",
    "aegis_mtls_failures_total": "mTLS handshake failures.",
    "aegis_db_errors_total": "Database errors.",
    "aegis_redis_errors_total": "Redis errors.",
    "aegis_query_duration_seconds": "Duration of main DB queries.",
}

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_HEX_RUN_RE = re.compile(r"[0-9a-fA-F]{16,}")
_DIGIT_RUN_RE = re.compile(r"\d{4,}")
_MAX_LABEL_LEN = 120


def escape_label_value(value: object) -> str:
    """Escape di un valore label secondo Prometheus exposition format."""
    return (
        str(value)
        .replace("\\", r"\\")
        .replace('"', r"\"")
        .replace("\n", r"\n")
    )


def fmt_labels(**kv: object) -> str:
    """Costruisce la stringa label `k="v",...` con escaping dei valori."""
    return ",".join(f'{k}="{escape_label_value(v)}"' for k, v in kv.items())


def normalize_path_label(path: str) -> str:
    """Riduce la cardinalita' delle label path: UUID, lunghe sequenze
    esadecimali/numeriche diventano placeholder; troncamento a 120 char.

    Senza questo, un path per evento/upload genera serie illimitate
    (esaurimento memoria Prometheus + scrape lenti).
    """
    p = str(path or "/")
    p = _UUID_RE.sub("{uuid}", p)
    p = _HEX_RUN_RE.sub("{hex}", p)
    p = _DIGIT_RUN_RE.sub("{id}", p)
    if len(p) > _MAX_LABEL_LEN:
        p = p[:_MAX_LABEL_LEN] + "..."
    return p


def _fmt_float(value: float) -> str:
    v = float(value)
    if math.isnan(v):
        return "NaN"
    if math.isinf(v):
        return "+Inf" if v > 0 else "-Inf"
    return repr(v)


def inc(name: str, value: int = 1, labels: str = ""):
    key = f"{name}{{{labels}}}" if labels else name
    with _lock:
        _counters[key] += value


def observe_hist(name: str, value: float):
    with _lock:
        h = _histograms[name]
        h["sum"] += float(value)
        h["count"] += 1


def set_gauge(name: str, value: float, labels: str = ""):
    key = f"{name}{{{labels}}}" if labels else name
    with _lock:
        _gauges[key] = float(value)


def _help_for(name: str) -> str:
    return _HELP.get(name, "No help registered for this metric.")


def render_prometheus() -> str:
    lines: list[str] = []
    with _lock:
        counters = dict(_counters)
        gauges = dict(_gauges)
        histograms = {k: dict(v) for k, v in _histograms.items()}

    def emit_family(base: str, kind: str, samples: list[str]):
        lines.append(f"# HELP {base} {_help_for(base)}")
        lines.append(f"# TYPE {base} {kind}")
        lines.extend(samples)

    by_family: dict[str, list[str]] = {}
    for k in sorted(counters):
        base = k.split("{")[0]
        by_family.setdefault(base, []).append(f"{k} {counters[k]}")
    for base in sorted(by_family):
        emit_family(base, "counter", by_family[base])

    by_family = {}
    for k in sorted(gauges):
        base = k.split("{")[0]
        by_family.setdefault(base, []).append(f"{k} {_fmt_float(gauges[k])}")
    for base in sorted(by_family):
        emit_family(base, "gauge", by_family[base])

    for k in sorted(histograms):
        h = histograms[k]
        emit_family(k, "histogram", [
            f"{k}_sum {_fmt_float(h['sum'])}",
            f"{k}_count {h['count']}",
        ])
        if h["count"]:
            avg = h["sum"] / h["count"]
            emit_family(f"{k}_avg", "gauge", [f"{k}_avg {_fmt_float(avg)}"])
    return "\n".join(lines) + "\n" if lines else "# no metrics yet\n"


class Timer:
    def __init__(self, hist_name: str):
        self.hist_name = hist_name
        self.start = time.perf_counter()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        observe_hist(self.hist_name, time.perf_counter() - self.start)
