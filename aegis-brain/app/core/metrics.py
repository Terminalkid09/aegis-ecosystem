"""Metriche applicative per osservabilità (Fase 1).

Espone contatori e istogrammi in memoria, senza dipendere da
prometheus_client (evita dipendenza extra per pilot 100 host).
Il formato Prometheus text è generato manualmente e servito su /metrics.

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
import time
import threading
from collections import defaultdict

_counters = defaultdict(int)
_histograms = defaultdict(lambda: {"sum": 0.0, "count": 0})
_gauges = {}
_lock = threading.Lock()

def inc(name: str, value: int = 1, labels: str = ""):
    key = f"{name}{{{labels}}}" if labels else name
    with _lock:
        _counters[key] += value

def observe_hist(name: str, value: float):
    with _lock:
        h = _histograms[name]
        h["sum"] += value
        h["count"] += 1

def set_gauge(name: str, value: float, labels: str = ""):
    key = f"{name}{{{labels}}}" if labels else name
    with _lock:
        _gauges[key] = value

def render_prometheus() -> str:
    lines = []
    with _lock:
        for k, v in _counters.items():
            base = k.split("{")[0]
            lines.append(f"# TYPE {base} counter")
            lines.append(f"{k} {v}")
        for k, v in _gauges.items():
            base = k.split("{")[0]
            lines.append(f"# TYPE {base} gauge")
            lines.append(f"{k} {v}")
        for k, h in _histograms.items():
            lines.append(f"# TYPE {k} histogram")
            lines.append(f"{k}_sum {h['sum']}")
            lines.append(f"{k}_count {h['count']}")
            if h["count"]:
                avg = h["sum"] / h["count"]
                lines.append(f"{k}_avg {avg}")
    return "\n".join(lines) + "\n" if lines else "# no metrics yet\n"

class Timer:
    def __init__(self, hist_name: str):
        self.hist_name = hist_name
        self.start = time.perf_counter()
    def __enter__(self):
        return self
    def __exit__(self, *a):
        observe_hist(self.hist_name, time.perf_counter() - self.start)
