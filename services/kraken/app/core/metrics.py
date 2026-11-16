from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response
import re
import time

registry = CollectorRegistry()

http_requests_total = Counter(
    "kraken_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
    registry=registry
)

http_request_duration_seconds = Histogram(
    "kraken_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    registry=registry
)

active_sandboxes = Gauge(
    "kraken_active_sandboxes",
    "Number of active sandbox containers",
    registry=registry
)

sandbox_created_total = Counter(
    "kraken_sandbox_created_total",
    "Total sandboxes created",
    ["status"],
    registry=registry
)

sandbox_destroyed_total = Counter(
    "kraken_sandbox_destroyed_total",
    "Total sandboxes destroyed",
    ["reason"],
    registry=registry
)

attacks_total = Counter(
    "kraken_attacks_total",
    "Total attacks detected",
    ["sensor_type", "country", "threat_level"],
    registry=registry
)

malware_captured_total = Counter(
    "kraken_malware_captured_total",
    "Total malware samples captured",
    registry=registry
)

db_connections_active = Gauge(
    "kraken_db_connections_active",
    "Active database connections",
    registry=registry
)

redis_connected = Gauge(
    "kraken_redis_connected",
    "Redis connection status (1=connected, 0=disconnected)",
    registry=registry
)

auth_failures_total = Counter(
    "kraken_auth_failures_total",
    "Total authentication failures",
    ["reason"],
    registry=registry
)

export_requests_total = Counter(
    "kraken_export_requests_total",
    "Total export requests",
    ["format", "status"],
    registry=registry
)

outbox_pending = Gauge(
    "kraken_outbox_pending",
    "Events waiting for delivery to Aegis",
    registry=registry
)

outbox_sent_total = Counter(
    "kraken_outbox_sent_total",
    "Events delivered to Aegis",
    registry=registry
)

outbox_failed_total = Counter(
    "kraken_outbox_failed_total",
    "Events permanently failed or exhausted retries",
    ["reason"],
    registry=registry
)

outbox_attempts_total = Counter(
    "kraken_outbox_attempts_total",
    "Delivery attempts by outcome",
    ["outcome"],
    registry=registry
)

def record_http_request(method: str, endpoint: str, status: int, duration: float):
    http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
    http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

def record_sandbox_created(success: bool):
    sandbox_created_total.labels(status="success" if success else "failure").inc()

def record_sandbox_destroyed(reason: str):
    sandbox_destroyed_total.labels(reason=reason).inc()

def set_active_sandboxes(count: int):
    active_sandboxes.set(count)

def record_attack(sensor_type: str, country: str, is_known_threat: bool):
    normalized = (country or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2,3}", normalized):
        normalized = "unknown"
    attacks_total.labels(
        sensor_type=sensor_type,
        country=normalized,
        threat_level="known" if is_known_threat else "unknown"
    ).inc()

def record_malware_captured(sha256: str = ""):
    # No per-sample label: unbounded cardinality is a DoS vector.
    malware_captured_total.inc()

def set_db_connections(count: int):
    db_connections_active.set(count)

def set_redis_connected(connected: bool):
    redis_connected.set(1 if connected else 0)

def record_auth_failure(reason: str):
    auth_failures_total.labels(reason=reason).inc()

def record_export(format_type: str, success: bool):
    export_requests_total.labels(format=format_type, status="success" if success else "failure").inc()

def set_outbox_pending(count: int):
    outbox_pending.set(count)

def record_outbox_sent():
    outbox_sent_total.inc()

def record_outbox_failed(reason: str):
    outbox_failed_total.labels(reason=reason).inc()

def record_outbox_attempt(outcome: str):
    outbox_attempts_total.labels(outcome=outcome).inc()

async def metrics_endpoint():
    return Response(content=generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

class MetricsMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.time()
        method = scope.get("method", "UNKNOWN")
        path = scope.get("path", "/")

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status = message["status"]
                duration = time.time() - start_time
                record_http_request(method, path, status, duration)
            await send(message)

        await self.app(scope, receive, send_wrapper)