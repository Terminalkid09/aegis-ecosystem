import pytest
from httpx import AsyncClient
from app.core.metrics import inc, observe_hist, set_gauge, render_prometheus
from app.core.rate_guard import RateGuard


def test_prometheus_render_has_types():
    inc("aegis_events_received_total", 2, 'agent="00000000-0000-0000-0000-000000000",type="PROCESS_CREATED"')
    set_gauge("aegis_queue_depth", 7, 'agent="x",stage="ingest"')
    observe_hist("aegis_ingestion_latency_seconds", 0.005)
    text = render_prometheus()
    assert "# TYPE aegis_events_received_total counter" in text
    assert "aegis_events_received_total{agent=\"00000000-0000-0000-0000-000000000\",type=\"PROCESS_CREATED\"} 2" in text
    assert "# TYPE aegis_queue_depth gauge" in text
    assert "aegis_queue_depth{agent=\"x\",stage=\"ingest\"} 7" in text
    assert "aegis_ingestion_latency_seconds_avg" in text


async def test_metrics_endpoint_exposes_prometheus(client: AsyncClient):
    r = await client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    assert "aegis_http_requests_total" in r.text


def test_rate_guard_allows_within_budget():
    rg = RateGuard(events_per_min=10)
    agent = "agent-1"
    allowed = all(rg.allow(agent) for _ in range(10))
    assert allowed is True
    assert rg.allow(agent) is False
    assert rg.remaining(agent) == 0


def test_rate_guard_allowlist_bypass():
    rg = RateGuard(events_per_min=2)
    rg.allowlist.add("sensor-9000")
    assert rg.allow("sensor-9000", 1000) is True


def test_rate_guard_resets_after_window():
    rg = RateGuard(events_per_min=5)
    agent = "agent-2"
    for _ in range(5):
        rg.allow(agent)
    assert rg.allow(agent) is False
    rg._windows[agent] = (5, rg._windows[agent][1] - 61.0)
    assert rg.allow(agent) is True


async def test_health_live_has_new_checks(client: AsyncClient):
    r = await client.get("/health/live")
    assert r.status_code == 200
    body = r.json()
    assert "checks" in body
    for name in ("database", "redis", "pipeline", "pki", "mtls"):
        assert name in body["checks"], name
    statuses = {v["status"] for v in body["checks"].values()}
    assert statuses <= {"healthy", "degraded", "unhealthy"}


def test_logging_formatter_injects_service():
    import logging
    from app.core.logging import get_logger, SERVICE_NAME
    assert SERVICE_NAME == "aegis-brain"
    logger = get_logger("test.svc")
    assert logger is not None


def test_optional_ollama_does_not_make_core_unready():
    from app.core.health import HealthChecker, HealthCheckResult, HealthStatus

    checker = HealthChecker()
    results = {
        "database": HealthCheckResult("database", HealthStatus.HEALTHY, 0, {}),
        "redis": HealthCheckResult("redis", HealthStatus.HEALTHY, 0, {}),
        "pipeline": HealthCheckResult("pipeline", HealthStatus.HEALTHY, 0, {}),
        "pki": HealthCheckResult("pki", HealthStatus.HEALTHY, 0, {}),
        "mtls": HealthCheckResult("mtls", HealthStatus.HEALTHY, 0, {}),
        "ollama": HealthCheckResult("ollama", HealthStatus.UNHEALTHY, 0, {}, "offline"),
    }

    assert checker.get_overall_status(results) == HealthStatus.DEGRADED


def test_critical_dependency_failure_remains_unhealthy():
    from app.core.health import HealthChecker, HealthCheckResult, HealthStatus

    checker = HealthChecker()
    results = {
        "database": HealthCheckResult("database", HealthStatus.UNHEALTHY, 0, {}, "offline"),
        "redis": HealthCheckResult("redis", HealthStatus.HEALTHY, 0, {}),
        "ollama": HealthCheckResult("ollama", HealthStatus.HEALTHY, 0, {}),
    }

    assert checker.get_overall_status(results) == HealthStatus.UNHEALTHY
