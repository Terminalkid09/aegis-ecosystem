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
    # Audit: due chiamate. Il middleware conta dopo l'handler, quindi la
    # prima /metrics su processo fresco e' legittimamente vuota.
    await client.get("/metrics")
    r = await client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    assert "aegis_http_requests_total" in r.text


def test_rate_guard_allows_within_budget():
    import uuid as _uuid
    # Audit: agent id unico (con Redis su, i contatori sono condivisi).
    rg = RateGuard(events_per_min=10)
    agent = f"agent-1-{_uuid.uuid4().hex[:8]}"
    allowed = all(rg.allow(agent) for _ in range(10))
    assert allowed is True
    assert rg.allow(agent) is False
    assert rg.remaining(agent) == 0


def test_rate_guard_allowlist_bypass():
    rg = RateGuard(events_per_min=2)
    rg.allowlist.add("sensor-9000")
    assert rg.allow("sensor-9000", 1000) is True


def test_rate_guard_resets_after_window():
    # Meccanica della finestra locale (use_redis=False): con Redis la finestra
    # vive sul server, non nel dict.
    rg = RateGuard(events_per_min=5, use_redis=False)
    agent = "agent-2"
    for _ in range(5):
        rg.allow(agent)
    assert rg.allow(agent) is False
    rg._windows[agent] = (5, rg._windows[agent][1] - 61.0)
    assert rg.allow(agent) is True


# Audit F4: /health/live e' SOLO prova di vita (contratto cambiato di
# proposito: prima eseguiva tutti i check, ora niente DB/rete).
# Lo stato funzionale completo vive su /health/ready.
async def test_health_live_is_alive_only(client: AsyncClient):
    r = await client.get("/health/live")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "alive"
    assert body["service"] == "aegis-brain"
    assert "checks" not in body


async def test_health_ready_has_full_checks(client: AsyncClient):
    r = await client.get("/health/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in {"ready", "not_ready"}
    assert "checks" in body
    for name in ("database", "redis", "pipeline", "pki", "mtls"):
        assert name in body["checks"], name
    statuses = {v["status"] for v in body["checks"].values()}
    assert statuses <= {"healthy", "degraded", "unhealthy"}


def test_liveness_needs_no_dependencies():
    import asyncio
    from app.core import health
    # Anche con DB/Redis irraggiungibili, la liveness risponde (nessun I/O).
    body = asyncio.run(health.liveness_check())
    assert body["status"] == "alive"


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


# ── Audit F3: robustezza metriche ──────────────────────────────────────────
def test_metrics_type_and_help_emitted_once_per_family():
    import app.core.metrics as m
    m.inc("f3_family_total", 1, m.fmt_labels(a="1"))
    m.inc("f3_family_total", 2, m.fmt_labels(a="2"))
    text = m.render_prometheus()
    assert text.count("# TYPE f3_family_total counter") == 1
    assert text.count("# HELP f3_family_total ") == 1
    assert 'f3_family_total{a="1"} 1' in text
    assert 'f3_family_total{a="2"} 2' in text


def test_metrics_label_values_escaped():
    import app.core.metrics as m
    labels = m.fmt_labels(path='a"b\\c\nd', agent='x')
    m.inc("f3_escape_total", 1, labels)
    text = m.render_prometheus()
    assert 'path="a\\"b\\\\c\\nd"' in text


def test_normalize_path_label_caps_cardinality():
    import app.core.metrics as m
    paths = [
        f"/api/v1/agents/123e4567-e89b-12d3-a456-426614174000/events?cursor={10000 + i}"
        for i in range(200)
    ] + [f"/uploads/abcdef0123456789/report-{10000 + i}.bin" for i in range(200)]
    normalized = {m.normalize_path_label(p) for p in paths}
    assert len(normalized) <= 4, sorted(normalized)
    assert m.normalize_path_label("/health/live") == "/health/live"
    # Le versioni API corte (/v1 vs /v2) restano distinte: niente fusione.
    assert m.normalize_path_label("/api/v1/x") != m.normalize_path_label("/api/v2/x")
    assert len(m.normalize_path_label("/x/" + "9" * 500)) <= 124


def test_metrics_nonfinite_render_as_valid_literals():
    import app.core.metrics as m
    m.set_gauge("f3_finite_gauge", float("nan"))
    m.set_gauge("f3_inf_gauge", float("inf"))
    m.observe_hist("f3_hist_seconds", 0.5)
    text = m.render_prometheus()
    assert "f3_finite_gauge NaN" in text
    assert "f3_inf_gauge +Inf" in text


def test_metrics_concurrent_increments_are_exact():
    import threading
    import app.core.metrics as m
    m.inc("f3_conc_total", 0)
    base = m._counters.get("f3_conc_total", 0)
    threads = [threading.Thread(target=lambda: [m.inc("f3_conc_total", 1) for _ in range(250)])
               for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert m._counters["f3_conc_total"] - base == 2000


def test_metrics_output_passes_strict_parser():
    import re
    import app.core.metrics as m
    m.inc("f3_parse_total", 1, m.fmt_labels(k="v", path="/api/v1/ai/threads/{id}/messages"))
    m.set_gauge("f3_parse_gauge", 3.5)
    m.observe_hist("f3_parse_seconds", 0.1)
    text = m.render_prometheus()
    name_re = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
    value_re = re.compile(r"^(-?\d+(\.\d+)?(e[+-]?\d+)?|NaN|\+Inf|-Inf)$")
    label_re = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\]|\\.)*"$')

    def split_labels(inner: str) -> list[str]:
        # Split su virgole FUORI dalle virgolette (i valori possono
        # contenere {} e virgole escapate).
        parts, cur, in_q, esc = [], [], False, False
        for ch in inner:
            if esc:
                cur.append(ch); esc = False
            elif ch == "\\" and in_q:
                cur.append(ch); esc = True
            elif ch == '"':
                cur.append(ch); in_q = not in_q
            elif ch == "," and not in_q:
                parts.append("".join(cur)); cur = []
            else:
                cur.append(ch)
        parts.append("".join(cur))
        return parts

    seen_type: dict[str, int] = {}
    for line in text.splitlines():
        if not line or line.startswith("# HELP "):
            continue
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(" ", 3)
            assert name_re.match(name), line
            assert kind in {"counter", "gauge", "histogram"}, line
            seen_type[name] = seen_type.get(name, 0) + 1
            continue
        if line.startswith("#"):
            raise AssertionError(f"unknown directive: {line}")
        metric, _, value = line.rpartition(" ")
        assert value_re.match(value), f"bad value: {line}"
        if "{" in metric:
            base, _, inner = metric.partition("{")
            assert inner.endswith("}"), line
            assert name_re.match(base), line
            for part in split_labels(inner[:-1]):
                assert label_re.match(part), f"bad label: {part} in {line}"
        else:
            assert name_re.match(metric), line
    assert all(v == 1 for v in seen_type.values()), seen_type
