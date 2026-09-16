"""Ingestione SIEM end-to-end su database reale.

Copre il percorso completo che rende il progetto un SIEM e non un raccoglitore:
payload grezzo → parser → evento normalizzato → store → regola Sigma /
correlazione → alert → ricerca. Se questo test passa, un syslog o un
Windows Event Log che punta all'endpoint produce una detection visibile nel SOC.

Ogni test usa un **nome sorgente univoco**: la dedup degli eventi è per
contenuto e sopravvive ai test (`SIEM_EVENT_DEDUP_TTL_S`), quindi riusare lo
stesso nome con lo stesso payload in un secondo test sarebbe un duplicato
legittimo — e il test misurerebbe la dedup invece dell'ingestione.

Richiede PostgreSQL (come il resto di `tests/integration`); Redis è opzionale:
dedup e correlazione degradano senza, e i test lo dichiarano.
"""
import json
import os
import re
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select

from app.core.config import settings
from app.database.models import Agent, Alert, SiemEvent
from app.services import siem_store

LOGS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "corpus", "logs")


def _corpus(name: str) -> str:
    with open(os.path.join(LOGS, name), encoding="utf-8") as fh:
        return fh.read()


def _window_hours(name: str = "windows_security.jsonl") -> int:
    """Ore di finestra che coprono il corpus, calcolate dai suoi timestamp.

    Il corpus ha timestamp **fissi**. Una finestra relativa scritta a mano
    (`hours=24`) rende il test dipendente dal giorno in cui lo esegui: il
    2026-09-16 il corpus del 2026-09-15T12:00 era gia' fuori finestra, e quattro
    test di ricerca tornavano 0 eventi senza che nulla fosse rotto. La finestra
    si ricava quindi dai timestamp del corpus, entro il massimo accettato
    dall'API (720h), cosi' il test misura la ricerca e non il calendario.
    """
    first = json.loads(_corpus(name).splitlines()[0])
    raw = first.get("TimeCreated") or first.get("Timestamp") or first.get("ts")
    iso = str(raw).replace("Z", "+00:00")
    # Windows Event Log usa 7 cifre frazionarie: `fromisoformat` prima di
    # Python 3.11 ne accetta 3 o 6 (stessa normalizzazione di parse_timestamp).
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)
    start = datetime.fromisoformat(iso)
    age_hours = int((datetime.now(timezone.utc) - start).total_seconds() // 3600) + 2
    return max(24, min(720, age_hours))


def _source(prefix: str) -> str:
    """Nome sorgente univoco per test: evita la dedup fra esecuzioni."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _auth_failure_line(index: int, ip: str) -> str:
    return (f"<134>1 2026-09-15T12:00:{index:02d}.000000+00:00 web-01 sshd "
            f"22{index} ID47 - Failed password for invalid user admin from {ip} "
            f"port {51000 + index} ssh2")


def _random_src_ip() -> str:
    """IP univoco per esecuzione: i contatori di correlazione vivono in Redis
    con TTL, quindi lo stesso IP in due run ravvicinate non scatenerebbe nulla."""
    return f"198.51.100.{uuid.uuid4().int % 200 + 11}"


async def _redis_up() -> bool:
    try:
        return bool(await siem_store.rc.ping())
    except Exception:
        return False


async def _event_count(db) -> int:
    return int(await db.scalar(select(func.count(SiemEvent.id))) or 0)


async def _alerts(db):
    return (await db.execute(select(Alert))).scalars().all()


class TestIngestAuth:
    async def test_ingest_requires_credentials(self, client):
        response = await client.post("/api/v1/ingest/syslog", json="hello")
        assert response.status_code == 401

    async def test_invalid_bearer_is_rejected(self, client):
        response = await client.post("/api/v1/ingest/syslog", json="hello",
                                     headers={"Authorization": "Bearer nonsense"})
        assert response.status_code == 401

    async def test_ingest_accepts_jwt(self, client, admin_auth_headers):
        line = _auth_failure_line(1, _random_src_ip())
        response = await client.post(
            f"/api/v1/ingest/{_source('syslog-src')}?parser=syslog", json=line,
            headers=admin_auth_headers)
        assert response.status_code == 200, response.text
        assert response.json()["stored"] == 1


class TestIngestApiKey:
    """La via di autenticazione degli shipper reali (rsyslog, Filebeat, script).

    Non coperta dal percorso JWT: se si rompe, l'integrazione di una sorgente
    fallisce con un 500 e nessuno se ne accorge finché non lo fa un cliente.
    """

    async def test_valid_api_key_is_accepted(self, client, monkeypatch):
        monkeypatch.setattr(settings, "AEGIS_API_KEY", "ingest-test-key")
        response = await client.post(
            f"/api/v1/ingest/{_source('keyed')}?parser=syslog",
            json=_auth_failure_line(1, _random_src_ip()),
            headers={"X-Api-Key": "ingest-test-key"})
        assert response.status_code == 200, response.text
        assert response.json()["stored"] == 1

    async def test_wrong_api_key_is_forbidden(self, client, monkeypatch):
        monkeypatch.setattr(settings, "AEGIS_API_KEY", "ingest-test-key")
        response = await client.post(f"/api/v1/ingest/{_source('keyed')}", json="x",
                                     headers={"X-Api-Key": "wrong"})
        assert response.status_code == 403

    async def test_api_key_never_means_anonymous(self, client, monkeypatch):
        monkeypatch.setattr(settings, "AEGIS_API_KEY", "")
        response = await client.post(f"/api/v1/ingest/{_source('keyed')}", json="x")
        # Chiave non configurata sul server: non deve diventare accesso libero.
        assert response.status_code in (401, 500)


class TestIngestPipeline:
    async def test_windows_corpus_is_ingested_and_stored(self, client, admin_auth_headers,
                                                        db_session):
        response = await client.post(
            f"/api/v1/ingest/{_source('win')}?parser=windows_event",
            json=_corpus("windows_security.jsonl"), headers=admin_auth_headers)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["parser"] == "windows_event"
        assert body["accepted"] == 8
        assert body["stored"] == 8
        assert body["unparsed"] == 0
        assert await _event_count(db_session) >= 8

    async def test_sigma_rules_produce_alerts_on_real_events(self, client, admin_auth_headers,
                                                            db_session):
        response = await client.post(
            f"/api/v1/ingest/{_source('win')}?parser=windows_event",
            json=_corpus("windows_security.jsonl"), headers=admin_auth_headers)
        assert response.status_code == 200, response.text
        body = response.json()
        # 1102 (log cancellato) e 7045 (servizio da path utente) sono detection reali.
        assert body["sigma"] >= 2, body
        assert body["alerts"] >= 2, body

        descriptions = [a.description for a in await _alerts(db_session)]
        assert any("SIGMA" in (d or "") for d in descriptions)

    async def test_alert_links_back_to_a_log_source_agent(self, client, admin_auth_headers,
                                                          db_session):
        """Gli alert da log devono essere indistinguibili da quelli degli agenti:
        stessa tabella, stesso ciclo di vita (triage, playbook, dashboard)."""
        source = _source("win")
        await client.post(f"/api/v1/ingest/{source}?parser=windows_event",
                          json=_corpus("windows_security.jsonl"),
                          headers=admin_auth_headers)
        alerts = await _alerts(db_session)
        assert alerts
        os_types = set()
        for alert in alerts:
            agent = await db_session.get(Agent, alert.agent_id)
            if agent is not None:
                os_types.add(agent.os_type)
        assert any(str(t).startswith("logsource:") for t in os_types), os_types

    async def test_idempotent_replay_does_not_duplicate(self, client, admin_auth_headers):
        """Un relay che reinvia lo stesso payload non genera eventi duplicati."""
        if not await _redis_up():
            pytest.skip("Redis non disponibile: dedup fail-open, non testabile")
        source = _source("syslog")
        line = _auth_failure_line(7, _random_src_ip())
        first = await client.post(f"/api/v1/ingest/{source}?parser=syslog", json=line,
                                  headers=admin_auth_headers)
        second = await client.post(f"/api/v1/ingest/{source}?parser=syslog", json=line,
                                   headers=admin_auth_headers)
        assert first.json()["stored"] == 1
        assert second.status_code == 200, second.text
        assert second.json()["stored"] == 0
        assert second.json()["duplicates"] == 1

    async def test_correlation_fires_after_repeated_failures(self, client, admin_auth_headers,
                                                            db_session):
        """Cinque fallimenti dallo stesso IP devono diventare un alert, non cinque."""
        if not await _redis_up():
            pytest.skip("Redis non disponibile: correlazione non valutabile")
        source = _source("syslog")
        ip = _random_src_ip()
        for index in range(5):
            response = await client.post(f"/api/v1/ingest/{source}?parser=syslog",
                                         json=_auth_failure_line(index, ip),
                                         headers=admin_auth_headers)
            assert response.status_code == 200, response.text

        rows = (await db_session.execute(
            select(Alert).where(Alert.event_type == "CORRELATION"))).scalars().all()
        assert rows, "la correlazione brute-force non ha prodotto alert"
        assert any("corr-ssh-bruteforce" in (r.description or "") for r in rows)

    async def test_unparseable_payload_is_422_with_diagnosis(self, client, admin_auth_headers):
        response = await client.post(f"/api/v1/ingest/{_source('garbage')}",
                                     json="@@@@ this is not a log line @@@@",
                                     headers=admin_auth_headers)
        assert response.status_code == 422
        assert "no event could be parsed" in response.text


class TestParsersAndSources:
    async def test_catalog_lists_supported_sources(self, client, admin_auth_headers):
        response = await client.get("/api/v1/ingest/catalog", headers=admin_auth_headers)
        assert response.status_code == 200
        names = {item["name"] for item in response.json()["parsers"]}
        for expected in ("syslog", "windows_event", "zeek", "suricata", "pfsense",
                         "nginx", "squid", "firewall", "json"):
            assert expected in names

    async def test_parser_preview_does_not_store(self, client, admin_auth_headers, db_session):
        before = await _event_count(db_session)
        response = await client.post("/api/v1/ingest/test",
                                     json={"parser": "syslog",
                                           "payload": _auth_failure_line(9, _random_src_ip())},
                                     headers=admin_auth_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["parser"] == "syslog"
        assert len(body["events"]) == 1
        assert body["events"][0]["src_ip"]
        assert await _event_count(db_session) == before, "l'anteprima non deve scrivere nello store"

    async def test_source_registry_tracks_ingestion(self, client, admin_auth_headers):
        source = _source("zeek")
        posted = await client.post(f"/api/v1/ingest/{source}?parser=zeek",
                                   json=_corpus("zeek_conn.log"), headers=admin_auth_headers)
        assert posted.status_code == 200, posted.text
        response = await client.get("/api/v1/ingest/sources", headers=admin_auth_headers)
        assert response.status_code == 200
        items = {item["name"]: item for item in response.json()["items"]}
        assert source in items
        assert items[source]["events_total"] >= 1
        assert items[source]["last_event_at"] is not None

    async def test_source_creation_validates_parser(self, client, admin_auth_headers):
        name = _source("my-fw")
        ok = await client.post("/api/v1/ingest/sources",
                               json={"name": name, "parser": "pfsense"},
                               headers=admin_auth_headers)
        assert ok.status_code == 200, ok.text
        assert ok.json()["name"] == name

        bad = await client.post("/api/v1/ingest/sources",
                                json={"name": name, "parser": "does-not-exist"},
                                headers=admin_auth_headers)
        assert bad.status_code == 422

    async def test_source_name_is_validated(self, client, admin_auth_headers):
        response = await client.post("/api/v1/ingest/sources",
                                     json={"name": "bad name!", "parser": "auto"},
                                     headers=admin_auth_headers)
        assert response.status_code == 422

    async def test_detection_coverage_is_honest(self, client, admin_auth_headers):
        response = await client.get("/api/v1/ingest/detection-coverage",
                                    headers=admin_auth_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["sigma"]["rules_executable"] >= 14
        assert body["sigma"]["rules_excluded"] == 0
        assert body["correlation"]["rules_executable"] >= 5
        assert body["correlation"]["excluded"] == []


class TestSearch:
    async def _seed(self, client, headers) -> str:
        source = _source("search")
        response = await client.post(f"/api/v1/ingest/{source}?parser=windows_event",
                                     json=_corpus("windows_security.jsonl"),
                                     headers=headers)
        assert response.status_code == 200, response.text
        return source

    async def test_search_by_text_and_filters(self, client, admin_auth_headers):
        source = await self._seed(client, admin_auth_headers)

        by_text = await client.get("/api/v1/search/events",
                                   params={"q": "log was cleared", "hours": _window_hours()},
                                   headers=admin_auth_headers)
        assert by_text.status_code == 200
        assert by_text.json()["total"] >= 1

        by_filter = await client.post("/api/v1/search/events",
                                      json={"filters": {"source": source}, "limit": 50},
                                      headers=admin_auth_headers)
        assert by_filter.status_code == 200
        body = by_filter.json()
        assert body["total"] == 8
        assert all(item["source"] == source for item in body["items"])

    async def test_search_by_source_type_filter(self, client, admin_auth_headers):
        await self._seed(client, admin_auth_headers)
        response = await client.post("/api/v1/search/events",
                                     json={"filters": {"source_type": "windows_event"},
                                           "limit": 50},
                                     headers=admin_auth_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["total"] >= 1
        assert all(item["source_type"] == "windows_event" for item in body["items"])

    async def test_search_ignores_unknown_filter_fields(self, client, admin_auth_headers):
        """Un campo fuori allowlist non deve produrre un errore 500."""
        await self._seed(client, admin_auth_headers)
        response = await client.post(
            "/api/v1/search/events",
            json={"filters": {"nope": "x", "; DROP TABLE siem_events": "1"}},
            headers=admin_auth_headers)
        assert response.status_code == 200

    async def test_search_wildcards_in_text_are_escaped(self, client, admin_auth_headers):
        """`%` non deve comportarsi da wildcard: altrimenti la ricerca torna tutto."""
        await self._seed(client, admin_auth_headers)
        response = await client.get("/api/v1/search/events",
                                    params={"q": "%", "hours": _window_hours()},
                                    headers=admin_auth_headers)
        assert response.status_code == 200
        assert response.json()["total"] == 0

    async def test_search_pagination_is_bounded(self, client, admin_auth_headers):
        await self._seed(client, admin_auth_headers)
        response = await client.get("/api/v1/search/events",
                                    params={"hours": _window_hours(), "limit": 3,
                                            "order": "asc"},
                                    headers=admin_auth_headers)
        assert response.status_code == 200
        body = response.json()
        assert len(body["items"]) == 3
        assert body["total"] >= 3
        assert body["items"] == sorted(body["items"], key=lambda i: i["time"])

    async def test_stats_and_fields(self, client, admin_auth_headers):
        await self._seed(client, admin_auth_headers)
        stats = await client.get("/api/v1/search/stats",
                                 params={"hours": _window_hours()},
                                 headers=admin_auth_headers)
        assert stats.status_code == 200
        assert stats.json()["total"] >= 1
        assert "by_source_type" in stats.json()

        fields = await client.get("/api/v1/search/fields", headers=admin_auth_headers)
        assert fields.status_code == 200
        assert "event_id" in {f["field"] for f in fields.json()["fields"]}

    async def test_ingest_stats_include_rule_counts(self, client, admin_auth_headers):
        await self._seed(client, admin_auth_headers)
        response = await client.get("/api/v1/ingest/stats",
                                    params={"hours": _window_hours()},
                                    headers=admin_auth_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["total"] >= 1
        assert body["detection"]["sigma_rules"] >= 14
        assert body["detection"]["correlation_rules"] >= 5
