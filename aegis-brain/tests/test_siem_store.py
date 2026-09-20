"""Test dello store SIEM: mapping, filtri, partizioni, dedup fail-open.

Sono test senza database di proposito: la logica di mapping e di allowlist dei
filtri è quella che, se sbagliata, produce errori silenziosi (un filtro
scartato, una colonna sbagliata). I test con PostgreSQL stanno in
`tests/integration/test_siem_ingest.py`.
"""
import os

from sqlalchemy import select

from app.database.models import SiemEvent
from app.ingest import default_registry as registry
from app.services import siem_store

LOGS = os.path.join(os.path.dirname(__file__), "corpus", "logs")


def _event(line: str, source: str = "syslog"):
    result = registry.parse(source, line, {"source": "store-test"})
    assert result.events, result.errors
    return result.events[0]


# ── mapping verso la riga ────────────────────────────────────────────────────
def test_event_to_row_covers_every_column():
    event = _event(open(os.path.join(LOGS, "syslog.log"), encoding="utf-8").readline())
    row = siem_store.event_to_row(event)
    for column in SiemEvent.__table__.columns.keys():
        if column in ("id", "created_at"):
            continue
        assert column in row, f"colonna {column} non mappata"
    assert row["search_text"]
    assert row["time"] == event.time
    assert isinstance(row["search_text"], str)


def test_searchable_text_is_bounded_and_includes_extra():
    event = _event(open(os.path.join(LOGS, "syslog.log"), encoding="utf-8").readline())
    text = event.searchable_text()
    assert "Failed password" in text
    assert len(text) <= 8192
    assert "event_type=auth_failure" in text


# ── allowlist dei filtri ─────────────────────────────────────────────────────
def _where(stmt) -> str:
    """Solo la clausola WHERE: il SELECT elenca sempre tutte le colonne."""
    assert stmt.whereclause is not None, "nessun filtro applicato"
    return str(stmt.whereclause.compile(compile_kwargs={"literal_binds": True}))


def test_apply_filters_ignores_unknown_fields():
    """Un campo fuori allowlist viene ignorato, mai interpolato in SQL."""
    stmt = siem_store.apply_filters(select(SiemEvent), {
        "source": "win-01",
        "DROP TABLE siem_events": "x",
        "search_text": "x",
        "id": 1,
    })
    sql = _where(stmt)
    assert "siem_events.source = 'win-01'" in sql
    assert "search_text" not in sql
    assert "siem_events.id" not in sql
    assert "DROP" not in sql.upper()


def test_apply_filters_accepts_lists_and_skips_empty_values():
    stmt = siem_store.apply_filters(select(SiemEvent), {
        "severity": ["HIGH", "CRITICAL"],
        "source": None,
        "hostname": "",
        "src_ip": [],
    })
    sql = _where(stmt)
    assert "severity IN ('HIGH', 'CRITICAL')" in sql
    assert "hostname" not in sql
    assert "src_ip" not in sql


def test_apply_filters_with_only_empty_values_adds_no_clause():
    stmt = siem_store.apply_filters(select(SiemEvent), {"source": None, "src_ip": ""})
    assert stmt.whereclause is None


def test_apply_filters_bounds_list_size():
    stmt = siem_store.apply_filters(select(SiemEvent),
                                    {"src_ip": [f"10.0.0.{i}" for i in range(200)]})
    sql = _where(stmt)
    assert sql.count("10.0.0.") == 50


def test_filterable_fields_stay_within_the_model():
    """L'allowlist deve riferirsi solo a colonne esistenti: un refuso qui
    diventa un AttributeError in produzione."""
    columns = set(SiemEvent.__table__.columns.keys())
    unknown = siem_store.FILTERABLE_FIELDS - columns
    assert unknown == set(), f"campi non filtrabili: {sorted(unknown)}"


# ── dedup ────────────────────────────────────────────────────────────────────
async def test_claim_event_fails_open_when_redis_is_down(monkeypatch):
    """Redis giù: si accetta l'evento (meglio un duplicato che un evento perso)."""
    class Down:
        async def set(self, *a, **k):
            raise ConnectionError("redis down")

    monkeypatch.setattr(siem_store, "rc", Down())
    assert await siem_store.claim_event("abc") is True


async def test_claim_event_without_id_is_never_deduplicated():
    assert await siem_store.claim_event("") is True


# ── partizioni ───────────────────────────────────────────────────────────────
async def test_ensure_partitions_is_a_noop_on_non_postgres(monkeypatch):
    """Su una tabella piatta (o SQLite) la funzione non deve sollevare."""
    siem_store._partitions_ready = False

    class FlatSession:
        async def scalar(self, *a, **k):
            raise RuntimeError("no pg_class")

    assert await siem_store.ensure_monthly_partitions(FlatSession()) == 0
    assert siem_store._partitions_ready is True


async def test_drop_old_partitions_returns_empty_when_catalog_unavailable():
    class FlatSession:
        async def execute(self, *a, **k):
            raise RuntimeError("no pg_inherits")

    assert await siem_store.drop_old_partitions(FlatSession(), retention_days=30) == []


# ── caratteri di controllo non memorizzabili (audit: NUL byte) ────────────────
#
# `store_events` inserisce tutte le righe con UN solo INSERT: una riga che il
# database rifiuta (0x00 in una colonna text) faceva fallire l'intero blocco, e
# in un log sorgente qualche byte binario dentro è la norma. Misurato dal vivo:
# la sorgente rispondeva "store failed" e le righe del blocco andavano perse.


def test_control_chars_stripped_from_a_log_line():
    event = _event(open(os.path.join(LOGS, "syslog.log"), encoding="utf-8").readline())
    event.message = "sshd: auth failure\x00 for user root"
    event.command_line = "/usr/bin/ssh\x00-d"

    row = siem_store.event_to_row(event)

    assert "\x00" not in row["message"]
    assert row["message"] == "sshd: auth failure for user root"
    assert row["command_line"] == "/usr/bin/ssh-d"


def test_control_chars_stripped_from_json_extra():
    """Anche jsonb rifiuta \\u0000 dentro una stringa."""
    event = _event(open(os.path.join(LOGS, "syslog.log"), encoding="utf-8").readline())
    event.extra = {"raw": "a\x00b", "nested": {"k": ["c\x00d"]}}

    row = siem_store.event_to_row(event)

    assert row["extra"]["raw"] == "ab"
    assert row["extra"]["nested"]["k"] == ["cd"]


def test_clean_event_is_untouched_by_the_strip():
    """Controprova: la ripulitura non altera un evento senza caratteri di
    controllo (nessuna riscrittura silenziosa dei dati)."""
    event = _event(open(os.path.join(LOGS, "syslog.log"), encoding="utf-8").readline())
    row = siem_store.event_to_row(event)
    assert "\x00" not in (row["message"] or "")
    assert row["message"] == event.message
    assert row["hostname"] == event.hostname
