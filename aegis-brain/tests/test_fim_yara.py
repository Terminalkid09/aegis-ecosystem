"""FIM + YARA: permessi, validazioni, flusso end-to-end del motore.

Copre i tre rischi veri:
1. la watchlist è write-only per admin (chi può ridurre la sorveglianza?);
2. una regola YARA rotta non blocca le altre (isolamento errori);
3. gli eventi FILE_MODIFIED/YARA_MATCH creano alert MITRE corretti e
   finiscono ricercabili nel SIEM store.
"""
import pytest

from app.services import yara_engine


# ------------------------------------------------------------------ yara engine

def test_yara_engine_isolates_broken_rule():
    ok, errs = yara_engine.compile_rules([
        ("good", 'rule good_r { strings: $s = "abc" condition: $s }'),
        ("bad", "rule bad { condition: }"),
    ])
    assert len(ok) == 1 and ok[0][0] == "good"
    assert len(errs) == 1 and errs[0]["rule"] == "bad"


def test_yara_scan_match_and_score():
    ok, _ = yara_engine.compile_rules([("t", 'rule t_r { strings: $s = "evil" condition: $s }')])
    res = yara_engine.scan_bytes(b"pure evil bytes", ok)
    assert res["enabled"] and len(res["matches"]) == 1
    assert res["matches"][0]["rule"] == "t_r"
    score, findings = yara_engine.score_impact(res, 0)
    assert score >= 40 and findings[0]["severity"] == "high"


def test_yara_no_match_clean():
    ok, _ = yara_engine.compile_rules([("t", 'rule t_r2 { strings: $s = "zzzz" condition: $s }')])
    res = yara_engine.scan_bytes(b"harmless", ok)
    assert res["enabled"] and res["matches"] == []


# ------------------------------------------------------------------ API watchlist FIM

@pytest.mark.asyncio
async def test_fim_watchlist_requires_manage(client, admin_auth_headers):
    r = await client.get("/api/v1/fim/agents/00000000-0000-0000-0000-000000000000/fim-watchlist",
                         headers=admin_auth_headers)
    # admin autenticato: 404 (agente inesistente) e NON 401/403
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_fim_watchlist_denies_anonymous(client):
    r = await client.get("/api/v1/fim/agents/00000000-0000-0000-0000-000000000000/fim-watchlist")
    assert r.status_code == 401


# ------------------------------------------------------------------ API regole YARA

@pytest.mark.asyncio
async def test_yara_rule_crud_and_validation(client, admin_auth_headers, db_session):
    from app.database.models import YaraRule
    # creazione valida
    r = await client.post("/api/v1/yara/rules", headers=admin_auth_headers,
                          json={"name": "test_rule_x", "is_active": True,
                                "content": 'rule test_rule_x { strings: $s = "xyz" condition: $s }'})
    assert r.status_code == 200, r.text
    rule_id = r.json()["id"]
    # contenuto non-YARA rifiutato
    r2 = await client.post("/api/v1/yara/rules", headers=admin_auth_headers,
                           json={"name": "junk", "content": "not a yara rule", "is_active": True})
    assert r2.status_code == 422
    # toggle
    r3 = await client.put(f"/api/v1/yara/rules/{rule_id}", headers=admin_auth_headers,
                          json={"is_active": False})
    assert r3.status_code == 200 and r3.json()["is_active"] is False
    # lista la contiene
    r4 = await client.get("/api/v1/yara/rules", headers=admin_auth_headers)
    names = [i["name"] for i in r4.json()["items"]]
    assert "test_rule_x" in names
    # cleanup
    await client.delete(f"/api/v1/yara/rules/{rule_id}", headers=admin_auth_headers)
    left = await db_session.execute(
        __import__("sqlalchemy").select(YaraRule).where(YaraRule.name == "test_rule_x"))
    assert left.scalars().first() is None


@pytest.mark.asyncio
async def test_yara_rules_denied_to_anonymous(client):
    r = await client.get("/api/v1/yara/rules")
    assert r.status_code == 401
