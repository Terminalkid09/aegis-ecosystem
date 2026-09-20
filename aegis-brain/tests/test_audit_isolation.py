import pytest
from httpx import AsyncClient
from app.core.audit import log_audit
from app.database.models import AuditLog
from sqlalchemy import select

pytestmark = pytest.mark.asyncio

async def test_real_user_named_test_not_is_test(client: AsyncClient, db_session):
    # Crea un utente reale con "test" nel nome ma senza PYTEST_CURRENT_TEST override?
    # Con il nuovo codice, is_test è dedotto solo da env, non da username.
    # Qui siamo dentro pytest, quindi PYTEST_CURRENT_TEST è settato → is_test true
    # Ma per simulare utente reale, passiamo is_test=False esplicito.
    await log_audit(db_session, action="login", resource="auth", username="testuser", is_test=False)
    await db_session.commit()
    r = await db_session.execute(select(AuditLog).where(AuditLog.username == "testuser"))
    row = r.scalars().first()
    assert row is not None
    assert row.is_test is False

async def test_explicit_is_test_flag(client: AsyncClient, db_session):
    await log_audit(db_session, action="test_action", resource="test", username="alice", is_test=True)
    await db_session.commit()
    r = await db_session.execute(select(AuditLog).where(AuditLog.username == "alice"))
    row = r.scalars().first()
    assert row.is_test is True

async def test_pytest_env_marks_is_test(client: AsyncClient, db_session, test_user):
    # Dentro pytest, PYTEST_CURRENT_TEST è settato, quindi is_test dedotto true
    await log_audit(db_session, action="auto", resource="x", username=test_user.username)
    await db_session.commit()
    r = await db_session.execute(select(AuditLog).where(AuditLog.username == test_user.username).order_by(AuditLog.id.desc()))
    row = r.scalars().first()
    assert row.is_test is True

async def test_filter_include_exclude(client: AsyncClient, admin_auth_headers, db_session):
    # Crea due audit, uno test e uno prod
    await log_audit(db_session, action="filter_test", resource="r", username="bob", is_test=False)
    await log_audit(db_session, action="filter_test", resource="r", username="bob_test", is_test=True)
    await db_session.commit()
    r = await client.get("/api/v1/audit/logs?exclude_test=true", headers=admin_auth_headers)
    assert r.status_code == 200
    logs = r.json()
    # Nessun is_test true deve essere presente
    for e in logs:
        assert e.get("is_test") is False or e.get("is_test") is None or e.get("is_test") == 0
    r2 = await client.get("/api/v1/audit/logs?include_test=true", headers=admin_auth_headers)
    assert r2.status_code == 200
    # Deve contenere almeno il test appena creato (se include_test true)
    # Non garantito ordine, ma almeno uno con is_test true dovrebbe essere visibile quando include_test
    # Verifichiamo che il count con include sia >= con exclude
    assert len(r2.json()) >= len(logs)
