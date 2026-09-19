import os
import sys

# Ensure test/dev imports succeed before app settings validation runs.
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("JWT_SECRET", "test_jwt_secret_for_testing_only_32_chars_minimum_length")
os.environ.setdefault("AGENT_ENROLL_KEY", "test_enrollment_token_16_chars_min")
os.environ.setdefault("MASTER_KEY_B64", "Q/wCZ5reU82bQpZppUc6Qq80sybBPz4Q276NbMBF97Q=")

# ------------------------------------------------------------------ Redis
# La suite deve funzionare anche dove `settings.REDIS_URL` non e' raggiungibile
# dall'host di test (es. `aegis-redis` in compose: risolvibile solo dentro la
# rete docker). I client Redis nascono in due modi: module-level
# (security.redis_client) e FRESH per richiesta (redis.from_url(...) negli
# endpoint) — un solo stub non copre entrambi, e alcuni percorsi sono
# fail-closed (blacklist -> "Token revoked", rate limit AI -> 429).
# Soluzione: verificare la raggiungibilità PRIMA degli import dell'app e,
# se l'URL configurato non risponde, riscrivere os.environ["REDIS_URL"]
# verso un endpoint raggiungibile (porta host-mappata dal compose, poi
# localhost:6379 come in CI). Se nulla risponde, si lascia com'è: i test
# che richiedono Redis falliranno con l'errore vero, non con 401 a cascata.

def _redis_ok(url: str) -> bool:
    try:
        import redis as _r
        _r.from_url(url, socket_connect_timeout=2, socket_timeout=2).ping()
        return True
    except Exception:
        return False


def _resolve_reachable_redis_url() -> None:
    original = os.getenv("REDIS_URL", "")
    if original and _redis_ok(original):
        return
    candidates = []
    # Porta host-mappata dal compose (REDIS_PORT_EXTERNAL), stessa password.
    try:
        from urllib.parse import urlparse
        ext_port = os.getenv("REDIS_PORT_EXTERNAL", "")
        parsed = urlparse(original) if original else None
        if ext_port.isdigit() and parsed and parsed.password:
            candidates.append(f"redis://:{parsed.password}@127.0.0.1:{ext_port}/0")
    except Exception:
        pass
    candidates.append("redis://127.0.0.1:6379/0")   # CI / redis locale
    candidates.append("redis://localhost:6379/0")
    for cand in candidates:
        if _redis_ok(cand):
            os.environ["REDIS_URL"] = cand
            print(f"conftest: REDIS_URL non raggiungibile, uso {cand}")
            return


try:
    _resolve_reachable_redis_url()
except Exception:
    pass

# ----------------------------------------------------------------- Database
# Stesso problema della sezione Redis, stessa cura: se `DATABASE_URL` punta a
# un hostname non risolvibile dall'host di test (es. `aegis-postgres` di
# compose, presente nel .env o nell'env della shell), l'engine module-level di
# `app.database.connection` nasce morto e i test che NON passano da `client`
# (es. listener syslog -> siem_pipeline) falliscono con `getaddrinfo failed`.
# Riscrittura verso un DATABASE **di test** raggiungibile (mai il DB live:
# il fallback mantiene il nome con /aegis_test).

def _pg_ok(url: str) -> bool:
    try:
        import asyncio
        import asyncpg

        dsn = url.replace("postgresql+asyncpg://", "postgresql://")

        async def _probe():
            conn = await asyncpg.connect(dsn, timeout=3)
            await conn.close()

        asyncio.run(_probe())
        return True
    except Exception:
        return False


_du = os.getenv("DATABASE_URL", "")
if _du and not _pg_ok(_du):
    _fallback = os.getenv("TEST_DATABASE_URL", "")
    if not _fallback and "@" in _du and "/" in _du:
        # Conserva credenziali e nome DB (/aegis_test: mai il DB live) ma
        # sostituisce l'HOSTNAME: i nomi di servizio compose (`aegis-postgres`)
        # non sono risolvibili dall'host di test. Prova prima la stessa porta,
        # poi le porte pubblicate tipiche su localhost.
        _creds = _du.rsplit("@", 1)[0] + "@"
        _hostport = _du.rsplit("@", 1)[1].rsplit("/", 1)[0]
        _port = _hostport.rsplit(":", 1)[1] if ":" in _hostport else "5432"
        # 127.0.0.1 esplicito, MAI `localhost`: su Windows `localhost` risolve
        # prima in ::1 (IPv6) dove Docker non pub­blica, e la connect pende in
        # timeout invece di fallire veloce. Ordine: porta del DSN, poi le
        # porte pubblicate tipiche di compose.
        for c in (_creds + "127.0.0.1:" + _port, _creds + "127.0.0.1:5444", _creds + "127.0.0.1:5432"):
            if _pg_ok(c + "/aegis_test"):
                _fallback = c + "/aegis_test"
                break
    if _fallback and _pg_ok(_fallback):
        os.environ["DATABASE_URL"] = _fallback
        print(f"conftest: DATABASE_URL non raggiungibile, uso {_fallback.rsplit('@', 1)[-1]}")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Avoid pytest path shadowing from a stale `app` module cache.
for _mod in ("app", "app.main"):
    sys.modules.pop(_mod, None)

import asyncio
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool

from app.main import app
from app.database.connection import get_db, Base
from app.core.config import settings
from app.database.models import User, Agent
from app.core.security import hash_password, create_access_token
import uuid


# Force test database URL — never use production DB for tests
_env_db = os.getenv("DATABASE_URL", "")
if os.getenv("TEST_DATABASE_URL"):
    TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
elif "aegis" in _env_db and "test" not in _env_db.lower():
    # Rewrite production URL to aegis_test
    parts = _env_db.rsplit("/", 1)
    TEST_DATABASE_URL = parts[0] + "/aegis_test"
else:
    TEST_DATABASE_URL = _env_db or "postgresql+asyncpg://postgres:password@localhost:5432/aegis_test"

TEST_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Guardrail: i test di integrazione eseguono `drop_all`/`create_all`. Un
# `TEST_DATABASE_URL` che punta a un database reale **cancella dati reali**: non
# e' un rischio teorico, e' successo puntandolo al DB di sviluppo — `drop_all`
# ha emesso `DROP TABLE` su tabelle vere (il lock lo ha fermato, non la logica).
# Qui si rifiuta a priori un nome di database che non contenga "test";
# `ALLOW_NON_TEST_DB=1` resta l'unico modo esplicito per procedere.
_test_db_name = TEST_DATABASE_URL.rsplit("/", 1)[-1].split("?")[0]
if ("test" not in _test_db_name.lower()
        and os.getenv("ALLOW_NON_TEST_DB", "").strip().lower() not in ("1", "true", "yes")):
    raise RuntimeError(
        f"Rifiutato: TEST_DATABASE_URL punta a {_test_db_name!r}, che non sembra un "
        "database di test. La suite esegue drop_all/create_all e cancellerebbe i "
        "dati reali. Usa un database dedicato (es. aegis_test), oppure — solo se "
        "sei davvero sicuro — imposta ALLOW_NON_TEST_DB=1."
    )

# Ensure test database exists by connecting to default `postgres` database first
async def _ensure_test_db():
    """Create aegis_test database if it doesn't exist."""
    try:
        root_url = TEST_DATABASE_URL.rsplit("/", 1)[0] + "/postgres"
        engine = create_async_engine(root_url, isolation_level="AUTOCOMMIT", poolclass=NullPool,
                                     connect_args={"timeout": 2})
        async with engine.begin() as conn:
            from sqlalchemy import text
            db_name = TEST_DATABASE_URL.rsplit("/", 1)[-1]
            result = await conn.execute(text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": db_name})
            if not result.scalar():
                await conn.execute(text(f"CREATE DATABASE \"{db_name}\""))
                print(f"Created test database: {db_name}")
        await engine.dispose()
    except Exception as e:
        print(f"Note: Could not ensure test database exists: {e}")

try:
    asyncio.run(_ensure_test_db())
except Exception:
    pass

_db_available = False
_require_integration = os.getenv("REQUIRE_INTEGRATION", "").strip().lower() in ("1", "true", "yes")
try:
    test_engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool, echo=False,
                                      connect_args={"timeout": 2})
    TestAsyncSessionLocal = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    async def _probe_database():
        async with test_engine.connect():
            return True
    try:
        asyncio.run(_probe_database())
        _db_available = True
    except Exception as exc:
        _db_available = False
        if _require_integration:
            raise RuntimeError(f"REQUIRE_INTEGRATION=1 ma DB non raggiungibile: {exc}") from exc
except Exception as exc:
    if _require_integration:
        raise RuntimeError(f"REQUIRE_INTEGRATION=1 ma engine non inizializzabile: {exc}") from exc
    test_engine = None
    TestAsyncSessionLocal = None


def pytest_runtest_setup(item):
    # Quando la CI dichiara REQUIRE_INTEGRATION=1, nessun test di integrazione
    # può essere skippato silenziosamente per "Database not available".
    if _require_integration and not _db_available:
        pytest.fail("REQUIRE_INTEGRATION=1 ma DB/Redis non disponibili: "
                    "i test di integrazione non possono essere skippati")


def pytest_collection_modifyitems(config, items):
    # Doppia guardia: se la suite è stata raccolta con DB assente ma
    # REQUIRE_INTEGRATION=1, fallisce prima ancora di eseguire i test.
    if _require_integration and not _db_available and any("integration" in str(i.fspath) for i in items):
        # Non alziamo qui per non rompere --collect-only, ma il runtest_setup farà fallire.
        pass


@pytest.fixture(scope="session", autouse=True)
async def setup_database():
    if not _db_available:
        yield
        return
    try:
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            # `alembic_version` non e' nei metadata: se sopravvive al drop_all,
            # il database resta con la versione "head" registrata e zero tabelle.
            # Qualunque processo che parte con `alembic upgrade head` (per esempio
            # un brain reale puntato al DB di test) crederebbe di avere lo schema.
            await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
            await conn.run_sync(Base.metadata.create_all)
        yield
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    except Exception:
        yield
    finally:
        if test_engine:
            await test_engine.dispose()


@pytest.fixture
async def db_session():
    if not _db_available:
        pytest.skip("Database not available")
    try:
        conn = await test_engine.connect()
    except Exception as exc:
        pytest.skip(f"Database not available: {exc}")
    trans = await conn.begin()
    session = TestAsyncSessionLocal(bind=conn)
    yield session
    await session.close()
    await trans.rollback()
    await conn.close()


@pytest.fixture
async def client(db_session):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _isolated_pki_dir(tmp_path, monkeypatch):
    """PKI dir ermetica per test (audit CI: senza, enroll/revoke dipendevano
    da /app/pki ambientale — 200 in locale, 503 in CI)."""
    monkeypatch.setattr(settings, "PKI_DIR", str(tmp_path / "pki"))


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """Contatori rate-limit azzerati prima di ogni test.

    I limiti restano attivi e verificabili (429) DENTRO il singolo test, ma
    nessun test parte con il bucket gia' consumato dai test precedenti: su CI
    il runoff degli altri test riempiva i bucket (10/min login, 5/min register)
    e auth/remember/userManagement fallivano a cascata con 429.
    """
    from app.core.rate_limit import limiter as _limiter
    _limiter.reset()
    yield


@pytest.fixture
async def test_user(db_session):
    user = User(
        username="testuser",
        email="test@example.com",
        password_hash=hash_password("testpass123"),
        role="user",
        active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def admin_user(db_session):
    user = User(
        username="admin",
        email="admin@example.com",
        password_hash=hash_password("adminpass123"),
        role="admin",
        active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def test_agent(db_session):
    agent = Agent(
        agent_id=uuid.uuid4(),
        hostname="test-host",
        os_type="linux",
        agent_type="nodetrace",
        device_token_hash=hash_password("agent-secret"),
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest.fixture
def user_auth_headers(test_user):
    token, _, _ = create_access_token(subject=str(test_user.id), role=test_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_auth_headers(admin_user):
    token, _, _ = create_access_token(subject=str(admin_user.id), role=admin_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def agent_auth_headers(test_agent):
    return {
        "Authorization": "Bearer agent-secret",
        "X-Agent-Id": str(test_agent.agent_id)
    }
