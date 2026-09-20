#!/usr/bin/env python3
"""
Esegue la suite di integrazione Aegis con configurazione deterministica.

Prerequisiti (Windows e Linux):
- Python 3.10+
- PostgreSQL in ascolto (compose: aegis-postgres)
- Redis in ascolto (compose: aegis-redis)
- File .env alla radice del repo (copiato da .env.example) con
  POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB / POSTGRES_PORT
  REDIS_PASSWORD / REDIS_PORT / REDIS_PORT_EXTERNAL
- `pip install -r aegis-brain/requirements.txt`

Comportamento:
- Legge .env (se presente) e costruisce TEST_DATABASE_URL / REDIS_URL
  verso 127.0.0.1 + porte mappate dal compose (port forwarding).
- NON usa mai il DB di produzione: se DATABASE_URL non contiene "test",
  lo riscrive verso aegis_test (logica di conftest.py).
- Se i servizi non sono raggiungibili, i test di integrazione vengono
  skippati con "Database not available" — tranne quando
  REQUIRE_INTEGRATION=1 è impostato (CI), nel qual caso la suite fallisce.

Uso:
  python scripts/run_integration_tests.py              # tutti i test, -q
  python scripts/run_integration_tests.py -v           # verboso
  python scripts/run_integration_tests.py tests/test_security.py

Portabilità:
- Risolve la root del repo dal percorso di questo file (funziona sia
  su Windows `C:\\...\\scripts\\run_integration_tests.py` che su Linux
  `/home/.../scripts/run_integration_tests.py`).
- Legge .env senza dipendenze esterne; ignora righe commentate/vuote.
"""
import os
import sys

def repo_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def load_dotenv(path: str) -> dict:
    env = {}
    if not os.path.isfile(path):
        return env
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k:
                env[k] = v
    return env

def main() -> int:
    root = repo_root()
    env_path = os.path.join(root, ".env")
    env_file = load_dotenv(env_path)

    # Permette override da env già esportato (CI secrets).
    def pick(name: str, default: str = "") -> str:
        return os.getenv(name) or env_file.get(name) or default

    pg_user = pick("POSTGRES_USER", "postgres")
    pg_pass = pick("POSTGRES_PASSWORD", "password")
    pg_db = pick("POSTGRES_DB", "aegis")
    # Compose mappa Postgres su POSTGRES_PORT verso host; su Linux interno è 5432.
    pg_port = pick("POSTGRES_PORT", pick("BRAIN_PORT_EXTERNAL", "5432"))
    # Fallback: se il valore sembra placeholder, usa default numerico.
    try:
        int(pg_port)
    except ValueError:
        pg_port = "5432"

    r_pass = pick("REDIS_PASSWORD", "")
    # Compose espone Redis su REDIS_PORT_EXTERNAL (host) e REDIS_PORT (container)
    r_port = pick("REDIS_PORT_EXTERNAL", pick("REDIS_PORT", "6379"))
    try:
        int(r_port)
    except ValueError:
        r_port = "6379"

    # Costruisce URL verso 127.0.0.1 (funziona sia da host Windows che Linux).
    os.environ["TEST_DATABASE_URL"] = (
        f"postgresql+asyncpg://{pg_user}:{pg_pass}@127.0.0.1:{pg_port}/aegis_test"
    )
    if r_pass:
        os.environ["REDIS_URL"] = f"redis://:{r_pass}@127.0.0.1:{r_port}"
    else:
        os.environ["REDIS_URL"] = f"redis://127.0.0.1:{r_port}"

    # Documenta la configurazione senza stampare segreti.
    print(f"[run_integration_tests] TEST_DATABASE_URL=postgresql+asyncpg://{pg_user}:***@127.0.0.1:{pg_port}/aegis_test", flush=True)
    print(f"[run_integration_tests] REDIS_URL=redis://***@127.0.0.1:{r_port}", flush=True)
    if os.path.isfile(env_path):
        print(f"[run_integration_tests] .env={env_path}", flush=True)
    else:
        print("[run_integration_tests] .env assente, uso default + env esportato", flush=True)

    os.chdir(os.path.join(root, "aegis-brain"))

    # Propaga argomenti pytest (default: tests -q)
    import pytest
    args = sys.argv[1:] or ["tests", "-q"]
    return pytest.main(args)

if __name__ == "__main__":
    raise SystemExit(main())
