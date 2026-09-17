#!/usr/bin/env python3
"""Aegis setup in UN comando — installazione e aggiornamento.

Installazione (da repo appena clonata):
    python scripts/setup.py

Fa tutto, nell'ordine:
  1. preflight dipendenze (docker, compose, python) con messaggi chiari
  2. .env: se manca, lo GENERA con segreti casuali forti (nessun placeholder)
  3. build artefatti agenti se assenti (PyInstaller + Maven + JRE + ETW)
  4. avvio piattaforma (compose) + attesa readiness + agenti host + smoke API
  5. bootstrap admin: crea/promuove l'utente admin e stampa le credenziali

Aggiornamento (dopo un git pull, o direttamente):
    python scripts/setup.py update

Fa: verifica repo pulita -> git pull -> rebuild immagini -> riavvio ->
smoke. NON tocca il volume del database: i dati (eventi, alert, utenti,
agenti) sopravvivono all'aggiornamento. Lo schema e' auto-creato
all'avvio (create_all), quindi nessuna migrazione manuale.

Idempotente: rilanciabile quante volte si vuole.
"""
from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import time
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IS_NT = os.name == "nt"
SCRIPTS = os.path.dirname(os.path.abspath(__file__))


def log(msg: str, kind: str = "*") -> None:
    print(f"[{kind}] {msg}", flush=True)


def run(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    """Esegue un comando catturandone l'output.

    Un eseguibile assente (tipico: `docker` non installato su una macchina
    vergine) non deve far esplodere un traceback: e' un prerequisito mancante,
    quindi torna l'exit code 127, che il chiamante gia' interpreta come
    fallimento del comando.
    """
    try:
        return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                              timeout=timeout)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, stdout="",
                                           stderr=f"{cmd[0]}: not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, stdout="",
                                           stderr=f"{cmd[0]}: timeout")


def die(msg: str) -> int:
    log(msg, "!")
    return 1


# ---------------------------------------------------------------- preflight

def preflight() -> int:
    problems = []
    if not run(["docker", "--version"], timeout=30).returncode == 0:
        problems.append("Docker non trovato: installa Docker Desktop e riapri il terminale")
    else:
        info = run(["docker", "info"], timeout=60)
        if info.returncode != 0:
            problems.append("Docker installato ma il daemon non risponde: apri Docker Desktop e rilancia")
    if sys.version_info < (3, 10):
        problems.append(f"Python 3.10+ richiesto (trovato {sys.version.split()[0]})")
    for p in problems:
        log(p, "!")
    return 1 if problems else 0


# -------------------------------------------------------------------- .env

REQUIRED_ENV = ("POSTGRES_PASSWORD", "REDIS_PASSWORD", "DATABASE_URL",
                "AEGIS_API_KEY", "AGENT_ENROLL_KEY", "JWT_SECRET")


def ensure_env() -> str:
    """Ritorna 'created' | 'existing' | 'incomplete:<chiavi>'."""
    path = os.path.join(REPO, ".env")
    if os.path.isfile(path):
        have = set()
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    have.add(line.split("=", 1)[0].strip())
        missing = [k for k in REQUIRED_ENV if k not in have]
        return "existing" if not missing else f"incomplete:{','.join(missing)}"

    log(".env assente: lo genero con segreti casuali forti...")
    pw = secrets.token_hex(16)
    redis_pw = secrets.token_hex(16)
    values = {
        "POSTGRES_USER": "aegis_user",
        "POSTGRES_PASSWORD": pw,
        "POSTGRES_DB": "aegis_db",
        "DATABASE_URL": f"postgresql+asyncpg://aegis_user:{pw}@aegis-postgres:5432/aegis_db",
        "REDIS_PASSWORD": redis_pw,
        "REDIS_URL": f"redis://:{redis_pw}@aegis-redis:6379",
        "REDIS_HOST": "aegis-redis",
        "REDIS_PORT": "6379",
        "POSTGRES_PORT": "5444",
        "BRAIN_PORT_EXTERNAL": "8000",
        "LINK_PORT_EXTERNAL": "8088",
        "OLLAMA_PORT_EXTERNAL": "11435",
        "AEGIS_API_KEY": secrets.token_hex(32),
        "AGENT_ENROLL_KEY": secrets.token_hex(16),
        "JWT_SECRET": secrets.token_hex(32),
        "JWT_ALGORITHM": "HS256",
        "JWT_EXPIRE_MINUTES": "60",
        "ALLOWED_ORIGINS": "http://localhost:3000,http://localhost:5173",
        "VITE_API_URL": "/api/v1",
        "AEGIS_AGENT_ID": "agent-001",
        "AEGIS_SCAN_INTERVAL_MS": "1000",
    }
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Generato da scripts/setup.py — segreti casuali, non condividere.\n")
        for k, v in values.items():
            f.write(f"{k}={v}\n")
    return "created"


# ------------------------------------------------------------------- build

def agents_built() -> bool:
    exe = os.path.join(REPO, "NodeTrace", "agents", "python", "dist",
                       "nodetrace-agent", "nodetrace-agent.exe")
    jar = os.path.join(REPO, "aegis-guard", "target", "aegis-guard.jar")
    return os.path.isfile(exe) and os.path.isfile(jar)


def build_agents() -> int:
    if agents_built():
        log("artefatti agenti gia' presenti: build saltata (usa --force-build per rifarla)")
        return 0
    if not IS_NT:
        log("host non-Windows: salto la build degli agenti endpoint (Guard/NodeTrace girano su Windows)")
        return 0
    log("build agenti (PyInstaller + Maven + JRE + ETW): qualche minuto...")
    r = run(["cmd", "/c", os.path.join(REPO, "build.bat")], timeout=1800)
    if r.returncode != 0:
        log(f"build.bat fallito:\n{(r.stdout or '')[-800:]}\n{(r.stderr or '')[-800:]}", "!")
        return 1
    return 0


# ------------------------------------------------------------------- pilot

def ai_profile_requested() -> bool:
    """AI locale (profilo ollama) solo su richiesta esplicita.

    L'LLM a riposo costa ~850MB di RAM e picchi su tutti i core, per una
    feature di sola sintesi: la detection non ne ha bisogno. Il vecchio
    default avviava Ollama per tutti, anche a chi non lo voleva.
    """
    return os.environ.get("AEGIS_WITH_AI", "").strip() == "1"


def compose_up(profile: str = "light") -> int:
    cmd = ["docker", "compose"]
    if profile == "ollama":
        cmd += ["--profile", "ollama"]
    cmd += ["up", "-d"]
    r = run(cmd, timeout=600)
    if r.returncode != 0:
        log(f"compose up fallito:\n{(r.stderr or r.stdout or '')[-800:]}", "!")
        return 1
    return 0


def wait_ready(base: str, wait: int) -> int:
    sys.path.insert(0, SCRIPTS)
    import pilot  # riuso wait_ready: una sola implementazione della logica
    ok, detail = pilot.wait_ready(base, wait)
    if not ok:
        log(f"backend non ready: {detail}", "!")
        return 1
    log("backend ready.")
    return 0


def start_agents() -> int:
    sys.path.insert(0, SCRIPTS)
    import pilot
    ok, detail = pilot.start_agents()
    log(detail, "+" if ok else "!")
    return 0 if ok else 1


def is_elevated() -> bool:
    """True solo se il processo puo' installare servizi Windows."""
    if not IS_NT:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def install_agent_services() -> bool:
    """Registra NodeTrace e Guard come SERVIZI Windows (autostart al boot).

    Perche' qui e non nel .ps1 a parte: l'autostart e' una proprieta'
    dell'installazione, non un passo manuale da ricordare. Il processo che
    avvia gli agenti e' lo stesso che li rende persistenti — come per Guard,
    che era gia' un servizio NSSM installato dall'installer.

    Ritorna True se i servizi sono stati registrati e avviati (in quel caso
    gli agenti NON vanno lanciati in modalita' dev, altrimenti si avrebbero
    due istanze per endpoint). Senza privilegi: False + istruzioni.
    """
    if not IS_NT:
        return False

    installers = [
        ("NodeTrace", os.path.join(REPO, "NodeTrace", "install", "windows", "install.ps1")),
        ("Guard", os.path.join(REPO, "aegis-guard", "install", "windows", "install.ps1")),
    ]
    available = [(name, path) for name, path in installers if os.path.isfile(path)]
    if not available:
        return False

    if not is_elevated():
        log("autostart: servizi agenti NON registrati (serve PowerShell elevato)", "!")
        print("  Per renderli persistenti (una volta sola, da shell admin):")
        for name, path in available:
            print(f"    powershell -ExecutionPolicy Bypass -File {os.path.relpath(path, REPO)}")
        print("  Alternativa senza admin (Scheduled Task al logon):")
        print("    powershell -ExecutionPolicy Bypass -File "
              "scripts\\install-agents-autostart.ps1")
        return False

    registered = True
    for name, path in available:
        log(f"registro il servizio {name} (autostart al boot)...")
        r = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path],
                timeout=600)
        tail = (r.stdout or "").strip().splitlines()[-3:]
        for line in tail:
            print(f"    {line}")
        if r.returncode != 0:
            log(f"servizio {name}: registrazione fallita (exit {r.returncode})", "!")
            registered = False
        else:
            log(f"servizio {name}: installato e avviato", "+")
    return registered


def run_smoke(base: str, email: str, password: str) -> int:
    r = run([sys.executable, os.path.join(SCRIPTS, "api_smoke.py"), "--base", base,
             "--email", email, "--password", password], timeout=300)
    print(r.stdout[-1500:])
    return r.returncode


# ---------------------------------------------------------------- bootstrap

def read_env() -> dict[str, str]:
    out = {}
    path = os.path.join(REPO, ".env")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def write_env_pair(key: str, value: str) -> None:
    """Aggiorna (o appende) una chiave nel .env senza toccare le altre."""
    path = os.path.join(REPO, ".env")
    lines = []
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    for i, line in enumerate(lines):
        if line.split("=", 1)[0].strip() == key:
            lines[i] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


def bootstrap_admin(env: dict[str, str], email: str | None, password: str | None) -> tuple[str, str]:
    """Crea/promuove l'admin e ritorna (email, password) effettive."""
    email = email or env.get("AEGIS_ADMIN_EMAIL") or "admin@aegis.local"
    password = password or env.get("AEGIS_ADMIN_PASSWORD") or secrets.token_urlsafe(12)

    in_container = run(["docker", "exec", "aegis-brain", "python", "-c", "1"], timeout=30)
    if in_container.returncode == 0:
        r = run(["docker", "exec", "aegis-brain", "python", "-m", "app.admin",
                 "bootstrap", email, password], timeout=120)
        if r.returncode != 0:
            log(f"bootstrap fallito:\n{(r.stdout or '')[-500:]}", "!")
            return "", ""
    else:
        # Setup senza container attivi (es. prima esecuzione di update): riprova dopo.
        log("container brain non raggiungibile: bootstrap rimandato", "!")
        return "", ""

    # Persisti le credenziali nel .env cosi' il re-run e' idempotente e ritrovabile.
    write_env_pair("AEGIS_ADMIN_EMAIL", email)
    write_env_pair("AEGIS_ADMIN_PASSWORD", password)
    return email, password


# ------------------------------------------------------------------ update

def cmd_update(args) -> int:
    git = run(["git", "status", "--porcelain"], timeout=30)
    if git.returncode != 0:
        return die("non e' una repo git: aggiorna manualmente")
    if git.stdout.strip() and not args.force:
        return die("working tree sporco: committa o stasha prima di aggiornare "
                   "(oppure --force per procedere comunque)")
    log("git pull...")
    pull = run(["git", "pull", "--ff-only"], timeout=120)
    print((pull.stdout or "").strip()[-400:])
    if pull.returncode != 0:
        return die(f"git pull fallito:\n{(pull.stderr or '')[-500:]}")

    log("rebuild immagini (il database NON viene toccato)...")
    b = run(["docker", "compose", "build", "aegis-brain", "aegis-link", "aegis-frontend"],
            timeout=1800)
    if b.returncode != 0:
        return die(f"build immagini fallita:\n{(b.stderr or '')[-800:]}")
    if ai_profile_requested():
        log("profilo AI locale attivo (AEGIS_WITH_AI=1): avvio anche ollama")
    if compose_up("ollama" if ai_profile_requested() else "light") != 0:
        return 1
    if wait_ready("http://127.0.0.1:8000", args.wait) != 0:
        return 1
    log("aggiornamento completato: dati preservati (volume DB intatto, "
        "schema auto-creato all'avvio).")

    if args.rebuild_agents and IS_NT:
        if build_agents() != 0:
            log("agenti non ricompilati: la piattaforma e' comunque aggiornata", "!")
    elif agents_built():
        log("agenti host: artefatti presenti (usa --rebuild-agents per ricompilarli)")

    env = read_env()
    email, password = bootstrap_admin(env, args.email, args.password)
    if email:
        log(f"admin operativo: {email}")
    rc = run_smoke("http://127.0.0.1:8000", email, password) if email else 1
    return 0 if rc == 0 else 1


# -------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(prog="setup.py",
                                 description="Installa o aggiorna Aegis con un solo comando.")
    sub = ap.add_subparsers(dest="command")
    up = sub.add_parser("update", help="git pull + rebuild + riavvio (dati preservati)")
    up.add_argument("--force", action="store_true", help="procedi anche con working tree sporco")
    up.add_argument("--rebuild-agents", action="store_true", help="ricompila anche gli agenti host")
    up.add_argument("--wait", type=int, default=120)
    up.add_argument("--email")
    up.add_argument("--password")

    ap.add_argument("--email", help="email admin (default: admin@aegis.local o quella nel .env)")
    ap.add_argument("--password", help="password admin (default: generata e salvata nel .env)")
    ap.add_argument("--no-agents", action="store_true", help="non avviare gli agenti host")
    ap.add_argument("--no-autostart", action="store_true",
                    help="non registrare gli agenti come servizi Windows (solo avvio dev)")
    ap.add_argument("--force-build", action="store_true", help="ricompila gli artefatti anche se presenti")
    ap.add_argument("--skip-build", action="store_true", help="salta la build degli artefatti")
    args = ap.parse_args()

    if args.command == "update":
        return cmd_update(args)

    log("=== AEGIS SETUP ===")
    if preflight() != 0:
        return 1

    status = ensure_env()
    if status.startswith("incomplete"):
        missing = status.split(":", 1)[1]
        return die(f".env esistente ma incompleto (manca: {missing}). "
                   "Completa le chiavi manualmente o cancella .env per rigenerarlo.")
    if status == "created":
        log(".env creato con segreti casuali.", "+")

    if not args.skip_build:
        if build_agents() != 0:
            return 1

    if ai_profile_requested():
        log("profilo AI locale attivo (AEGIS_WITH_AI=1): avvio anche ollama")
    else:
        log("avvio leggero: ollama non parte (AI locale con AEGIS_WITH_AI=1)")
    if compose_up("ollama" if ai_profile_requested() else "light") != 0:
        return 1
    if wait_ready("http://127.0.0.1:8000", 180) != 0:
        return 1

    # Bootstrap PRIMA di agenti e smoke: il .env riceve le credenziali admin
    # che poi pilot/smoke riutilizzano (un'unica fonte, nessun doppio prompt).
    env = read_env()
    email, password = bootstrap_admin(env, args.email, args.password)
    if not email:
        return 1
    log(f"admin pronto: {email}", "+")

    if not args.no_agents:
        # Prima i servizi (persistono al reboot), poi — solo se NON registrati —
        # l'avvio dev. Mai entrambi: due istanze per endpoint = telemetria doppia.
        services_up = False if args.no_autostart else install_agent_services()
        if services_up:
            log("agenti gestiti dai servizi Windows (ripartono da soli al boot)", "+")
        else:
            if start_agents() != 0:
                log("agenti non avviati: la piattaforma resta utilizzabile", "!")
        time.sleep(8)

    if run_smoke("http://127.0.0.1:8000", email, password) != 0:
        return 1

    print()
    log("=== AEGIS PRONTO ===", "+")
    print(f"  Dashboard:   http://localhost:3000   (login: {email})")
    print(f"  Password:    {password}   (salvata anche in .env: AEGIS_ADMIN_PASSWORD)")
    print(f"  API:         http://127.0.0.1:8000/api/v1")
    print(f"  Aggiornare?  python scripts/setup.py update")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
