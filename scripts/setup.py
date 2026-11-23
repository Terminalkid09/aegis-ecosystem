#!/usr/bin/env python3
"""Aegis setup in UN comando — installazione e aggiornamento.

Installazione (da repo appena clonata):
    python scripts/setup.py

Fa tutto, nell'ordine:
  1. preflight dipendenze (docker, compose, python) con messaggi chiari
  2. .env: se manca, lo GENERA con segreti casuali forti (nessun placeholder)
  3. avvio piattaforma (compose) + attesa readiness + smoke API
  4. bootstrap admin: crea/promuove l'utente admin e stampa le credenziali

Gli agenti endpoint non vengono piu' compilati o installati da questo script:
la 4.3 li installa dalla Deployment Manager con un token monouso e l'archivio
unified pubblicato. Guard/NodeTrace restano solo nel sorgente per i 4.2.1
gia' installati.

Aggiornamento (dopo un git pull, o direttamente):
    python scripts/setup.py update

Fa: verifica repo pulita -> git pull -> rebuild immagini -> riavvio ->
smoke. NON tocca il volume del database: i dati (eventi, alert, utenti,
agenti) sopravvivono all'aggiornamento. Le migrazioni (Alembic) girano da
sole all'avvio del brain, quindi nessun passo manuale sullo schema.

Idempotente: rilanciabile quante volte si vuole.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

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

def free_tcp_port(preferred: int = 3000) -> int:
    """Return a usable local dashboard port.

    Port 3000 is frequently occupied by a dev server on a workstation. Prefer
    the configured value, then try 3000-3099; never silently reuse a port that
    is already listening.
    """
    candidates = [preferred] + [p for p in range(3000, 3100) if p != preferred]
    for port in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free dashboard port in 3000-3099")


def preflight() -> int:
    problems = []
    if not run(["docker", "--version"], timeout=30).returncode == 0:
        problems.append("Docker non trovato: installa Docker Desktop e riapri il terminale")
    else:
        info = run(["docker", "info"], timeout=60)
        if info.returncode != 0:
            problems.append("Docker installato ma il daemon non risponde: apri Docker Desktop e rilancia")
    if sys.version_info < (3, 15):
        problems.append(f"Python 3.15+ richiesto (trovato {sys.version.split()[0]})")
    for p in problems:
        log(p, "!")
    return 1 if problems else 0


# -------------------------------------------------------------------- .env

REQUIRED_ENV = ("POSTGRES_PASSWORD", "REDIS_PASSWORD", "DATABASE_URL",
                "AEGIS_API_KEY", "AGENT_ENROLL_KEY", "JWT_SECRET",
                "MASTER_KEY_B64")


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
    # The compose file marks MASTER_KEY_B64 as required. A fresh clone must get
    # a valid 32-byte key here, otherwise `setup.py` generates a .env that
    # immediately fails at `docker compose up`.
    master_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    domain = (os.environ.get("AEGIS_DOMAIN") or "aegis.local").strip()
    acme_email = (os.environ.get("ACME_EMAIL") or "internal").strip()
    try:
        ui_port = int(os.environ.get("AEGIS_UI_PORT") or free_tcp_port())
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(f"AEGIS_UI_PORT: {exc}") from exc
    if domain not in ("aegis.local", "localhost") and acme_email == "internal":
        log("ATTENZIONE: AEGIS_DOMAIN e' un dominio pubblico ma ACME_EMAIL=internal; "
            "Caddy userebbe la CA interna. Imposta ACME_EMAIL con un indirizzo reale.")
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
        "AEGIS_UI_PORT": str(ui_port),
        "AEGIS_API_KEY": secrets.token_hex(32),
        "AGENT_ENROLL_KEY": secrets.token_hex(16),
        "JWT_SECRET": secrets.token_hex(32),
        "MASTER_KEY_B64": master_key,
        "JWT_ALGORITHM": "HS256",
        "JWT_EXPIRE_MINUTES": "60",
        # Only the direct localhost dashboard is plain HTTP. Aegis.local is
        # served by Caddy over HTTPS, so its cookie must remain Secure even
        # though the hostname is not a public FQDN. The local port is selected
        # above because 3000 is often occupied on a workstation.
        "AEGIS_DEBUG": "false",
        "AEGIS_ALLOW_OPEN_REGISTRATION": "false",
        "AEGIS_COOKIE_SECURE": "false" if domain == "localhost" else "true",
        # Caddy domain/TLS. A real FQDN + real ACME email uses Let's Encrypt;
        # the lab default uses Caddy's internal CA.
        "AEGIS_DOMAIN": domain,
        "ACME_EMAIL": acme_email,
        # Include the Caddy HTTPS origin: without it, cookie-authenticated
        # POST/PATCH requests through https://<domain> fail CSRF checks with
        # 403 even though the dashboard loads correctly. PUBLIC_BASE_URL is
        # used by OIDC callbacks and deployment links and must match.
        "ALLOWED_ORIGINS": f"https://{domain},http://localhost:{ui_port},http://localhost:5173",
        "PUBLIC_BASE_URL": f"https://{domain}",
        "VITE_API_URL": "/api/v1",
        "AEGIS_AGENT_ID": "agent-001",
        "AEGIS_SCAN_INTERVAL_MS": "1000",
        # Kraken is an optional compose profile, but a fresh clone should be
        # able to start it without hand-editing secrets. These values are
        # independent from the Brain secrets above.
        "KRAKEN_DB_PASSWORD": secrets.token_hex(16),
        "KRAKEN_REDIS_PASSWORD": secrets.token_hex(16),
        "KRAKEN_SECRET_KEY": secrets.token_hex(32),
        "KRAKEN_INTERNAL_API_KEY": secrets.token_hex(32),
        "KRAKEN_SSO_ENABLED": "true",
        "KRAKEN_SSO_SECRET": secrets.token_hex(32),
        "KRAKEN_INGEST_ENABLED": "false",
        "KRAKEN_INGEST_KEY": secrets.token_hex(32),
        "KRAKEN_INGEST_SECRET": secrets.token_hex(32),
        "SANDBOX_BROKER_TOKEN": secrets.token_hex(32),
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


# ---------------------------------------------------------------- binaries
# Due binari Windows che servono a due feature precise:
#   nssm    -> registra gli agenti come servizi (autostart al boot)
#   yara64  -> scansioni YARA on-demand sull'endpoint
# Prima andavano scaricati a mano: meta' installazione si fermava con un
# "copy nssm.exe here" scoperto a installazione avviata. Ora si scaricano da
# soli, con SHA-256 PINNATO: l'hash e' il controllo che il binario e' quello
# atteso (niente fiducia cieca sul CDN) e viene verificato DUE volte —
# sull'archivio e sul singolo eseguibile estratto. Se la rete manca o l'hash
# non torna non si installa nulla: si dice cosa mettere a mano e dove.
#
# Gli .exe sono in .gitignore: chi clona non li prende dal repo, li prende da
# qui (o a mano). Vedi README, "optional extras".
VENDOR_BINARIES: dict[str, dict] = {
    "nssm": {
        "url": "https://nssm.cc/release/nssm-2.24.zip",
        "sha256": "727d1e42275c605e0f04aba98095c38a8e1e46def453cdffce42869428aa6743",
        "member": "nssm-2.24/win64/nssm.exe",
        "exe_sha256": "f689ee9af94b00e9e3f0bb072b34caaf207f32dcb4f5782fc9ca351df9a06c97",
        "targets": [os.path.join(REPO, "aegis-guard", "install", "windows", "nssm.exe")],
        "why": "servizi Windows per Guard e NodeTrace (autostart al boot)",
        "manual": ("scarica https://nssm.cc/download, prendi win64/nssm.exe "
                   "e copialo in aegis-guard/install/windows/"),
    },
    "yara64": {
        "url": ("https://github.com/VirusTotal/yara/releases/download/v4.5.5/"
                "yara-4.5.5-2368-win64.zip"),
        "sha256": "352396c8a3d9b31b157a4820abd3b9347fc934a2314cdda8a4f566a5570163e4",
        "member": "yara64.exe",
        "exe_sha256": "1c45eb279d820aba81fd41c22384428ebe44037cf5793be4b52a9d3b3df62b33",
        # Sorgente per l'installer + copia nel workdir di Guard gia' in uso.
        "targets": [
            os.path.join(REPO, "aegis-guard", "install", "windows", "bin", "yara64.exe"),
            os.path.join(REPO, "aegis-guard", "bin", "yara64.exe"),
        ],
        "why": "scansioni YARA on-demand sugli endpoint",
        "manual": ("scarica yara64.exe (win64, 4.5.x) da "
                   "https://github.com/VirusTotal/yara/releases e mettilo in "
                   "aegis-guard/install/windows/bin/"),
    },
}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: str, timeout: int = 180) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "aegis-setup"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as out:
        shutil.copyfileobj(resp, out)


def ensure_binary(name: str, force: bool = False) -> bool:
    """Installa un binario vendor se manca. True = presente e integro.

    Non alza eccezioni: qualunque problema diventa un messaggio con la via
    manuale, perche' l'installazione della piattaforma non deve morire per
    un binario opzionale (le feature che lo usano degradano, e lo dicono).
    """
    spec = VENDOR_BINARIES[name]
    if not IS_NT:
        # Gli agenti endpoint sono Windows-only: altrove il binario non serve.
        log(f"{name}: host non-Windows, salto (serve agli agenti Windows)")
        return True

    targets = spec["targets"]
    if not force and all(os.path.isfile(t) for t in targets):
        log(f"{name}: gia' presente")
        return True

    log(f"{name}: scarico {spec['url'].rsplit('/', 1)[-1]}...")
    tmpdir = tempfile.mkdtemp(prefix=f"aegis-{name}-")
    try:
        pkg = os.path.join(tmpdir, "pkg.zip")
        try:
            _download(spec["url"], pkg)
        except Exception as exc:  # rete assente, 404, timeout...
            log(f"{name}: download non riuscito ({exc}).", "!")
            log(f"    serve per: {spec['why']}", "!")
            log(f"    a mano: {spec['manual']}", "!")
            return False

        got = _sha256(pkg)
        if got.lower() != spec["sha256"].lower():
            log(f"{name}: SHA-256 dell'archivio NON corrisponde: scartato.", "!")
            log(f"    atteso:  {spec['sha256']}", "!")
            log(f"    trovato: {got}", "!")
            log(f"    a mano: {spec['manual']}", "!")
            return False

        try:
            with zipfile.ZipFile(pkg) as zf:
                member = next((n for n in zf.namelist()
                               if n.replace("\\", "/") == spec["member"]), None)
                if member is None:
                    log(f"{name}: {spec['member']} non presente nell'archivio", "!")
                    return False
                extracted = os.path.join(tmpdir, os.path.basename(member))
                with zf.open(member) as src, open(extracted, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        except zipfile.BadZipFile:
            log(f"{name}: archivio illeggibile (download interrotto?)", "!")
            return False

        exe_hash = _sha256(extracted)
        if exe_hash.lower() != spec["exe_sha256"].lower():
            log(f"{name}: hash dell'eseguibile non corrisponde: non installo.", "!")
            log(f"    atteso:  {spec['exe_sha256']}\n    trovato: {exe_hash}", "!")
            return False

        for target in targets:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copyfile(extracted, target)
        log(f"{name}: installato e verificato ({spec['exe_sha256'][:12]}...) "
            f"per {spec['why']}", "+")
        return True
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def ensure_binaries(force: bool = False) -> int:
    """Binari vendor mancanti. 0 = tutti a posto, 1 = qualcosa manca.

    Non e' fatale: senza nssm gli agenti girano in modalita' dev, senza yara64
    le scansioni YARA dichiarano di essere disattivate. Il chiamante avvisa e
    prosegue, perche' la piattaforma non dipende da questi due binari.
    """
    ok = True
    for name in VENDOR_BINARIES:
        ok = ensure_binary(name, force=force) and ok
    return 0 if ok else 1


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


def bootstrap_pki() -> int:
    """Create the CA/manifest key once, before any agent installer is served.

    The one-liner needs the Ed25519 manifest public key. Without it the
    installer fails closed with 503, which is correct but makes a fresh clone
    look broken. This is idempotent: an existing ca.crt is left untouched and
    the CA private key is never read or printed.
    """
    present = run(["docker", "compose", "exec", "-T", "aegis-brain",
                   "test", "-f", "/app/pki/ca.crt"], timeout=30)
    if present.returncode == 0:
        return 0
    log("PKI bootstrap (CA + manifest key)...")
    r = run(["docker", "compose", "exec", "-T", "aegis-brain",
             "python", "-m", "app.services.pki", "--dir", "/app/pki"], timeout=120)
    if r.returncode != 0:
        log(f"PKI bootstrap fallito:\n{(r.stderr or r.stdout or '')[-800:]}", "!")
        return 1
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
    if not email or not password:
        log("smoke autenticato saltato: password admin non disponibile "
            "(re-run con AEGIS_ADMIN_PASSWORD_FILE per eseguirlo)", "!")
        return 0
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


def _configured_admin_password(env: dict[str, str]) -> str:
    """Password from --password, environment or a mounted secret file."""
    password = (env.get("AEGIS_ADMIN_PASSWORD") or "").strip()
    if password:
        return password
    path = (os.environ.get("AEGIS_ADMIN_PASSWORD_FILE") or "").strip()
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def admin_exists() -> bool:
    """True if at least one admin already exists. Used to keep re-runs non-destructive."""
    r = run(["docker", "exec", "aegis-brain", "python", "-m", "app.admin", "list"], timeout=60)
    if r.returncode != 0:
        return False
    out = (r.stdout or "") + (r.stderr or "")
    match = re.search(r"admin:\s*(\d+)", out)
    return bool(match and int(match.group(1)) > 0)


def bootstrap_admin(env: dict[str, str], email: str | None, password: str | None) -> tuple[str, str]:
    """Create/promote the first admin without persisting its password.

    The password is generated once, printed once and never written to .env.
    On a re-run an existing admin is left untouched: silently resetting it to a
    new generated value would lock the operator out of the account they had.
    For automation, supply AEGIS_ADMIN_PASSWORD or AEGIS_ADMIN_PASSWORD_FILE.
    """
    email = email or env.get("AEGIS_ADMIN_EMAIL") or "admin@aegis.local"
    configured = (password or _configured_admin_password(env)).strip()

    in_container = run(["docker", "exec", "aegis-brain", "python", "-c", "1"], timeout=30)
    if in_container.returncode != 0:
        # Setup senza container attivi (es. prima esecuzione di update): riprova dopo.
        log("container brain non raggiungibile: bootstrap rimandato", "!")
        return "", ""

    if not configured and admin_exists():
        log("admin già presente: password non modificata e non salvata in .env", "+")
        write_env_pair("AEGIS_ADMIN_EMAIL", email)
        return email, ""

    password = configured or secrets.token_urlsafe(18)
    r = run(["docker", "exec", "aegis-brain", "python", "-m", "app.admin",
             "bootstrap", email, password], timeout=120)
    if r.returncode != 0:
        out = (r.stdout or "") + (r.stderr or "")
        if "password non corrisponde" in out:
            log("admin esistente con una password diversa: non la resetto", "!")
            write_env_pair("AEGIS_ADMIN_EMAIL", email)
            return email, ""
        log(f"bootstrap fallito:\n{(r.stdout or '')[-500:]}", "!")
        return "", ""

    # Solo l'email è configurazione; la password resta fuori dal file.
    write_env_pair("AEGIS_ADMIN_EMAIL", email)
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
    if bootstrap_pki() != 0:
        return 1
    log("aggiornamento completato: dati preservati (volume DB intatto, "
        "migrazioni applicate all'avvio).")

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
    up.add_argument("--wait", type=int, default=120)
    up.add_argument("--email")
    up.add_argument("--password")

    ap.add_argument("--email", help="email admin (default: admin@aegis.local o quella nel .env)")
    ap.add_argument("--password", help="password admin (default: generata e mostrata una sola volta)")
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

    if ai_profile_requested():
        log("profilo AI locale attivo (AEGIS_WITH_AI=1): avvio anche ollama")
    else:
        log("avvio leggero: ollama non parte (AI locale con AEGIS_WITH_AI=1)")
    if compose_up("ollama" if ai_profile_requested() else "light") != 0:
        return 1
    if wait_ready("http://127.0.0.1:8000", 180) != 0:
        return 1
    if bootstrap_pki() != 0:
        return 1

    # Bootstrap PRIMA di agenti e smoke: il .env riceve le credenziali admin
    # che poi pilot/smoke riutilizzano (un'unica fonte, nessun doppio prompt).
    env = read_env()
    email, password = bootstrap_admin(env, args.email, args.password)
    if not email:
        return 1
    log(f"admin pronto: {email}", "+")

    if run_smoke("http://127.0.0.1:8000", email, password) != 0:
        return 1

    print()
    log("=== AEGIS PRONTO ===", "+")
    env = read_env()
    ui_port = env.get("AEGIS_UI_PORT", "3000")
    print(f"  Dashboard:   http://localhost:{ui_port}   (login: {email})")
    if password:
        print(f"  Password:    {password}   (mostrata una sola volta, NON salvata in .env)")
    else:
        print("  Password:    invariata (admin già esistente); usa AEGIS_ADMIN_PASSWORD_FILE per l'automazione)")
    print(f"  API:         http://127.0.0.1:8000/api/v1")
    print(f"  Aggiornare?  python scripts/setup.py update")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
