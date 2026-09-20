"""Batteria live v2: enroll reale (token deploy), poi benigni vs attacchi vs resolve.

Flusso identico a quello di un agente vero: token di deploy monouso -> /enroll
-> agent_id + agent_secret -> ingest firmata con il segreto del device.

Credenziali dashboard via env (niente segreti nel repo):
  AEGIS_EMAIL / AEGIS_PASSWORD (o E2E_EMAIL / E2E_PASSWORD)
"""
import os
import requests, time, uuid, sys
from datetime import datetime, timezone

B = "http://127.0.0.1:8000"
EMAIL = os.getenv("AEGIS_EMAIL") or os.getenv("E2E_EMAIL") or ""
PASSWORD = os.getenv("AEGIS_PASSWORD") or os.getenv("E2E_PASSWORD") or ""
assert EMAIL and PASSWORD, "set AEGIS_EMAIL / AEGIS_PASSWORD (dashboard credentials)"

B = "http://127.0.0.1:8000"
def fresh():
    s = requests.Session(); s.trust_env = False
    s.headers["Origin"] = "http://localhost:3000"
    return s

ok = 0
fail = []
def check(name, cond, extra=""):
    global ok
    if cond: ok += 1; print(f"  [ok] {name}")
    else: fail.append(name); print(f"  [FAIL] {name} {extra}")

S = fresh()
r = S.post(f"{B}/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}, timeout=15)
assert r.status_code == 200, r.text[:200]
H = {"Authorization": f"Bearer {r.json()['access_token']}"}
print("1) login admin ok")

def enroll(host):
    host = f"{host}-{int(time.time())}"
    r = S.post(f"{B}/api/v1/deploy/token", headers=H,
               json={"label": f"bat-{host}", "agent_type": "nodetrace", "ttl_minutes": 30}, timeout=15)
    assert r.status_code == 200, f"deploy/token: {r.status_code} {r.text[:150]}"
    tok = r.json()["token"]
    r = S.post(f"{B}/api/v1/enroll/enroll", json={
        "hostname": host, "os": "Windows", "enroll_key": tok,
        "agent_type": "nodetrace"}, timeout=15)
    assert r.status_code == 200, f"enroll: {r.status_code} {r.text[:200]}"
    d = r.json()
    return d["agent_id"], d["agent_secret"]

AG_CLEAN, SEC_CLEAN = enroll("bat-clean")
AG_EVIL, SEC_EVIL = enroll("bat-evil")
check("enroll due agenti (flusso reale con token deploy)", True)
AH_CLEAN = {"X-Agent-Id": AG_CLEAN, "Authorization": f"Bearer {SEC_CLEAN}"}
AH_EVIL = {"X-Agent-Id": AG_EVIL, "Authorization": f"Bearer {SEC_EVIL}"}

def report(ah, agent_id, **ev):
    base = {"agent_id": agent_id,
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "PROCESS_CREATED",
            "pid": 10000}
    base.update(ev)
    return S.post(f"{B}/api/v1/telemetry/report", json=base, headers=ah, timeout=15)

# ── 2) benigni: zero alert attesi ────────────────────────────────────────────
print("2) rumore benigno (attesi 0 alert)")
BENIGN = [
    dict(process_name="Code.exe", process_path="C:\\Users\\dev\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
         signature="authenticode-trusted", publisher="Microsoft Corporation"),
    dict(process_name="curl.exe", process_path="C:\\Program Files\\Git\\mingw64\\bin\\curl.exe",
         signature="authenticode-trusted", publisher="curl Foundation"),
    dict(process_name="pwsh.exe", process_path="C:\\Program Files\\PowerShell\\7\\pwsh.exe",
         signature="authenticode-trusted", publisher="Microsoft Corporation",
         command_line="pwsh.exe -Command Get-Process"),
    dict(process_name="node.exe", process_path="C:\\Program Files\\nodejs\\node.exe",
         signature="authenticode-trusted", publisher="OpenJS Foundation"),
    dict(process_name="npm.cmd", process_path="C:\\Program Files\\nodejs\\npm.cmd",
         signature="authenticode-trusted", publisher="OpenJS Foundation"),
]
for ev in BENIGN:
    r = report(AH_CLEAN, AG_CLEAN, **ev)
    check(f"report {ev['process_name']} accettato", r.status_code == 200, str(r.status_code))

# ── 3) attacchi: alert attesi con severita' ─────────────────────────────────
print("3) attacchi (alert attesi)")
ATTACKS = [
    ("mimikatz", dict(process_name="mimikatz.exe", process_path="C:\\Users\\dev\\AppData\\Local\\Temp\\mimikatz.exe",
                      command_line="mimikatz.exe sekurlsa::logonpasswords"), "CRITICAL"),
    ("run key", dict(process_name="reg.exe", process_path="C:\\Windows\\System32\\reg.exe",
                     command_line="reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\Users\\Public\\evil.exe /f"), "HIGH"),
    ("procdump lsass", dict(process_name="procdump.exe", process_path="C:\\Users\\Public\\procdump.exe",
                            command_line="procdump.exe -ma lsass.exe out.dmp"), "CRITICAL"),
    ("windefend disable", dict(process_name="cmd.exe", process_path="C:\\Windows\\System32\\cmd.exe",
                               command_line="cmd.exe /c sc config WinDefend start= disabled"), "CRITICAL"),
    ("log clearing", dict(process_name="wevtutil.exe", process_path="C:\\Windows\\System32\\wevtutil.exe",
                          command_line="wevtutil cl Security"), "CRITICAL"),
]
for name, ev, sev in ATTACKS:
    r = report(AH_EVIL, AG_EVIL, **ev)
    check(f"report attacco {name} accettato", r.status_code == 200, str(r.status_code))

time.sleep(2)

# ── 4) verifica alert ────────────────────────────────────────────────────────
print("4) conteggio alert per agente")
def alerts_for(agent_id, resolved=None):
    q = "?limit=1000"
    if resolved is not None:
        q += f"&is_resolved={'true' if resolved else 'false'}"
    r = S.get(f"{B}/api/v1/telemetry/alerts{q}", headers=H, timeout=15)
    assert r.status_code == 200, r.text[:200]
    return [a for a in r.json() if str(a.get("agent_id")) == agent_id]

open_clean = alerts_for(AG_CLEAN, resolved=False)
check("benigni: ZERO alert aperti", len(open_clean) == 0,
      f"{[(a.get('process_name'), a.get('description','')[:70]) for a in open_clean[:3]]}")

open_evil = alerts_for(AG_EVIL, resolved=False)
check("attacchi: >=5 alert aperti", len(open_evil) >= 5, str(len(open_evil)))
for name, ev, sev in ATTACKS:
    got = [a for a in open_evil
           if name.split()[0] in str(a.get("description", "")).lower()
           or name.split()[0] in str(a.get("process_name", "")).lower()]
    check(f"attacco '{name}' -> alert {sev}", len(got) >= 1
          and any(a.get("severity") == sev for a in got),
          f"{[(a.get('severity'), a.get('description','')[:60]) for a in got[:2]]}")

# ── 5) ciclo resolve visibile in tutte le viste ──────────────────────────────
print("5) ciclo resolve")
if open_evil:
    target = open_evil[0]
    r = S.patch(f"{B}/api/v1/telemetry/alerts/{target['id']}/resolve",
                json={"resolved": True}, headers=H, timeout=15)
    check("PATCH resolve 200", r.status_code == 200, r.text[:120])
    time.sleep(1)
    check("resolved visibile via is_resolved=true",
          any(a["id"] == target["id"] for a in alerts_for(AG_EVIL, resolved=True)))
    check("resolved NON piu' in unresolved",
          all(a["id"] != target["id"] for a in alerts_for(AG_EVIL, resolved=False)))
    check("resolved visibile nella lista completa",
          target["id"] in {a["id"] for a in alerts_for(AG_EVIL)})
    r = S.post(f"{B}/api/v1/telemetry/alerts/resolve-all", headers=H, timeout=15)
    check("resolve-all 200", r.status_code == 200, r.text[:100])
    time.sleep(1)
    check("dopo resolve-all: zero aperti", len(alerts_for(AG_EVIL, resolved=False)) == 0)
    check("dopo resolve-all: tutti in Resolved", len(alerts_for(AG_EVIL, resolved=True)) >= 1)

print(f"\nRISULTATO: {ok} ok, {len(fail)} falliti")
if fail:
    print("Falliti:", fail); sys.exit(1)
