#!/usr/bin/env python3
"""API smoke end-to-end contro lo stack live.

Due livelli, e il secondo **non si salta in silenzio**:

  **A — pubblico** (nessuna credenziale)
      `/health/live`, `/health/ready`, `/metrics`.

  **B — autenticato ed end-to-end**
      login -> catalogo parser -> ingestione di un log reale -> evento
      normalizzato e ricercabile -> detection Sigma -> alert con tecnica MITRE,
      idempotenza dell'event_id, diagnosi sui payload non riconosciuti,
      enforcement del RBAC coerente col ruolo dichiarato.

Perché esiste: i test unitari verificano le funzioni una per una; questo
verifica che **lo stack montato** (brain + Postgres + Redis + migrazioni +
regole caricate) faccia il percorso completo. Un componente che passa i test e
non è cablato nell'applicazione non lo scopri con pytest. Lo scopri qui.

Uso:
    python scripts/api_smoke.py --email admin@aegis.com --password '...'
    python scripts/api_smoke.py --public-only
    AEGIS_SMOKE_EMAIL=... AEGIS_SMOKE_PASSWORD=... python scripts/api_smoke.py

Exit: 0 = ALL PASS, 1 = almeno un FAIL, 2 = run impossibile (es. credenziali
mancanti senza `--public-only`).
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

CHECKS = []


def check(name, fn, level="B"):
    """Esegue un controllo. Un'eccezione qualsiasi è un FAIL, non un crash."""
    try:
        detail = fn()
        CHECKS.append({"name": name, "level": level, "status": "pass", "detail": detail})
    except Exception as e:  # noqa: BLE001 - smoke: ogni errore e' un FAIL
        CHECKS.append({"name": name, "level": level, "status": "fail", "detail": str(e)[:300]})


def get(base, path, timeout=10):
    req = urllib.request.Request(base + path, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


class ApiError(Exception):
    """Errore HTTP con corpo leggibile: senza il corpo, un 422 è indistinguibile."""

    def __init__(self, status, body):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {body[:200]}")


def call(base, method, path, body=None, token=None, api_key=None, timeout=15):
    """Chiamata JSON. Ritorna (status, parsed). Solleva ApiError sui 4xx/5xx."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if api_key:
        req.add_header("X-Api-Key", api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        raise ApiError(e.code, raw) from None


def expect_status(fn, wanted, label=""):
    """Esegue fn e pretende uno status preciso; se no, FAIL con il corpo.

    Utile per verificare i percorsi di errore: un 422 con diagnosi è corretto,
    un 200 silenzioso su un payload non riconosciuto è il bug.
    """
    try:
        fn()
    except ApiError as e:
        if e.status == wanted:
            return e.body
        raise AssertionError(f"{label}: atteso HTTP {wanted}, ricevuto {e.status}") from None
    raise AssertionError(f"{label}: atteso HTTP {wanted}, ricevuto 2xx")


SYSLOG_LINE = (
    "<34>{ts} smoke-host sshd[4242]: Failed password for invalid user admin "
    "from 203.0.113.77 port 51234 ssh2"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--email", default=os.getenv("AEGIS_SMOKE_EMAIL"))
    ap.add_argument("--password", default=os.getenv("AEGIS_SMOKE_PASSWORD"))
    ap.add_argument("--public-only", action="store_true",
                    help="esegue solo i controlli senza credenziali (run incompleto, esplicito)")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    # ---------------------------------------------------------------- livello A
    def live():
        status, body = get(base, "/health/live")
        assert status == 200, f"HTTP {status}"
        data = json.loads(body)
        assert data.get("status") == "alive", data
        assert "checks" not in data, "liveness deve essere alive-only (audit F4)"
        return f"alive, uptime_s={data.get('uptime_s')}"

    def ready():
        status, body = get(base, "/health/ready")
        assert status == 200, f"HTTP {status}"
        data = json.loads(body)
        assert data.get("status") in {"ready", "not_ready"}, data
        checks = data.get("checks", {})
        for name in ("database", "redis", "pipeline", "pki", "mtls"):
            assert name in checks, f"check mancante: {name}"
        return f"{data['status']}: " + ", ".join(
            f"{k}={v.get('status')}" for k, v in checks.items())

    def metrics():
        status, body = get(base, "/metrics")
        assert status == 200, f"HTTP {status}"
        text = body.decode("utf-8", errors="replace")
        assert "aegis_http_requests_total" in text, "metrica http assente"
        assert "# TYPE " in text and "# HELP " in text, "directive Prometheus assenti"
        return f"{len(text.splitlines())} righe exposition"

    check("liveness alive-only", live, level="A")
    check("readiness full checks", ready, level="A")
    check("metrics exposition", metrics, level="A")

    if args.public_only:
        return _report(base, args, note="--public-only: livello B non eseguito")

    if not (args.email and args.password):
        print("Credenziali mancanti. Passa --email/--password (o AEGIS_SMOKE_EMAIL/"
              "AEGIS_SMOKE_PASSWORD), oppure --public-only se vuoi il run incompleto.",
              file=sys.stderr)
        return 2

    # ---------------------------------------------------------------- livello B
    state = {}

    def login():
        status, data = call(base, "POST", "/api/v1/auth/login",
                            {"email": args.email, "password": args.password})
        assert status == 200, f"HTTP {status}"
        token = data.get("access_token")
        assert token, f"nessun access_token: {data}"
        state["token"] = token
        state["user"] = data.get("user") or {}
        return f"{state['user'].get('username')} ruolo={state['user'].get('role')}"

    check("login", login, level="B")
    if "token" not in state:
        print("login fallito: il livello B non può proseguire.", file=sys.stderr)
        return _report(base, args)

    token = state["token"]

    def me():
        status, data = call(base, "GET", "/api/v1/auth/me", token=token)
        assert status == 200, f"HTTP {status}"
        assert data.get("email", "").lower() == args.email.lower(), data
        return f"{data.get('username')} / {data.get('role')}"

    def catalog():
        status, data = call(base, "GET", "/api/v1/ingest/catalog", token=token)
        parsers = [p["name"] for p in data.get("parsers", [])]
        assert parsers, "catalogo parser vuoto"
        for expected in ("syslog", "windows_event", "zeek", "suricata"):
            assert expected in parsers, f"parser atteso assente: {expected}"
        assert data.get("aliases"), "alias di compatibilità assenti"
        return f"{len(parsers)} parser: {', '.join(sorted(parsers))}"

    def coverage():
        status, data = call(base, "GET", "/api/v1/ingest/detection-coverage", token=token)
        sigma, corr = data["sigma"], data["correlation"]
        assert sigma["rules_executable"] > 0, "nessuna regola Sigma eseguibile"
        assert corr["rules_executable"] > 0, "nessuna regola di correlazione eseguibile"
        for name, cov in (("sigma", sigma), ("correlazione", corr)):
            assert cov["rules_executable"] <= cov["rules_total"], f"{name}: eseguibili > totali"
        return (f"sigma {sigma['rules_executable']}/{sigma['rules_total']}, "
                f"correlazione {corr['rules_executable']}/{corr['rules_total']}")

    def parse_preview():
        # Due forme entrambe dichiarate supportate: quella canonica del collector
        # (`{"Id":…, "EventData":{…}}`) e la variante con la chiave `EventID`.
        shapes = [
            {"Id": 4625, "Channel": "Security",
             "Provider": "Microsoft-Windows-Security-Auditing",
             "EventData": {"TargetUserName": "Administrator",
                            "IpAddress": "203.0.113.9", "LogonType": "3"}},
            {"EventID": 4625,
             "EventData": {"TargetUserName": "root", "IpAddress": "203.0.113.9"}},
        ]
        seen = []
        for payload in shapes:
            status, data = call(base, "POST", "/api/v1/ingest/test",
                                {"parser": "windows_event", "payload": payload}, token=token)
            assert status == 200, f"HTTP {status}"
            assert data.get("events"), (
                f"nessun evento da chiave {list(payload)[0]}: {data.get('errors')}")
            ev = data["events"][0]
            assert str(ev.get("event_id")), "event_id assente nell'evento normalizzato"
            seen.append(f"{list(payload)[0]}->{len(data['events'])}")
        return f"{data['parser']}: forme accettate {', '.join(seen)}"

    def ingest_e2e():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        state["source"] = f"smoke-e2e-{stamp}"
        state["event_id"] = f"smoke-{stamp}-1"
        # La riga si conserva identica: l'idempotenza si prova rispedendo **lo
        # stesso byte**, non una riga riscritta con un timestamp nuovo.
        state["line"] = SYSLOG_LINE.format(
            ts=datetime.now(timezone.utc).strftime("%b %d %H:%M:%S"))
        body = {"message": state["line"], "event_id": state["event_id"]}
        status, data = call(base, "POST", f"/api/v1/ingest/{state['source']}",
                            body, token=token)
        assert status == 200, f"HTTP {status}"
        assert data.get("accepted"), f"payload non accettato: {data}"
        assert data.get("stored"), f"evento non salvato: {data}"
        assert not data.get("unparsed"), f"unparsed: {data.get('unparsed')}"
        state["stored"] = data.get("stored")
        return f"sorgente={state['source']} parser={data.get('parser')} stored={data.get('stored')}"

    def ingest_idempotent():
        assert state.get("source"), "ingestione precedente fallita"
        body = {"message": state["line"], "event_id": state["event_id"]}
        status, data = call(base, "POST", f"/api/v1/ingest/{state['source']}",
                            body, token=token)
        assert status == 200, f"HTTP {status}"
        assert not data.get("stored"), f"duplicato salvato due volte: {data}"
        assert data.get("duplicates"), f"duplicato non riconosciuto: {data}"
        return f"reinviato lo stesso event_id: stored={data.get('stored')} duplicates={data.get('duplicates')}"

    def ingest_rejects_garbage():
        # Stringa nuda e senza struttura: un dizionario JSON verrebbe invece
        # preso dal parser JSON generico, che e' il comportamento voluto.
        detail = expect_status(
            lambda: call(base, "POST", "/api/v1/ingest/smoke-unparseable",
                         "smoke probe riga non riconoscibile da nessun parser",
                         token=token),
            422, label="payload non riconosciuto")
        assert "unparsed" in detail or "parsed" in detail, detail
        return "422 con diagnosi (non un 200 silenzioso)"

    def event_searchable():
        status, data = call(base, "GET", "/api/v1/search/events?q=Failed%20password&hours=1&limit=50",
                            token=token)
        assert status == 200, f"HTTP {status}"
        items = data.get("items", data if isinstance(data, list) else [])
        assert items, f"evento ingerito non ricercabile: {json.dumps(data)[:200]}"
        hit = next((e for e in items if e.get("source") == state.get("source")), None)
        assert hit, f"sorgente {state.get('source')} assente nei risultati"
        assert hit.get("src_ip") == "203.0.113.77", f"src_ip non estratto: {hit.get('src_ip')}"
        return f"{len(items)} risultati, trovato {state['source']} src_ip={hit.get('src_ip')}"

    def alert_with_mitre():
        status, data = call(base, "GET", "/api/v1/telemetry/alerts?is_resolved=false&limit=200",
                            token=token)
        assert status == 200, f"HTTP {status}"
        mitre = [a for a in data if (a.get("mitre_technique_id") or "").startswith("T1110")]
        assert mitre, "nessun alert con T1110: la detection non ha prodotto alert"
        state["alert_id"] = mitre[0]["id"]
        return (f"alert #{mitre[0]['id']} {mitre[0].get('mitre_technique_id')} "
                f"{mitre[0].get('mitre_tactic_name')}")

    def stats_moves():
        status, data = call(base, "GET", "/api/v1/ingest/stats?hours=1", token=token)
        assert status == 200, f"HTTP {status}"
        det = data.get("detection", {})
        assert det.get("sigma_rules"), "stats senza regole Sigma attive"
        total = data.get("total") or data.get("events") or data.get("count")
        return f"eventi={total} sigma={det.get('sigma_rules')} correlazione={det.get('correlation_rules')}"

    def sources_listed():
        status, data = call(base, "GET", "/api/v1/ingest/sources", token=token)
        assert status == 200, f"HTTP {status}"
        names = [s.get("name") for s in data.get("items", [])]
        assert state.get("source") in names, f"{state.get('source')} non registrata: {names[:5]}"
        return f"{len(names)} sorgenti registrate, inclusa {state['source']}"

    def search_fields():
        status, data = call(base, "GET", "/api/v1/search/fields", token=token)
        assert status == 200, f"HTTP {status}"
        fields = data.get("fields", data)
        assert fields, "nessun campo filtrabile"
        return f"{len(fields)} campi filtrabili"

    def agents_reporting():
        status, data = call(base, "GET", "/api/v1/telemetry/agents", token=token)
        assert status == 200, f"HTTP {status}"
        agents = data if isinstance(data, list) else data.get("items", [])
        assert agents, "nessun agente registrato: la telemetria endpoint non arriva"
        return f"{len(agents)} agenti registrati"

    def rbac_matches_role():
        """L'enforcement deve essere coerente col ruolo di chi ha fatto login.

        Un endpoint privilegiato senza permesso deve dare 403, non 200: è la
        differenza tra RBAC applicato e RBAC dichiarato.
        """
        role = (state["user"].get("role") or "user").lower()
        privileged = {"admin", "analyst"}
        body = {"name": f"smoke-rbac-{datetime.now(timezone.utc).strftime('%H%M%S')}",
                "parser": "syslog"}
        try:
            status, _ = call(base, "POST", "/api/v1/ingest/sources", body, token=token)
            if role not in privileged:
                raise AssertionError(f"ruolo {role} ha potuto creare una sorgente (atteso 403)")
            return f"ruolo {role}: accesso consentito come da matrice"
        except ApiError as e:
            if e.status == 403 and role not in privileged:
                return f"ruolo {role}: 403 come da matrice"
            raise AssertionError(f"ruolo {role}: HTTP {e.status} inatteso") from None

    def rbac_anonymous_denied():
        expect_status(lambda: call(base, "GET", "/api/v1/search/events?limit=1"),
                      401, label="ricerca anonima")
        expect_status(lambda: call(base, "GET", "/api/v1/ingest/stats"),
                      401, label="stats anonime")
        return "401 su ricerca e stats senza token"

    check("profilo utente", me)
    check("catalogo parser", catalog)
    check("copertura detection", coverage)
    check("parser windows_event su payload reale", parse_preview)
    check("ingestione end-to-end", ingest_e2e)
    check("idempotenza event_id", ingest_idempotent)
    check("payload non riconosciuto -> 422", ingest_rejects_garbage)
    check("evento ricercabile con src_ip", event_searchable)
    check("alert Sigma con MITRE", alert_with_mitre)
    check("stats ingestione", stats_moves)
    check("sorgenti registrate", sources_listed)
    check("campi filtrabili", search_fields)
    check("agenti endpoint", agents_reporting)
    def bootstrap_path_exists():
        # Zero-config: il primo admin si ottiene da una CLI fuori dal processo
        # HTTP (privilegio da shell, non da API esposta). Qui si verifica solo
        # che il percorso esista nel repo: il check non importa l'app e non
        # tocca il DB, quindi non dipende da env o stato.
        from pathlib import Path
        admin_py = Path(__file__).resolve().parents[1] / "aegis-brain" / "app" / "admin.py"
        assert admin_py.exists(), "app/admin.py assente: percorso di bootstrap rotto"
        text = admin_py.read_text(encoding="utf-8")
        assert '"bootstrap"' in text and "user_bootstrap" in text, \
            "il comando bootstrap non esiste più: nessun modo di ottenere il primo admin"
        return "app.admin: bootstrap + set-role (privilegio da shell, audit registrato)"

    check("RBAC coerente col ruolo", rbac_matches_role)
    check("RBAC nega l'anonimo", rbac_anonymous_denied)
    check("Percorso bootstrap del primo admin", bootstrap_path_exists)

    return _report(base, args)


def _report(base, args, note=None) -> int:
    failed = sum(1 for c in CHECKS if c["status"] == "fail")
    if args.json:
        print(json.dumps({"base": base, "failed": failed, "note": note, "checks": CHECKS},
                         indent=2))
    else:
        for c in CHECKS:
            print(f"[{c['status'].upper()}] ({c.get('level', '-')}) {c['name']}: {c['detail']}")
        if note:
            print(f"\nnota: {note}")
        print("ALL PASS" if failed == 0 else f"{failed} FAILURES")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
