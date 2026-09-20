#!/usr/bin/env python3
"""Demo end-to-end del SIEM: spedisce log di esempio all'API di ingestione.

Cosa dimostra: gli stessi scenari che un SOC vede davvero (brute force, log
cancellato, servizio installato da path utente, DNS tunneling, download di
eseguibili dal proxy) entrano come **log di rete e di endpoint**, non come
eventi di un agente, e diventano alert tramite regole Sigma e di correlazione.

Onesta' sul dato: i payload sono **campioni sintetici** presi da
`tests/corpus/logs` (nello stesso formato di Zeek/Suricata/syslog/Windows Event
Log reali). Sono fatti per essere mostrati e per i test, non sono traffico
catturato. Gli stessi formati si ottengono puntando il collector vero:
`scripts/winevent-collector.ps1` per Windows Event Log e il firewall di Windows,
un filebeat/rsyslog verso `POST /api/v1/ingest/<sorgente>` per il resto.

Uso:
    python scripts/siem_demo.py --scenario all
    python scripts/siem_demo.py --scenario bruteforce --api-key <AEGIS_API_KEY>
    python scripts/siem_demo.py --dry-run            # solo stampa i payload
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
import uuid

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CORPUS = os.path.join(REPO, "aegis-brain", "tests", "corpus", "logs")

SCENARIOS = ("bruteforce", "windows-persistence", "dns-tunneling",
             "web-attack", "all")


def corpus(name: str) -> str:
    with open(os.path.join(CORPUS, name), encoding="utf-8") as fh:
        return fh.read()


def _log(message: str, kind: str = "*") -> None:
    print(f"[{kind}] {message}", flush=True)


def _syslog(ts_second: int, message: str, tag: str = "sshd", host: str = "web-01") -> str:
    return (f"<134>1 2026-09-15T12:00:{ts_second:02d}.000000+00:00 {host} {tag} "
            f"{2200 + ts_second} ID47 - {message}")


def scenario_bruteforce(ip: str) -> list[tuple[str, str, str]]:
    """5 fallimenti + 1 successo dallo stesso IP: soglia + sequenza."""
    steps: list[tuple[str, str, str]] = []
    for index in range(5):
        steps.append(("syslog", "ssh", _syslog(
            index, f"Failed password for invalid user admin from {ip} port {51000 + index} ssh2")))
    # Stessa sorgente dei fallimenti: e' lo stesso host che logga, ed e' cosi'
    # che la sequenza "fallimenti + successo" resta correlabile.
    steps.append(("syslog", "ssh", _syslog(
        10, f"Accepted password for admin from {ip} port 51234 ssh2")))
    return steps


def scenario_windows_persistence(ip: str) -> list[tuple[str, str, str]]:
    """Windows Event Log reale nel formato dell'API: log svuotato, servizio,
    scheduled task, account aggiunto al gruppo admin."""
    events = [json.loads(line) for line in corpus("windows_security.jsonl").splitlines() if line.strip()]
    extra = {
        "Id": 4728,
        "Level": 4,
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Computer": "WIN-DEV01",
        "TimeCreated": "2026-09-15T12:01:00.1234567Z",
        "Message": "A member was added to a security-enabled global group.",
        "EventData": {"MemberName": "WIN-DEV01\\jsmith",
                      "TargetUserName": "Administrators",
                      "SubjectUserName": "Administrator"},
    }
    events.append(extra)
    payload = "\n".join(json.dumps(e, ensure_ascii=False) for e in events)
    return [("windows_event", "windows", payload)]


def scenario_dns_tunneling() -> list[tuple[str, str, str]]:
    """Zeek DNS: query lunghe verso un dominio sospetto."""
    return [("zeek", "zeek-dns", corpus("zeek_dns.log"))]


def scenario_web_attack() -> list[tuple[str, str, str]]:
    """Proxy e web server: download di eseguibili e richieste bloccate."""
    return [("squid", "proxy", corpus("squid_access.log")),
            ("nginx", "webserver", corpus("nginx_access.log"))]


def build(scenario: str) -> list[tuple[str, str, str]]:
    ip = f"198.51.100.{random.randint(11, 250)}"
    chosen = SCENARIOS[:-1] if scenario == "all" else (scenario,)
    steps: list[tuple[str, str, str]] = []
    for name in chosen:
        if name == "bruteforce":
            steps += scenario_bruteforce(ip)
        elif name == "windows-persistence":
            steps += scenario_windows_persistence(ip)
        elif name == "dns-tunneling":
            steps += scenario_dns_tunneling()
        elif name == "web-attack":
            steps += scenario_web_attack()
    return steps


def send(base_url: str, api_key: str, parser: str, source: str, payload: str,
         timeout: int = 30, attempts: int = 3) -> dict:
    """POST con un paio di retry: subito dopo l'avvio del brain la prima
    connessione può cadere mentre gli engine si inizializzano."""
    url = f"{base_url.rstrip('/')}/api/v1/ingest/{source}?parser={parser}"
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", "X-Api-Key": api_key})
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError:
            raise
        except Exception as exc:  # URLError, disconnessione, timeout
            last = exc
            if attempt < attempts:
                _log(f"tentativo {attempt}/{attempts} fallito ({exc}); riprovo…", "-")
                time.sleep(2)
    raise urllib.error.URLError(last)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=os.getenv("AEGIS_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--api-key", default=os.getenv("AEGIS_API_KEY", ""))
    parser.add_argument("--scenario", choices=SCENARIOS, default="all")
    parser.add_argument("--dry-run", action="store_true", help="stampa i payload senza inviarli")
    args = parser.parse_args()

    if not args.api_key and not args.dry_run:
        _log("Nessuna API key: usa --api-key oppure AEGIS_API_KEY nell'ambiente.", "!")
        return 2

    run_id = uuid.uuid4().hex[:6]
    steps = build(args.scenario)
    _log(f"scenario={args.scenario} passi={len(steps)} run={run_id}")

    totals = {"stored": 0, "alerts": 0, "sigma": 0, "correlation": 0, "duplicates": 0}
    for index, (parser_name, source_hint, payload) in enumerate(steps):
        source = f"demo-{source_hint}-{run_id}"
        if args.dry_run:
            _log(f"[{index + 1}/{len(steps)}] {parser_name} -> {source}: "
                 f"{len(payload.splitlines())} righe", "-")
            print(payload if len(payload) < 2000 else payload[:2000] + "…")
            continue
        try:
            result = send(args.base_url, args.api_key, parser_name, source, payload)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            _log(f"[{index + 1}/{len(steps)}] {parser_name}: HTTP {exc.code} {detail}", "!")
            continue
        except urllib.error.URLError as exc:
            _log(f"brain non raggiungibile su {args.base_url}: {exc.reason}", "!")
            return 1
        for key in totals:
            totals[key] += int(result.get(key, 0) or 0)
        _log(f"[{index + 1}/{len(steps)}] {parser_name}: stored={result.get('stored')} "
             f"sigma={result.get('sigma')} correlation={result.get('correlation')} "
             f"alerts={result.get('alerts')}", "+")

    if args.dry_run:
        _log("dry-run: nessun payload inviato")
        return 0

    print()
    _log(f"eventi salvati ....... {totals['stored']}")
    _log(f"match Sigma .......... {totals['sigma']}")
    _log(f"match correlazione ... {totals['correlation']}")
    _log(f"alert creati ......... {totals['alerts']}")
    _log(f"duplicati ignorati ... {totals['duplicates']}")
    _log(f"Apri la dashboard: {args.base_url.replace(':8000', ':8443')} -> Alerts / Search")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        _log("interrotto", "!")
        sys.exit(130)
    except Exception as exc:  # uno script di demo non deve morire in silenzio
        _log(f"errore non gestito: {type(exc).__name__}: {exc}", "!")
        sys.exit(1)
