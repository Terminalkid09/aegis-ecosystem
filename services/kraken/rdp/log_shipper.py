#!/usr/bin/env python3
"""Forward xrdp authentication telemetry to the Kraken internal API.

The container runs xrdp as a real service, so its authentication events are
written to the host/container logs by PAM and xrdp-sesman.  The Python RDP
listener is only a banner fallback; this shipper is the path that makes real
xrdp logins visible in Aegis.

Only bounded metadata is sent: source IP/port, username, result and a synthetic
session id.  Passwords and session contents never leave the RDP container.
The tailer starts at the current end of each file, handles rotation/truncation,
and retries a failed POST a small number of times without blocking forever.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_LOG_PATHS = "/var/log/auth.log,/var/log/xrdp.log,/var/log/xrdp-sesman.log"
INGEST_URL = os.getenv("KRAKEN_RDP_INGEST_URL", "http://aegis-kraken:8000").rstrip("/")
INTERNAL_KEY = os.getenv("INTERNAL_API_KEY", "")
SENSOR_PORT = int(os.getenv("KRAKEN_RDP_SENSOR_PORT", "3389"))
ENABLED = os.getenv("KRAKEN_RDP_INGEST_ENABLED", "true").strip().lower() not in {
    "0", "false", "no", "off",
}
LOG_PATHS = [
    Path(item.strip())
    for item in os.getenv("KRAKEN_RDP_LOG_PATHS", DEFAULT_LOG_PATHS).split(",")
    if item.strip()
]

_FAILED = re.compile(
    r"(?i)Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"(?i)Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
_CONNECTION = re.compile(
    r"(?i)connection received from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
_SESSION = re.compile(
    r"(?i)session (?P<result>started successfully|failed) for user "
    r"(?P<user>[\w.@-]+)"
)

_stop = threading.Event()
_seen_lock = threading.Lock()
_seen: dict[str, float] = {}


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_log_line(line: str, source: str = "") -> dict | None:
    """Parse one auth/xrdp log line into a bounded, non-secret record."""
    text = line.strip()
    if not text:
        return None

    match = _FAILED.search(text) or _ACCEPTED.search(text)
    if match:
        groups = match.groupdict()
        if not _valid_ip(groups["ip"]):
            return None
        result = "failed" if _FAILED.search(text) else "success"
        return {
            "sensor_type": "rdp",
            "attacker_ip": groups["ip"],
            "attacker_port": int(groups["port"]),
            "username": groups["user"][:128],
            "result": result,
            "source": source or "auth",
            "raw_kind": "authentication",
        }

    match = _CONNECTION.search(text)
    if match:
        groups = match.groupdict()
        if not _valid_ip(groups["ip"]):
            return None
        return {
            "sensor_type": "rdp",
            "attacker_ip": groups["ip"],
            "attacker_port": int(groups["port"]),
            "username": None,
            "result": "connection",
            "source": source or "xrdp",
            "raw_kind": "connection",
        }

    match = _SESSION.search(text)
    if match:
        groups = match.groupdict()
        # xrdp-sesman often omits the source address; an event without an IP
        # cannot be attributed and must not be invented.
        return {
            "sensor_type": "rdp",
            "attacker_ip": "",
            "attacker_port": 1,
            "username": groups["user"][:128],
            "result": "success" if "started" in groups["result"].lower() else "failed",
            "source": source or "xrdp-sesman",
            "raw_kind": "session",
        }

    return None


def build_event(record: dict, sensor_port: int = SENSOR_PORT) -> dict | None:
    """Build the Kraken SensorEventIn payload, excluding all credentials."""
    ip = str(record.get("attacker_ip") or "")
    if not _valid_ip(ip):
        return None
    result = str(record.get("result") or "unknown")[:32]
    username = record.get("username")
    port = int(record.get("attacker_port") or 1)
    if port < 1 or port > 65535:
        port = 1
    session_basis = "|".join(
        [ip, str(port), str(username or ""), result, str(record.get("source") or "")]
    )
    digest = hashlib.sha1(session_basis.encode("utf-8")).hexdigest()[:32]
    return {
        "sensor_type": "rdp",
        "attacker_ip": ip,
        "attacker_port": port,
        "sensor_port": sensor_port,
        "session_id": f"rdp-{digest}",
        "username": str(username)[:128] if username else None,
        "commands": [f"RDP authentication {result}"],
        "context": "sensor",
    }


def _post_event(payload: dict) -> bool:
    if not ENABLED:
        return True
    if not INTERNAL_KEY:
        print("RDP log shipper: INTERNAL_API_KEY is not set", file=sys.stderr)
        return False
    url = f"{INGEST_URL}/api/v1/events/ingest"
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Internal-API-Key": INTERNAL_KEY,
        },
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                if 200 <= response.status < 300 or response.status == 409:
                    return True
                print(f"RDP log shipper: ingest HTTP {response.status}", file=sys.stderr)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt == 2:
                print(f"RDP log shipper: ingest failed: {type(exc).__name__}", file=sys.stderr)
                return False
        time.sleep(0.5 * (attempt + 1))
    return False


def _handle_line(line: str, source: str) -> None:
    record = parse_log_line(line, source=source)
    if not record:
        return
    payload = build_event(record)
    if not payload:
        return
    # Auth logs can contain the same failure more than once (PAM and xrdp).
    # Keep the dedupe window bounded so a long-running container cannot grow
    # an unbounded in-memory set.
    key = payload["session_id"]
    now = time.monotonic()
    with _seen_lock:
        previous = _seen.get(key)
        if previous is not None and now - previous < 30:
            return
        _seen[key] = now
        if len(_seen) > 4096:
            cutoff = now - 300
            for stale in [item for item, stamp in _seen.items() if stamp < cutoff]:
                _seen.pop(stale, None)
    _post_event(payload)


def _tail(path: Path) -> None:
    handle = None
    inode = None
    position = 0
    while not _stop.is_set():
        try:
            stat = path.stat()
            if handle is None or inode != stat.st_ino or stat.st_size < position:
                if handle is not None:
                    handle.close()
                handle = path.open("r", encoding="utf-8", errors="replace")
                # Only tail new lines. Starting at the beginning would replay
                # every previous RDP login after a container restart.
                handle.seek(0, os.SEEK_END)
                position = handle.tell()
                inode = stat.st_ino
            line = handle.readline()
            if line:
                position = handle.tell()
                _handle_line(line, path.name)
                continue
        except FileNotFoundError:
            pass
        except OSError as exc:
            print(f"RDP log shipper: cannot read {path}: {exc}", file=sys.stderr)
        _stop.wait(0.5)


def main() -> int:
    if not ENABLED:
        print("RDP log shipper disabled")
        return 0
    if not INTERNAL_KEY:
        print("RDP log shipper: INTERNAL_API_KEY is required", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, lambda *_: _stop.set())
    signal.signal(signal.SIGINT, lambda *_: _stop.set())
    for path in LOG_PATHS:
        threading.Thread(target=_tail, args=(path,), daemon=True).start()
    print(f"RDP log shipper watching: {', '.join(str(path) for path in LOG_PATHS)}")
    while not _stop.wait(1):
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
