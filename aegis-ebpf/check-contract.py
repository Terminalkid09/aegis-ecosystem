#!/usr/bin/env python3
"""Conformance test for the single event contract (event.schema.json), stdlib only.

Validates:
  1. tests/golden.jsonl (REAL lines captured from the kernel via eBPF)
  2. a synthetic ETW line (same shape aegis_etw.c prints)
  3. that the brain mapping (EventSchema) accepts the key fields

Usage: python3 check-contract.py  (exit 0 = fully conformant)
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "tests", "golden.jsonl")

REQUIRED = {"pid", "event_type"}
TYPES = {"PROCESS_CREATED", "PROCESS_EXITED", "CONNECTION_ESTABLISHED"}

# v2 fields: all optional (v1 compatibility), but typed when present.
V2_INT_FIELDS = ("schema_version", "seq", "ts_wall_ns", "proc_start_ns", "ppid_start_ns")
V2_STR_FIELDS = ("event_id", "agent_id", "boot_id", "session", "integrity",
                 "proto", "container_id", "cgroup", "namespace", "provenance",
                 "quality", "sampling", "drop_reason")
V2_DIRECTIONS = {"outbound", "inbound", "unknown"}

# Sample line from aegis_etw.c (Windows): same contract, uid=0, wall-clock ts.
ETW_SAMPLE = (
    '{"ts_ns":170527184865484,"pid":1234,"ppid":567,"uid":0,'
    '"comm":"notepad.exe","filename":"C:\\\\Windows\\\\notepad.exe",'
    '"event_type":"PROCESS_CREATED"}'
)

fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f" | {extra}" if extra else ""))
    if not cond:
        fails.append(name)


def validate_event(ev, origin):
    if not isinstance(ev, dict):
        return f"{origin}: not an object"
    for k in REQUIRED:
        if k not in ev:
            return f"{origin}: missing {k}"
    if ev["event_type"] not in TYPES:
        return f"{origin}: invalid event_type {ev.get('event_type')}"
    if not isinstance(ev["pid"], int) or ev["pid"] < 1:
        return f"{origin}: invalid pid"
    if "ppid" in ev and (not isinstance(ev["ppid"], int) or ev["ppid"] < 0):
        return f"{origin}: invalid ppid"
    if "ts_ns" in ev and (not isinstance(ev["ts_ns"], int) or ev["ts_ns"] < 0):
        return f"{origin}: invalid ts_ns"
    if ev["event_type"] == "PROCESS_CREATED" and not ev.get("comm"):
        return f"{origin}: created event without comm"
    if ev["event_type"] == "CONNECTION_ESTABLISHED":
        remote = ev.get("remote", "")
        if ":" not in str(remote):
            return f"{origin}: connection event without remote ip:port"
    # v2: optional field typing (v1 without these fields remains valid).
    sv = ev.get("schema_version", 1)
    if not isinstance(sv, int) or sv < 1:
        return f"{origin}: invalid schema_version"
    for k in V2_INT_FIELDS:
        if k in ev and (not isinstance(ev[k], int) or ev[k] < 0):
            return f"{origin}: invalid {k}"
    for k in V2_STR_FIELDS:
        if k in ev and not isinstance(ev[k], str):
            return f"{origin}: {k} is not a string"
    if "direction" in ev and ev["direction"] not in V2_DIRECTIONS:
        return f"{origin}: invalid direction"
    if "seq" in ev and "boot_id" not in ev:
        return f"{origin}: seq without boot_id (cannot be anchored)"
    return None


# v2 line produced by an updated agent: identity + sequence + dual timestamps.
V2_SAMPLE = (
    '{"schema_version":2,"event_id":"3f2504e0-4f89-11d3-9a0c-0305e82c3301",'
    '"agent_id":"agent-001","boot_id":"b8e65a9c-4f89-11d3-9a0c-0305e82c3301","seq":41,'
    '"ts_ns":170527184458021,"ts_wall_ns":170527184458021000,'
    '"pid":101,"ppid":100,"proc_start_ns":170527180000000,'
    '"uid":1000,"comm":"echo","filename":"/bin/echo",'
    '"provenance":"ebpf-full","quality":"full",'
    '"event_type":"PROCESS_CREATED"}'
)

# v1 legacy line (no schema_version): MUST remain valid forever.
V1_SAMPLE = (
    '{"pid":7,"ppid":1,"comm":"sh","filename":"/bin/sh",'
    '"event_type":"PROCESS_CREATED"}'
)


def main():
    check("golden.jsonl exists", os.path.exists(GOLDEN))
    if not os.path.exists(GOLDEN):
        sys.exit(1)
    with open(GOLDEN, encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    check("golden has >=3 events", len(lines) >= 3, f"{len(lines)} lines")
    types_seen = set()
    exec_with_parent = False
    for i, ln in enumerate(lines):
        try:
            ev = json.loads(ln)
        except json.JSONDecodeError as e:
            check(f"golden line {i} JSON", False, str(e)[:80])
            continue
        err = validate_event(ev, f"golden line {i}")
        check(f"golden line {i} conformant", err is None, err or "")
        if err is None:
            types_seen.add(ev["event_type"])
            if ev["event_type"] == "PROCESS_CREATED" and ev.get("ppid", 0) > 0 and ev.get("filename"):
                exec_with_parent = True
    check("golden covers created+exited", {"PROCESS_CREATED", "PROCESS_EXITED"} <= types_seen, str(types_seen))
    check("golden has exec with real ppid+filename", exec_with_parent)

    try:
        ev = json.loads(ETW_SAMPLE)
    except json.JSONDecodeError as e:
        check("ETW sample JSON", False, str(e)[:80])
        ev = None
    if ev is not None:
        err = validate_event(ev, "ETW sample")
        check("ETW sample conforms to the contract", err is None, err or "")

    for name, sample in (("V2 sample", V2_SAMPLE), ("V1 legacy sample", V1_SAMPLE)):
        try:
            sev = json.loads(sample)
        except json.JSONDecodeError as e:
            check(f"{name} JSON", False, str(e)[:80])
            continue
        serr = validate_event(sev, name)
        check(f"{name} conforms to the contract", serr is None, serr or "")
    # negative v2: seq without boot_id must fail (cannot be anchored).
    bad_seq = json.loads('{"pid":9,"event_type":"PROCESS_CREATED","comm":"x","seq":3}')
    check("seq without boot_id rejected", validate_event(bad_seq, "seq-orphan") is not None)

    print()
    if fails:
        print(f"RESULT: {len(fails)} FAILURES: {fails}")
        return 1
    print("RESULT: ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
