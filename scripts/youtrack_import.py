#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Create YouTrack issues from docs/youtrack_tickets.csv.

The script is dry-run by default. It needs a YouTrack URL, a permanent token
and the project short name only when --apply is used:

    YOUTRACK_URL=https://example.youtrack.cloud
    YOUTRACK_TOKEN=perm:...
    YOUTRACK_PROJECT=AEGIS

Usage:
    python scripts/youtrack_import.py
    python scripts/youtrack_import.py --apply

The CSV has two columns: Summary and Description. The importer checks existing
summaries in the project before creating a ticket, so a retry after a partial
run does not duplicate what was already created. It does not update existing
issues: change those in YouTrack or extend the script deliberately.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_CSV = Path(__file__).resolve().parent.parent / "docs" / "youtrack_tickets.csv"


def request_json(url: str, token: str, method: str = "GET", payload: dict | None = None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required = {"Summary", "Description"}
    if not rows:
        raise SystemExit(f"No rows in {path}")
    missing = required.difference(rows[0].keys())
    if missing:
        raise SystemExit(f"Missing CSV columns: {', '.join(sorted(missing))}")
    return rows


def existing_summaries(base: str, token: str, project: str) -> set[str]:
    query = urllib.parse.quote(f"project: {project}")
    url = (
        f"{base}/api/issues?query={query}"
        "&fields=idReadable,summary&$top=1000"
    )
    issues = request_json(url, token) or []
    return {issue["summary"] for issue in issues if "summary" in issue}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually create issues. Without it the script only prints a preview.",
    )
    args = parser.parse_args()

    rows = load_rows(args.csv)
    print(f"{len(rows)} tickets in {args.csv}")

    if not args.apply:
        print("DRY RUN: no issue created. Showing the first 12 summaries:")
        for row in rows[:12]:
            print(f"- {row['Summary'].strip()}")
        print("Use --apply with YOUTRACK_URL, YOUTRACK_TOKEN and YOUTRACK_PROJECT.")
        return 0

    base = os.environ.get("YOUTRACK_URL", "").rstrip("/")
    token = os.environ.get("YOUTRACK_TOKEN", "")
    project = os.environ.get("YOUTRACK_PROJECT", "")
    missing = [
        name
        for name, value in (
            ("YOUTRACK_URL", base),
            ("YOUTRACK_TOKEN", token),
            ("YOUTRACK_PROJECT", project),
        )
        if not value
    ]
    if missing:
        raise SystemExit(f"Missing environment variables: {', '.join(missing)}")

    existing = existing_summaries(base, token, project)
    created = skipped = 0
    for row in rows:
        summary = row["Summary"].strip()
        description = row["Description"].strip()
        if not summary:
            continue
        if summary in existing:
            skipped += 1
            continue
        payload = {
            "project": {"shortName": project},
            "summary": summary,
            "description": description,
        }
        issue = request_json(
            f"{base}/api/issues?fields=idReadable,summary",
            token,
            method="POST",
            payload=payload,
        )
        print(f"created {issue['idReadable']}: {summary}")
        existing.add(summary)
        created += 1
        time.sleep(0.15)

    print(f"created={created} skipped={skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
