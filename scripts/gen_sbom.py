#!/usr/bin/env python3
"""SBOM manifest-derived (audit F5).

Genera sbom.cyclonedx.json (CycloneDX 1.6 minimale, stdlib-only) dai manifest
dichiarati: requirements.txt (pip), package.json (npm), pom.xml (maven, solo
dipendenze dirette con versione letterale).

Limite onesto: questa SBOM descrive i manifest, NON gli image layer.
La SBOM image-layer richiede `trivy image --format cyclonedx` (Trivy non
installato in questo ambiente: vedi report, sezione supply-chain).

Uso: python scripts/gen_sbom.py [--out sbom.cyclonedx.json]
"""
import argparse
import datetime
import json
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def pip_components():
    comps = []
    path = os.path.join(REPO, "aegis-brain", "requirements.txt")
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([^;\s]+)", line)
            if m:
                comps.append({
                    "type": "library", "name": m.group(1), "version": m.group(2),
                    "purl": f"pkg:pypi/{m.group(1)}@{m.group(2)}",
                    "scope": "required", "evidence": "requirements.txt",
                })
    return comps


def npm_components():
    comps = []
    path = os.path.join(REPO, "frontend", "package.json")
    with open(path, encoding="utf-8") as f:
        pkg = json.load(f)
    for section in ("dependencies", "devDependencies"):
        for name, ver in (pkg.get(section) or {}).items():
            clean = re.sub(r"^[\^~>=< ]+", "", str(ver)).split()[0]
            comps.append({
                "type": "library", "name": f"npm:{name}", "version": clean,
                "purl": f"pkg:npm/{name}@{clean}",
                "scope": "required" if section == "dependencies" else "optional",
                "evidence": "frontend/package.json",
            })
    return comps


def maven_components():
    comps = []
    for mod in ("aegis-guard", "aegis-link"):
        path = os.path.join(REPO, mod, "pom.xml")
        try:
            with open(path, encoding="utf-8") as f:
                pom = f.read()
        except FileNotFoundError:
            continue
        props = dict(re.findall(r"<([\w.\-]+)>([^<>]+)</\1>", pom))
        for group, artifact, version in re.findall(
                r"<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>"
                r".*?<version>(.*?)</version>.*?</dependency>", pom, re.S):
            v = version.strip()
            if v.startswith("${") and v.endswith("}"):
                v = props.get(v[2:-1], v)
            if "$" in v:  # versione non risolvibile offline: skip onesto
                continue
            comps.append({
                "type": "library", "name": f"{group.strip()}:{artifact.strip()}",
                "version": v.strip(),
                "purl": f"pkg:maven/{group.strip()}/{artifact.strip()}@{v.strip()}",
                "scope": "required", "evidence": f"{mod}/pom.xml",
            })
    return comps


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(REPO, "sbom.cyclonedx.json"))
    args = ap.parse_args()
    components = pip_components() + npm_components() + maven_components()
    # Dedup per (name, version)
    seen, uniq = set(), []
    for c in components:
        key = (c["name"], c["version"])
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tools": [{"name": "aegis-gen_sbom", "version": "1.0"}],
            "comment": "manifest-derived only (pip+npm+maven manifests). "
                       "Image-layer SBOM requires trivy image scan (not run here).",
        },
        "components": sorted(uniq, key=lambda c: c["name"]),
    }
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
        f.write("\n")
    by_evidence: dict[str, int] = {}
    for c in uniq:
        by_evidence[c["evidence"]] = by_evidence.get(c["evidence"], 0) + 1
    print(f"SBOM: {len(uniq)} componenti -> {args.out}")
    for ev, n in sorted(by_evidence.items()):
        print(f"  {ev}: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
