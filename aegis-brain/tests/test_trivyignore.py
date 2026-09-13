"""M4 audit F5: .trivyignore strutturato e fail-closed (senza DB/rete)."""
import datetime
import os
import re

REPO = os.path.join(os.path.dirname(__file__), "..", "..")
IGNORE = os.path.join(REPO, ".trivyignore")

REQUIRED_KEYS = {"group", "package", "image", "reason", "fix", "owner", "review", "expiry"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _parse():
    groups = []
    current = None
    with open(IGNORE, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("# ==="):
                m = re.match(r"# === group: (.+?) ===$", line)
                assert m, f"header gruppo malformato: {line}"
                current = {"group": m.group(1), "_cves": []}
                groups.append(current)
                continue
            if line.startswith("#"):
                m = re.match(r"# ([a-z]+): (.*)$", line)
                if m and current is not None:
                    current[m.group(1)] = m.group(2)
                continue
            assert current is not None, f"CVE fuori da un gruppo: {line}"
            assert CVE_RE.match(line), f"riga non-CVE: {line}"
            current["_cves"].append(line)
    return groups


def test_trivyignore_groups_have_metadata():
    groups = _parse()
    assert len(groups) >= 1
    for g in groups:
        missing = REQUIRED_KEYS - set(g)
        assert not missing, f"gruppo {g.get('group')}: chiavi mancanti {missing}"
        assert len(g["_cves"]) >= 1, f"gruppo {g['group']}: nessuna CVE"


def test_trivyignore_no_duplicate_cves():
    seen = {}
    for g in _parse():
        for cve in g["_cves"]:
            assert cve not in seen, f"{cve} duplicata in {seen[cve]} e {g['group']}"
            seen[cve] = g["group"]
    assert len(seen) == 22, f"attese 22 CVE documentate, trovate {len(seen)}"


def test_trivyignore_expiry_forces_review():
    today = datetime.date.today().isoformat()
    for g in _parse():
        for key in ("review", "expiry"):
            datetime.date.fromisoformat(g[key])  # formato YYYY-MM-DD valido
        assert g["expiry"] >= g["review"], f"gruppo {g['group']}: expiry < review"
        assert g["expiry"] >= today, (
            f"gruppo {g['group']}: review SCADUTA il {g['expiry']} — "
            "rieseguire Trivy e rinnovare o rimuovere le CVE"
        )
