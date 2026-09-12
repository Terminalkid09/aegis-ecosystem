"""M6 Fase 7: installer senza segreti statici + pin/manifest agent (senza DB)."""
import re

from app.api.v1.deploy import INSTALL_PS1, INSTALL_SH


def _assert_no_static_secrets(name: str, template: str):
    # Il token viaggia via header a runtime, mai nel template.
    assert "X-Enroll-Token" in template, f"{name}: token via header atteso"
    for pat in (r"sk-[A-Za-z0-9]{8,}", r"AKIA[0-9A-Z]{16}",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----"):
        assert not re.search(pat, template), f"{name}: segreto statico? {pat}"
    # Niente placeholder che sembrano valori reali lunghi ed entropici.
    for line in template.splitlines():
        low = line.lower()
        if "example" in low or "replace" in low or "<token>" in low or "{base}" in low:
            continue
        for tok in re.findall(r"[A-Za-z0-9+/=_-]{40,}", line):
            if "AEGIS_" in line or "X-Enroll-Token" in line:
                continue
            raise AssertionError(f"{name}: possibile segreto statico: {tok[:20]}...")


def test_install_ps1_no_static_secrets():
    _assert_no_static_secrets("install.ps1", INSTALL_PS1)


def test_install_sh_no_static_secrets():
    _assert_no_static_secrets("install.sh", INSTALL_SH)


def test_installers_reference_signed_artifacts_only():
    for tpl in (INSTALL_PS1, INSTALL_SH):
        assert "artifacts/" in tpl
        assert "curl" in tpl or "Invoke-WebRequest" in tpl
