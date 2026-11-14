"""M6 Fase 7: installer senza segreti statici + pin/manifest agent (senza DB)."""
import base64
import re
from pathlib import Path

import pytest

from app.api.v1 import deploy
from app.api.v1.deploy import INSTALL_PS1, INSTALL_SH
from app.services import pki


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


def test_installers_register_persistent_services_for_both_agents():
    assert 'Install-AegisService "nodetrace"' in INSTALL_PS1
    assert 'Install-AegisService "aegis-guard"' in INSTALL_PS1
    assert 'install_service "nodetrace"' in INSTALL_SH
    assert 'install_service "aegis-guard"' in INSTALL_SH
    assert "SERVICE_AUTO_START" in INSTALL_PS1 or "-StartupType Automatic" in INSTALL_PS1
    assert "systemctl enable --now" in INSTALL_SH


def test_installers_do_not_embed_proxy_configuration():
    for tpl in (INSTALL_PS1, INSTALL_SH):
        assert "PROXY_URL" not in tpl
        assert "HTTP_PROXY" not in tpl
        assert "HTTPS_PROXY" not in tpl


def test_one_liner_uses_token_file_and_manifest_pubkey():
    """AEGIS-SEC-002: il token non finisce nell'env persistente."""
    for tpl in (INSTALL_PS1, INSTALL_SH):
        assert "AEGIS_ENROLL_TOKEN_FILE" in tpl
        assert "AEGIS_MANIFEST_PUBKEY" in tpl
        assert "AEGIS_ENROLL_KEY" not in tpl
        assert "enroll.token" in tpl


def test_manifest_has_no_hmac_and_update_command_is_ed25519_only():
    manifest = deploy.build_manifest([
        {"name": "aegis-guard-1.2.3.zip", "sha256": "a" * 64},
    ])
    assert "hmac" not in manifest
    assert manifest["artifacts"][0] == {
        "name": "aegis-guard-1.2.3.zip", "sha256": "a" * 64,
    }
    cmd = deploy.build_update_command(
        "aegis-guard", "1.2.3", "https://aegis.local", "a" * 64,
        "{\"artifacts\":[]}", "00",
    )
    assert "signature" not in cmd
    assert cmd["manifest_sig"] == "00"


def test_manifest_signing_requires_pki_key(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy.settings, "PKI_DIR", str(tmp_path))
    with pytest.raises(deploy.ManifestUnavailable):
        deploy.sign_manifest_bundle(deploy.build_manifest([]))


def test_manifest_signing_uses_ed25519_key(tmp_path, monkeypatch):
    pki.ensure_manifest_key(str(tmp_path))
    monkeypatch.setattr(deploy.settings, "PKI_DIR", str(tmp_path))
    manifest = deploy.build_manifest([
        {"name": "nodetrace-1.2.3.zip", "sha256": "b" * 64},
    ])
    bundle = deploy.sign_manifest_bundle(manifest)
    assert bundle["signed"] is True
    raw = base64.b64decode(pki.manifest_pubkey_b64(
        str(Path(tmp_path) / pki.MANIFEST_PUB)))
    assert pki.verify_manifest_signature(raw, bundle["manifest"], bundle["ed25519"])


# ---------------------------------------------------------------------------
# Parita' fra installazione remota (one-liner) e installazione locale
# ---------------------------------------------------------------------------
# Perche' questi test: il percorso remoto e il percorso locale erano due
# prodotti diversi. L'installer locale puntava ETW a un path assoluto e
# verificava la major di Java; quello remoto no — quindi un host arruolato da
# remote girava senza telemetria kernel (e con `java` del PATH, che poteva
# essere la 8) senza che nessuno lo dicesse.

def test_windows_installer_wires_kernel_telemetry():
    """ETW: path assoluto + opt-in esplicito per il collector non firmato."""
    assert "AEGIS_ETW_ENABLED" in INSTALL_PS1
    assert "AEGIS_ETW_PATH" in INSTALL_PS1
    assert "AEGIS_ETW_ALLOW_UNSIGNED" in INSTALL_PS1
    # Path ASSOLUTO: un path relativo non viene risolto e l'ETW non parte mai.
    assert 'Join-Path $Dir "aegis-etw.exe"' in INSTALL_PS1


def test_windows_installer_declares_missing_etw_instead_of_silence():
    """Capacita' mancante dichiarata, mai finta: e' il contratto del progetto."""
    assert "no ETW collector in the artifact" in INSTALL_PS1
    assert "quality=degraded" in INSTALL_PS1


def test_windows_installer_resolves_java_version_not_just_presence():
    """Java 8 nel PATH installa un servizio che poi muore: va verificata la major."""
    assert "function Get-JavaMajor" in INSTALL_PS1
    assert "function Resolve-Java" in INSTALL_PS1
    assert "jre\\bin\\java.exe" in INSTALL_PS1
    assert "-ge 25" in INSTALL_PS1


def test_windows_installer_says_when_no_service_was_registered():
    """Senza dashboard remota non si registra nulla: va detto, non sottinteso."""
    assert "no service registered" in INSTALL_PS1
    assert "remote dashboard NOT selected" in INSTALL_PS1
