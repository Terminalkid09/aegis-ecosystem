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
        if ("example" in low or "replace" in low or "<token>" in low
                or "{base}" in low or "$base" in low or "http" in low):
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


def test_installers_register_only_the_unified_service():
    assert 'Install-AegisService "nodetrace"' not in INSTALL_PS1
    assert 'Install-AegisService "aegis-guard"' not in INSTALL_PS1
    assert 'install_service "nodetrace"' not in INSTALL_SH
    assert 'install_service "aegis-guard"' not in INSTALL_SH
    assert "AegisAgent" in INSTALL_PS1
    assert "aegis-unified.service" in INSTALL_SH
    assert "-StartupType Automatic" in INSTALL_PS1
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
        {"name": "unified-1.2.3.zip", "sha256": "a" * 64},
    ])
    assert "hmac" not in manifest
    assert manifest["artifacts"][0] == {
        "name": "unified-1.2.3.zip", "sha256": "a" * 64,
    }
    cmd = deploy.build_update_command(
        "unified", "1.2.3", "https://aegis.local", "a" * 64,
        "{\"artifacts\":[]}", "00",
    )
    assert "signature" not in cmd
    assert cmd["manifest_sig"] == "00"
    assert cmd["url"].endswith("/unified-1.2.3.zip")


def test_manifest_signing_requires_pki_key(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy.settings, "PKI_DIR", str(tmp_path))
    with pytest.raises(deploy.ManifestUnavailable):
        deploy.sign_manifest_bundle(deploy.build_manifest([]))


def test_manifest_signing_uses_ed25519_key(tmp_path, monkeypatch):
    pki.ensure_manifest_key(str(tmp_path))
    monkeypatch.setattr(deploy.settings, "PKI_DIR", str(tmp_path))
    manifest = deploy.build_manifest([
        {"name": "unified-1.2.3.zip", "sha256": "b" * 64},
    ])
    bundle = deploy.sign_manifest_bundle(manifest)
    assert bundle["signed"] is True
    raw = base64.b64decode(pki.manifest_pubkey_b64(
        str(Path(tmp_path) / pki.MANIFEST_PUB)))
    assert pki.verify_manifest_signature(raw, bundle["manifest"], bundle["ed25519"])


# ---------------------------------------------------------------------------
# Parita' fra installazione remota (one-liner) e installazione locale
# ---------------------------------------------------------------------------

def test_windows_installer_wires_kernel_telemetry():
    """ETW: path assoluto + opt-in esplicito per il collector non firmato."""
    assert "AEGIS_ETW_ENABLED" in INSTALL_PS1
    assert "AEGIS_ETW_PATH" in INSTALL_PS1
    assert "AEGIS_ETW_ALLOW_UNSIGNED" in INSTALL_PS1
    assert 'Join-Path $Dir "aegis-etw.exe"' in INSTALL_PS1


def test_windows_installer_declares_missing_etw_instead_of_silence():
    assert "no ETW collector in the artifact" in INSTALL_PS1
    assert "quality=degraded" in INSTALL_PS1


def test_windows_installer_says_when_no_service_was_registered():
    assert "no service registered" in INSTALL_PS1
    assert "remote dashboard NOT selected" in INSTALL_PS1


def test_unified_is_a_single_agent_installer_not_both_legacy():
    assert deploy.VALID_AGENT_TYPES == {"unified"}
    assert deploy.artifact_name_for("unified", "4.3.0") == "unified-4.3.0.zip"
    with pytest.raises(ValueError):
        deploy.artifact_name_for("aegis-guard", "4.3.0")
    assert "unified-latest.zip" in INSTALL_PS1
    assert "unified-latest.tar.gz" in INSTALL_SH
    assert "aegis-agent" in INSTALL_PS1
    assert "aegis-agent" in INSTALL_SH
    assert "nodetrace-agent" not in INSTALL_PS1.lower()
    assert "nodetrace-agent" not in INSTALL_SH.lower()
    assert "aegis-guard.jar" not in INSTALL_PS1.lower()
    assert "aegis-guard.jar" not in INSTALL_SH.lower()
    # NODETRACE_EBPF_* is the compatibility env read by the Go kernel consumer.
    assert "NODETRACE_EBPF=1" in INSTALL_SH


def test_artifact_response_does_not_use_streaming_file_response(tmp_path):
    """Starlette 1.10 + BaseHTTPMiddleware drops FileResponse bodies."""
    payload = b"unified-agent-archive"
    path = tmp_path / "unified-latest.zip"
    path.write_bytes(payload)

    response = deploy._artifact_response(path, "unified-latest.zip")

    assert response.body == payload
    assert response.media_type == "application/octet-stream"
    assert response.headers["content-disposition"] == (
        'attachment; filename="unified-latest.zip"'
    )
