"""M6 Fase 7: ciclo PKI completo + manifest (tmp dir, niente DB/rete)."""
import base64
import os

from app.services import pki


def test_ca_bootstrap_idempotent(tmp_path):
    k1, c1 = pki.ensure_ca(str(tmp_path))
    k2, c2 = pki.ensure_ca(str(tmp_path))
    assert (k1, c1) == (k2, c2)
    assert os.path.exists(k1) and os.path.exists(c1)
    key, cert = pki.load_ca(str(tmp_path))
    assert cert.issuer == cert.subject  # self-signed
    pem = pki.ca_cert_pem(str(tmp_path))
    assert pem.startswith(b"-----BEGIN CERTIFICATE-----")


def test_csr_sign_verify_cycle(tmp_path):
    pki.ensure_ca(str(tmp_path))
    key, cert = pki.load_ca(str(tmp_path))
    _dk, csr = pki.build_agent_csr("agent-123")
    pem, serial, exp = pki.sign_csr(key, cert, csr, "agent-123", ttl_days=30)
    assert serial and exp is not None
    ok, reason = pki.verify_device_cert(cert, pem, "agent-123")
    assert ok, reason


def test_csr_cn_mismatch_rejected(tmp_path):
    pki.ensure_ca(str(tmp_path))
    key, cert = pki.load_ca(str(tmp_path))
    _dk, csr = pki.build_agent_csr("agent-123")
    try:
        pki.sign_csr(key, cert, csr, "agent-999")
        raise AssertionError("CN diverso deve essere rifiutato")
    except ValueError as e:
        assert "CN" in str(e)


def test_csr_garbage_rejected(tmp_path):
    pki.ensure_ca(str(tmp_path))
    key, cert = pki.load_ca(str(tmp_path))
    try:
        pki.sign_csr(key, cert, b"not-a-csr", "a")
        raise AssertionError("CSR illeggibile rifiutata")
    except ValueError:
        pass


def test_revoked_cert_rejected_and_persisted(tmp_path):
    pki.ensure_ca(str(tmp_path))
    key, cert = pki.load_ca(str(tmp_path))
    _dk, csr = pki.build_agent_csr("agent-7")
    pem, serial, _exp = pki.sign_csr(key, cert, csr, "agent-7")
    rl = pki.RevokeList(str(tmp_path / "revoked.txt"))
    assert not rl.is_revoked(serial)
    rl.revoke(serial)
    assert rl.is_revoked(serial.upper()), "match case-insensitive"
    ok, reason = pki.verify_device_cert(cert, pem, "agent-7", [serial])
    assert not ok and "revocat" in reason
    rl2 = pki.RevokeList(str(tmp_path / "revoked.txt"))
    assert rl2.is_revoked(serial), "revoche sopravvivono al reboot"
    assert rl2.agent_revoked("agent-7") is False
    rl2.revoke("agent:agent-7")
    assert rl2.agent_revoked("agent-7")


def test_wrong_ca_rejected(tmp_path):
    pki.ensure_ca(str(tmp_path / "ca1"))
    pki.ensure_ca(str(tmp_path / "ca2"))
    k1, c1 = pki.load_ca(str(tmp_path / "ca1"))
    _k2, c2 = pki.load_ca(str(tmp_path / "ca2"))
    _dk, csr = pki.build_agent_csr("a")
    pem, _s, _e = pki.sign_csr(k1, c1, csr, "a")
    ok, reason = pki.verify_device_cert(c2, pem, "a")
    assert not ok and "issuer" in reason, reason


def test_manifest_sign_verify(tmp_path):
    priv, pub = pki.ensure_manifest_key(str(tmp_path))
    key = pki.load_manifest_private(priv)
    manifest = {"artifacts": [{"name": "a.zip", "sha256": "abc"}], "key_id": "m1"}
    sig = pki.sign_manifest(key, manifest)
    raw = base64.b64decode(pki.manifest_pubkey_b64(pub))
    assert pki.verify_manifest_signature(raw, manifest, sig)
    assert not pki.verify_manifest_signature(raw, {**manifest, "extra": 1}, sig)
    assert not pki.verify_manifest_signature(raw, manifest, "00" * 64)


def test_fingerprint_stable(tmp_path):
    pki.ensure_ca(str(tmp_path))
    pem = pki.ca_cert_pem(str(tmp_path))
    assert pki.fingerprint_sha256(pem) == pki.fingerprint_sha256(pem)
    assert len(pki.fingerprint_sha256(pem)) == 64


def test_revoke_list_fail_closed_on_io(tmp_path):
    # Un FILE dove serve una directory -> makedirs fallisce -> require_healthy alza.
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    rl = pki.RevokeList(str(blocker / "revoked.txt"))
    try:
        rl.require_healthy()
        raise AssertionError("backend inaffidabile deve alzare")
    except pki.PkiUnavailable:
        pass


def test_revoke_write_failure_raises(tmp_path, monkeypatch):
    rl = pki.RevokeList(str(tmp_path / "revoked.txt"))
    rl.revoke("agent:y")
    assert rl.is_revoked("agent:y")
    assert rl.agent_revoked("y")
    # Simula disco in sola lettura: revoke deve alzare, non fingere.
    import builtins

    def boom(*a, **k):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(builtins, "open", boom)
    try:
        rl.revoke("agent:z")
        raise AssertionError("revoca non persistita deve alzare")
    except pki.PkiUnavailable:
        pass
    finally:
        monkeypatch.undo()


# Vettore gold condiviso con la JVM (ManifestVerifierTest): prova che la
# canonica JSON + Ed25519 concordano tra Python e Java. Firmato una volta
# con pki.sign_manifest; NON modificare senza rifirma.
INTEROP_PUB_B64 = "l2EBppcwnLG+lH4IW/2QB0iC3mxiMHmpWP+ty2nGWCg="
INTEROP_MANIFEST = {
    "artifacts": [{"name": "aegis-guard-3.0.1.zip",
                   "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}],
    "key_id": "aegis-manifest-v1",
}
INTEROP_SIG = ("2c39d931ed3accac06e98b5d55a0d726d21eadc7727f0f79aa2a7fcb1d69fcaf96f"
               "4627fef934b595bca1842733b4261d891beb18b3bb336d12e7a31bcb1d606")


def test_interop_vector_stable():
    import base64
    raw = base64.b64decode(INTEROP_PUB_B64)
    assert len(raw) == 32
    assert pki.verify_manifest_signature(raw, INTEROP_MANIFEST, INTEROP_SIG)
    assert not pki.verify_manifest_signature(
        raw, {**INTEROP_MANIFEST, "key_id": "evil"}, INTEROP_SIG)
