"""Post-audit: mutual auth agent + mTLS end-to-end reale (loopback TLS)."""
import socket
import ssl
import threading

import pytest
from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.serialization import Encoding as _Enc
from fastapi import HTTPException

from app.core import config
from app.services import mtls, pki


@pytest.fixture()
def pki_dir(tmp_path, monkeypatch):
    d = str(tmp_path / "pki")
    pki.ensure_ca(d)
    monkeypatch.setattr(config.settings, "PKI_DIR", d)
    monkeypatch.setattr(config.settings, "MTLS_MODE", "required")
    return d


@pytest.fixture()
def device(pki_dir):
    key, cert = pki.load_ca(pki_dir)
    _dk, csr = pki.build_agent_csr("agent-007")
    pem, serial, _exp = pki.sign_csr(key, cert, csr, "agent-007")
    return {"pem": pem, "serial": serial}


def test_extract_header_variants():
    assert mtls.extract_client_cert({}) is None
    assert mtls.extract_client_cert({"x-client-cert": "garbage"}) is None
    assert mtls.extract_client_cert({"x-client-cert": "x" * 9000}) is None
    pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    assert mtls.extract_client_cert({"X-Client-Cert": pem.decode()}) == pem.strip()


def test_extract_b64_der_transport(pki_dir, device):
    """Trasporto single-line reale: base64(DER) -> PEM normalizzato."""
    import base64
    from cryptography import x509 as _x509
    cert = _x509.load_pem_x509_certificate(device["pem"])
    der_b64 = base64.b64encode(
        cert.public_bytes(_Enc.DER)).decode()
    out = mtls.extract_client_cert({"x-client-cert": der_b64})
    assert out is not None and b"BEGIN CERTIFICATE" in out
    ok, _ = mtls.verify_agent_cert("agent-007", out)
    assert ok


def test_verify_ok_and_wrong_cn(pki_dir, device):
    ok, reason = mtls.verify_agent_cert("agent-007", device["pem"])
    assert ok, reason
    ok, reason = mtls.verify_agent_cert("agent-999", device["pem"])
    assert not ok and "CN" in reason


def test_verify_revoked_agent(pki_dir, device):
    rl = pki.RevokeList(f"{pki_dir}/{pki.REVOKED}")
    rl.revoke("agent:agent-007")
    ok, reason = mtls.verify_agent_cert("agent-007", device["pem"])
    assert not ok and "revocat" in reason


def test_verify_unhealthy_pki_raises(pki_dir, device, monkeypatch):
    monkeypatch.setattr(config.settings, "PKI_DIR", "/definitely/not/here")
    try:
        mtls.verify_agent_cert("agent-007", device["pem"])
        raise AssertionError("PKI illeggibile deve negare con eccezione")
    except pki.PkiUnavailable:
        pass


def test_enforce_matrix(pki_dir, device, monkeypatch):
    monkeypatch.setattr(config.settings, "MTLS_MODE", "off")
    assert mtls.enforce({}, "agent-007") is None
    monkeypatch.setattr(config.settings, "MTLS_MODE", "optional")
    assert mtls.enforce({}, "agent-007") == "no-cert-optional"
    try:
        mtls.enforce({"x-client-cert": "garbage"}, "agent-007")
        raise AssertionError("optional con cert invalido = 401")
    except HTTPException as e:
        assert e.status_code == 401
    monkeypatch.setattr(config.settings, "MTLS_MODE", "required")
    try:
        mtls.enforce({}, "agent-007")
        raise AssertionError("required senza cert = 401")
    except HTTPException as e:
        assert e.status_code == 401
    headers = {"x-client-cert": device["pem"].decode()}
    assert mtls.enforce(headers, "agent-007") == "cert-ok"
    monkeypatch.setattr(config.settings, "PKI_DIR", "/definitely/not/here")
    try:
        mtls.enforce(headers, "agent-007")
        raise AssertionError("PKI rotta = 503 fail-closed")
    except HTTPException as e:
        assert e.status_code == 503


def test_enforce_bootstrap_allows_first_issue(pki_dir, device, monkeypatch):
    monkeypatch.setattr(config.settings, "MTLS_MODE", "required")
    # Primo rilascio senza cert: consentito solo in bootstrap (es. /enroll/csr).
    assert mtls.enforce({}, "agent-007", bootstrap=True) == "bootstrap-no-cert"
    # Sulle rotte normali resta negato.
    try:
        mtls.enforce({}, "agent-007")
        raise AssertionError("required senza cert = 401")
    except HTTPException as e:
        assert e.status_code == 401
    # Con cert valido il bootstrap passa comunque.
    headers = {"x-client-cert": device["pem"].decode()}
    assert mtls.enforce(headers, "agent-007", bootstrap=True) == "cert-ok"


def test_enforce_fingerprint_binding(pki_dir, device, monkeypatch):
    import hashlib
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives.serialization import Encoding as _E
    monkeypatch.setattr(config.settings, "MTLS_MODE", "required")
    fp = hashlib.sha256(
        _x509.load_pem_x509_certificate(device["pem"]).public_bytes(_E.DER)).hexdigest()

    class FakeAgent:
        agent_id = "agent-007"
        meta = {"site": "hq", "device_cert_sha256": fp}

    h = {"x-client-cert-hash": fp}
    assert mtls.enforce_fingerprint(FakeAgent(), h) == "fingerprint-ok"
    # Site preservato altrove, binding esatto qui.
    try:
        mtls.enforce_fingerprint(FakeAgent(), {"x-client-cert-hash": "0" * 64})
        raise AssertionError("hash errato = 401")
    except HTTPException as e:
        assert e.status_code == 401
    # Senza fingerprint legato: 401 anche con hash ben formato.
    class Bare:
        agent_id = "agent-007"
        meta = {}
    try:
        mtls.enforce_fingerprint(Bare(), h)
        raise AssertionError("senza binding = 401")
    except HTTPException as e:
        assert e.status_code == 401
    # Revoca agent: 401 anche con hash giusto.
    pki.RevokeList(f"{pki_dir}/{pki.REVOKED}").revoke("agent:agent-007")
    try:
        mtls.enforce_fingerprint(FakeAgent(), h)
        raise AssertionError("revocato = 401")
    except HTTPException as e:
        assert e.status_code == 401


def _write(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)
    return str(path)


def _run_tls_server(ca_crt, srv_crt, srv_key, pki_dir, out: dict):
    """Server TLS che richiede cert client e applica revoca app-layer."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(srv_crt, srv_key)
    ctx.load_verify_locations(cafile=ca_crt)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    out["port"] = ls.getsockname()[1]
    out["ready"].set()
    conn, _addr = ls.accept()
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
        try:
            peer_der = tls.getpeercert(binary_form=True)
            peer_pem = ssl.DER_cert_to_PEM_cert(peer_der).encode()
            # CN dal cert presentato
            from cryptography import x509 as _x509
            from cryptography.x509.oid import NameOID as _N
            cn = _x509.load_pem_x509_certificate(peer_pem).subject.get_attributes_for_oid(
                _N.COMMON_NAME)[0].value
            ok, reason = mtls.verify_agent_cert(cn, peer_pem)
            tls.sendall(b"OK" if ok else b"DENIED")
            out["result"] = (ok, reason, cn)
        except Exception as e:  # handshake fallito (es. cert scaduto)
            out["result"] = (False, f"handshake: {e}", "")
    finally:
        try:
            conn.close()
        except OSError:
            pass
        ls.close()


def _tls_client(ca_crt, cli_crt, cli_key, port) -> bytes:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=ca_crt)
    ctx.load_cert_chain(cli_crt, cli_key)
    ctx.check_hostname = False  # loopback: verifichiamo noi CN/SAN nel test
    ctx.verify_mode = ssl.CERT_REQUIRED
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            return tls.recv(16)


def test_mtls_end_to_end_loopback(pki_dir, tmp_path):
    """Handshake TLS mutuo REALE con materiale pki.* + revoca sul wire."""
    key, cert = pki.load_ca(pki_dir)
    srv_key, srv_crt = pki.issue_server_cert(
        key, cert, "localhost", san_dns=["localhost"])
    ca_crt = f"{pki_dir}/{pki.CA_CRT}"
    _dk, csr = pki.build_agent_csr("agent-007")
    dev_pem, _serial, _exp = pki.sign_csr(key, cert, csr, "agent-007")

    files = {}
    for name, data in (("srv.key", srv_key), ("srv.crt", srv_crt),
                       ("cli.key", _dk.private_bytes(
                           _ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                           _ser.NoEncryption())),
                       ("cli.crt", dev_pem)):
        files[name] = _write(str(tmp_path / name), data)

    out = {"ready": threading.Event()}
    t = threading.Thread(target=_run_tls_server,
                         args=(ca_crt, files["srv.crt"], files["srv.key"], pki_dir, out),
                         daemon=True)
    t.start()
    assert out["ready"].wait(10)
    assert _tls_client(ca_crt, files["cli.crt"], files["cli.key"], out["port"]) == b"OK"
    t.join(10)
    assert out["result"][0] is True and out["result"][2] == "agent-007"


def test_mtls_revoked_denied_on_wire(pki_dir, tmp_path):
    key, cert = pki.load_ca(pki_dir)
    srv_key, srv_crt = pki.issue_server_cert(
        key, cert, "localhost", san_dns=["localhost"])
    ca_crt = f"{pki_dir}/{pki.CA_CRT}"
    _dk, csr = pki.build_agent_csr("agent-007")
    dev_pem, serial, _exp = pki.sign_csr(key, cert, csr, "agent-007")
    pki.RevokeList(f"{pki_dir}/{pki.REVOKED}").revoke(serial)

    files = {}
    for name, data in (("srv.key", srv_key), ("srv.crt", srv_crt),
                       ("cli.key", _dk.private_bytes(
                           _ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                           _ser.NoEncryption())),
                       ("cli.crt", dev_pem)):
        files[name] = _write(str(tmp_path / name), data)

    out = {"ready": threading.Event()}
    t = threading.Thread(target=_run_tls_server,
                         args=(ca_crt, files["srv.crt"], files["srv.key"], pki_dir, out),
                         daemon=True)
    t.start()
    assert out["ready"].wait(10)
    # Handshake passa (cert valido), ma l'app-layer nega per revoca.
    assert _tls_client(ca_crt, files["cli.crt"], files["cli.key"], out["port"]) == b"DENIED"
    t.join(10)
    assert out["result"][0] is False and "revocat" in out["result"][1]


def test_enterprise_strict_guard(monkeypatch):
    from app.main import enforce_enterprise_strict
    monkeypatch.setattr(config.settings, "ENTERPRISE_STRICT", False)
    enforce_enterprise_strict()  # nessun vincolo in dev/lab
    monkeypatch.setattr(config.settings, "ENTERPRISE_STRICT", True)
    monkeypatch.setattr(config.settings, "MTLS_MODE", "required")
    enforce_enterprise_strict()
    monkeypatch.setattr(config.settings, "MTLS_MODE", "off")
    try:
        enforce_enterprise_strict()
        raise AssertionError("prod senza mTLS deve rifiutare l'avvio")
    except RuntimeError as e:
        assert "MTLS_MODE" in str(e)
