import datetime
import os
import ssl
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services import device_identity as di


class TestDeviceIdentity(unittest.TestCase):
    def test_csr_cn_and_signature(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        key_pem, csr_pem = di.build_csr("agent-42")
        self.assertIn("CERTIFICATE REQUEST", csr_pem)
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, "agent-42")
        self.assertTrue(csr.is_signature_valid)

    def test_save_load_roundtrip_and_perms(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            key_pem, csr_pem = di.build_csr("a")
            # Self-signed finto per roundtrip storage (firma non verificata qui).
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            key = serialization.load_pem_private_key(key_pem.encode(), None)
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "a")]))
                    .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ca")]))
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=10))
                    .sign(key, hashes.SHA256()))
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            kp, cp = di.save_identity(tmp, key_pem, cert_pem)
            if os.name == "posix":
                self.assertEqual(oct(os.stat(kp).st_mode & 0o777), "0o600")
            k2, c2 = di.load_identity(tmp)
            self.assertEqual(k2, key_pem)
            self.assertEqual(c2, cert_pem)
            # Il cert da 10gg rientra nella finestra di rinnovo (30gg).
            self.assertTrue(di.needs_renewal(c2))

    def test_corrupt_quarantined(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            kp, _cp = di.identity_paths(tmp)
            os.makedirs(tmp, exist_ok=True)
            with open(kp, "w") as f:
                f.write("NOT-A-KEY")
            with open(_cp, "w") as f:
                f.write("NOT-A-CERT")
            self.assertEqual(di.load_identity(tmp), (None, None))
            self.assertFalse(os.path.exists(kp))
            bad = [p for p in os.listdir(tmp) if ".bad" in p]
            self.assertTrue(bad, "file corrotti in quarantena, mai cancellati")

    def test_needs_renewal_predicate(self):
        self.assertTrue(di.needs_renewal(None))
        self.assertTrue(di.needs_renewal("garbage"))
        import tempfile
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        for days, expected in ((400, False), (10, True), (-1, True)):
            cert = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "a")]))
                    .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ca")]))
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=2))
                    .not_valid_after(now + datetime.timedelta(days=days))
                    .sign(key, hashes.SHA256()))
            pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            self.assertEqual(di.needs_renewal(pem), expected, days)

    def test_b64_and_fingerprint(self):
        key_pem, _csr = di.build_csr("a")
        import tempfile
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = serialization.load_pem_private_key(key_pem.encode(), None)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "a")]))
                .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ca")]))
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=10))
                .sign(key, hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        b64 = di.cert_b64der(pem)
        self.assertNotIn("\n", b64)
        import base64
        from cryptography import x509 as _x2
        back = _x2.load_der_x509_certificate(base64.b64decode(b64))
        cn = back.subject.get_attributes_for_oid(_x2.oid.NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, "a")
        self.assertEqual(len(di.fingerprint_sha256(pem)), 64)

    def test_ssl_context_mutual(self):
        # CA + server + client reali, handshake mutuo in-process.
        import tempfile
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "T-CA")])
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=2))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
              .sign(ca_key, hashes.SHA256()))

        def issue(cn, server=False):
            k = ec.generate_private_key(ec.SECP256R1())
            b = (x509.CertificateBuilder()
                 .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)]))
                 .issuer_name(ca_name).public_key(k.public_key())
                 .serial_number(x509.random_serial_number())
                 .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=2)))
            if server:
                b = b.add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                 x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1"))]),
                    False)
                b = b.add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), True)
            else:
                b = b.add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), True)
            c = b.sign(ca_key, hashes.SHA256())
            enc = serialization.Encoding.PEM
            return (k.private_bytes(enc, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode(),
                    c.public_bytes(enc).decode())

        srv_key, srv_crt = issue("localhost", server=True)
        cli_key, cli_crt = issue("agent-1")
        with tempfile.TemporaryDirectory() as tmp:
            ca_p = os.path.join(tmp, "ca.crt")
            open(ca_p, "w").write(
                ca.public_bytes(serialization.Encoding.PEM).decode())
            # Server che richiede client cert della CA.
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sk = os.path.join(tmp, "s.key")
            sc = os.path.join(tmp, "s.crt")
            open(sk, "w").write(srv_key)
            open(sc, "w").write(srv_crt)
            sctx.load_cert_chain(sc, sk)
            sctx.load_verify_locations(cafile=ca_p)
            sctx.verify_mode = ssl.CERT_REQUIRED
            ls = socket_bind()
            got = {}

            def serve():
                conn, _a = ls.accept()
                try:
                    tls = sctx.wrap_socket(conn, server_side=True)
                    tls.do_handshake()
                    peer = tls.getpeercert(binary_form=True)
                    got["peer"] = peer
                    # Drena la richiesta: chiudere con dati non letti causa RST
                    # e il client perderebbe la risposta (flaky).
                    tls.settimeout(5)
                    req = b""
                    try:
                        while b"\r\n\r\n" not in req:
                            chunk = tls.recv(1024)
                            if not chunk:
                                break
                            req += chunk
                    except Exception:
                        pass
                    tls.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    tls.close()
                except Exception as e:  # noqa - handshake rifiutato = test valido
                    got["error"] = type(e).__name__
                finally:
                    ls.close()

            import threading
            th = threading.Thread(target=serve, daemon=True)
            th.start()
            port = ls.getsockname()[1]
            # Client buono via helper del modulo (CA pinnata, hostname verificato).
            with tempfile.TemporaryDirectory() as tmp2:
                kp = os.path.join(tmp2, "device.key")
                cp = os.path.join(tmp2, "device.crt")
                open(kp, "w").write(cli_key)
                open(cp, "w").write(cli_crt)
                with open(kp, encoding="utf-8") as _kf, open(cp, encoding="utf-8") as _cf:
                    cctx = di.build_ssl_context(ca_p, _kf.read(), _cf.read())
                import socket as _s
                with _s.create_connection(("127.0.0.1", port), timeout=10) as raw:
                    with cctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                        tls.sendall(b"GET / HTTP/1.0\r\n\r\n")
                        data = tls.recv(64)
                        self.assertIn(b"200", data)
            th.join(10)
            self.assertIn("peer", got, f"server-side: {got.get('error')}")

    def test_ssl_context_no_ca_fails_closed(self):
        with self.assertRaises(ValueError):
            di.build_ssl_context("/definitely/no-ca.crt", "k", "c")


def socket_bind():
    import socket as _s
    ls = _s.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    return ls


if __name__ == "__main__":
    unittest.main()
