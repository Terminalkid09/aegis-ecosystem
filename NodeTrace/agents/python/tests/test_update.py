import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.updater import (
    hmac_sign,
    verify_signature,
    sha256_file,
    is_newer,
    stage_package,
    verify_manifest_ed25519,
    manifest_covers,
)
from services.token_service import TokenService

try:
    import cryptography  # noqa
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Vettore gold condiviso col brain (test_pki) e la JVM (ManifestVerifierTest).
INTEROP_PUB = "l2EBppcwnLG+lH4IW/2QB0iC3mxiMHmpWP+ty2nGWCg="
INTEROP_MANIFEST = (
    '{"artifacts":[{"name":"aegis-guard-3.0.1.zip",'
    '"sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}],'
    '"key_id":"aegis-manifest-v1"}'
)
INTEROP_SIG = ("2c39d931ed3accac06e98b5d55a0d726d21eadc7727f0f79aa2a7fcb1d69fcaf96f"
               "4627fef934b595bca1842733b4261d891beb18b3bb336d12e7a31bcb1d606")


class TestUpdater(unittest.TestCase):
    def test_hmac_round_trip(self):
        sig = hmac_sign("abc123", "enroll-key")
        self.assertTrue(verify_signature("abc123", sig, "enroll-key"))

    def test_wrong_key_fails(self):
        sig = hmac_sign("abc123", "right")
        self.assertFalse(verify_signature("abc123", sig, "wrong"))

    def test_tampered_sha_fails(self):
        sig = hmac_sign("abc123", "k")
        self.assertFalse(verify_signature("abc124", sig, "k"))

    def test_empty_inputs_fail_closed(self):
        self.assertFalse(verify_signature("", "x", "k"))
        self.assertFalse(verify_signature("x", None, "k"))
        self.assertFalse(verify_signature("x", "y", "  "))

    def test_version_compare(self):
        self.assertTrue(is_newer("1.0.0", "1.0.1"))
        self.assertTrue(is_newer("1.9.0", "1.10.0"))
        self.assertFalse(is_newer("2.0.0", "1.9.9"))
        self.assertFalse(is_newer("1.0.0", "1.0.0"))
        self.assertTrue(is_newer("1.0.0", "latest"))
        self.assertTrue(is_newer(None, "1.0.0"))

    def test_stage_verifies_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkg = os.path.join(tmp, "dl.pkg")
            with open(pkg, "wb") as f:
                f.write(b"fake-bytes")
            sha = sha256_file(pkg)
            staged = stage_package(pkg, sha, os.path.join(tmp, "work"))
            self.assertTrue(os.path.exists(staged))
            self.assertFalse(os.path.exists(pkg))

    def test_stage_rejects_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkg = os.path.join(tmp, "dl.pkg")
            with open(pkg, "wb") as f:
                f.write(b"fake-bytes")
            with self.assertRaises(ValueError):
                stage_package(pkg, "0" * 64, tmp)
            self.assertFalse(os.path.exists(pkg))


@unittest.skipUnless(HAS_CRYPTO, "cryptography non installata (agent lean)")
class TestManifestEd25519(unittest.TestCase):
    def test_interop_vector(self):
        self.assertTrue(verify_manifest_ed25519(INTEROP_MANIFEST, INTEROP_SIG, INTEROP_PUB))

    def test_tampered_rejected(self):
        evil = INTEROP_MANIFEST.replace("3.0.1", "9.9.9")
        self.assertFalse(verify_manifest_ed25519(evil, INTEROP_SIG, INTEROP_PUB))
        self.assertFalse(verify_manifest_ed25519(INTEROP_MANIFEST, "00" * 64, INTEROP_PUB))

    def test_bad_inputs_fail_closed(self):
        self.assertFalse(verify_manifest_ed25519("", INTEROP_SIG, INTEROP_PUB))
        self.assertFalse(verify_manifest_ed25519(INTEROP_MANIFEST, "", INTEROP_PUB))
        self.assertFalse(verify_manifest_ed25519(INTEROP_MANIFEST, INTEROP_SIG, ""))

    def test_manifest_covers(self):
        self.assertTrue(manifest_covers(
            INTEROP_MANIFEST, "aegis-guard-3.0.1.zip",
            "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"))
        self.assertFalse(manifest_covers(INTEROP_MANIFEST, "evil.zip",
                                         "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"))
        self.assertFalse(manifest_covers("not-json", "a", "b"))


class TestServerPin(unittest.TestCase):
    def test_same_ok(self):
        self.assertIsNone(TokenService.check_server_pin(
            "https://aegis.local/api/v1", "https://aegis.local/api/v1/"))
        self.assertIsNone(TokenService.check_server_pin(None, "https://x"))
        self.assertIsNone(TokenService.check_server_pin("", "https://x"))

    def test_changed_refused(self):
        err = TokenService.check_server_pin(
            "https://aegis.local/api/v1", "https://evil.example/api/v1")
        self.assertIsNotNone(err)
        self.assertIn("re-enroll", err)
        self.assertIsNotNone(TokenService.check_server_pin("https://a", ""))

    def test_save_load_server_roundtrip(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            svc = TokenService()
            svc.FILE = os.path.join(tmp, "token.json")
            svc.save("tok", "dev-1", server_url="https://aegis.local/api/v1")
            tok, dev = svc.load()
            self.assertEqual((tok, dev), ("tok", "dev-1"))
            self.assertEqual(svc.load_server(), "https://aegis.local/api/v1")

    def test_token_file_is_private(self):
        # Audit: token.json mai world-readable (solo POSIX: su Windows gli
        # ACL non mappano sui bit unix).
        import stat
        import sys as _sys
        if _sys.platform == "win32":
            self.skipTest("permessi unix non applicabili su Windows")
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            svc = TokenService()
            svc.FILE = os.path.join(tmp, "token.json")
            svc.save("tok", "dev-1")
            mode = stat.S_IMODE(os.stat(svc.FILE).st_mode)
            self.assertEqual(mode & 0o077, 0, oct(mode))


class TestScanBounds(unittest.TestCase):
    def test_rejects_huge_cidr(self):
        from services.network import NetworkService
        svc = NetworkService()
        with self.assertRaises(ValueError):
            svc.scan_network(cidr="10.0.0.0/8")
        with self.assertRaises(ValueError):
            svc.scan_network(cidr="0.0.0.0/0")

    def test_rejects_port_flood(self):
        from services.network import NetworkService
        svc = NetworkService()
        with self.assertRaises(ValueError):
            svc.scan_network(cidr="192.168.1.0/24", ports=list(range(1, 7000)))
        with self.assertRaises(ValueError):
            svc.scan_network(cidr="192.168.1.0/24", ports=[])

    def test_rejects_bad_timeout(self):
        from services.network import NetworkService
        svc = NetworkService()
        with self.assertRaises(ValueError):
            svc.scan_network(cidr="192.168.1.0/24", probe_timeout=30)
        with self.assertRaises(ValueError):
            svc.scan_network(cidr="192.168.1.0/24", probe_timeout="fast")


class TestHttpErrors(unittest.TestCase):
    def test_ensure_ok_raises_on_5xx(self):
        from utils.curl_http import Response, ensure_ok, HttpStatusError
        with self.assertRaises(HttpStatusError):
            ensure_ok(Response(500, "boom"), "telemetry")
        # 401/404 gestiti dal chiamante, non retry cieco:
        self.assertEqual(ensure_ok(Response(401, "x"), "h").status_code, 401)
        self.assertEqual(ensure_ok(Response(404, "x"), "h").status_code, 404)
        self.assertEqual(ensure_ok(Response(200, "ok"), "h").status_code, 200)


class TestUpdateUrlAllowlist(unittest.TestCase):
    def _agent(self, hb):
        import types
        import agent as _agent_mod
        a = types.SimpleNamespace(config={"heartbeat_url": hb})
        # Lo stub deve esporre anche il sibling usato dal gate.
        a._brain_origin = _agent_mod.Agent._brain_origin.__get__(a)
        return _agent_mod.Agent._update_url_allowed.__get__(a)

    def test_allows_brain_artifacts(self):
        f = self._agent("https://aegis.local/api/v1/nodetrace/heartbeat")
        self.assertTrue(f("https://aegis.local/api/v1/deploy/artifacts/nodetrace-1.tar.gz"))

    def test_rejects_off_origin_and_paths(self):
        f = self._agent("https://aegis.local/api/v1/nodetrace/heartbeat")
        self.assertFalse(f("https://evil.example/a.tar.gz"))
        self.assertFalse(f("https://aegis.local/api/v1/auth/login"))
        self.assertFalse(f("http://aegis.local/api/v1/deploy/artifacts/x"))
        self.assertFalse(f("not-a-url"))


class TestPidLock(unittest.TestCase):
    def test_stale_lock_overwritten(self):
        import tempfile
        import agent as _agent_mod
        with tempfile.TemporaryDirectory() as tmp:
            pf = os.path.join(tmp, "agent.pid")
            with open(pf, "w") as f:
                f.write("99999999")
            _agent_mod.PidLock(pf).acquire()
            with open(pf) as f:
                self.assertEqual(f.read().strip(), str(os.getpid()))

    def test_alien_pid_overwritten(self):
        # PID vivo ma NON nostro (init): prima usciva "already running".
        import tempfile
        import agent as _agent_mod
        with tempfile.TemporaryDirectory() as tmp:
            pf = os.path.join(tmp, "agent.pid")
            with open(pf, "w") as f:
                f.write("1")
            if not _agent_mod._pid_alive(1):
                self.skipTest("pid 1 assente qui")
            _agent_mod.PidLock(pf).acquire()
            with open(pf) as f:
                self.assertEqual(f.read().strip(), str(os.getpid()))


class TestStagedStateSeal(unittest.TestCase):
    def _staged(self, tmp):
        from services.updater import stage_package, sha256_file
        pkg = os.path.join(tmp, "agent.pkg")
        with open(pkg, "wb") as f:
            f.write(b"fake-agent-bytes")
        sha = sha256_file(pkg)
        staged = stage_package(pkg, sha, tmp)
        return staged, sha

    def test_rollback_rejected(self):
        import tempfile
        from services.updater import stage_package, sha256_file
        with tempfile.TemporaryDirectory() as tmp:
            pkg = os.path.join(tmp, "agent.pkg")
            with open(pkg, "wb") as f:
                f.write(b"fake-agent-bytes")
            sha = sha256_file(pkg)
            with self.assertRaises(ValueError):
                stage_package(pkg, sha, tmp, current_version="2.0.0",
                              target_version="1.9.9")
            self.assertFalse(os.path.exists(pkg))

    def test_seal_roundtrip_and_tamper(self):
        import tempfile
        from services.updater import seal_staged_state, verify_staged_state, STATE_FILE
        with tempfile.TemporaryDirectory() as tmp:
            staged, sha = self._staged(tmp)
            seal_staged_state(tmp, "device-secret")
            got_staged, got_sha = verify_staged_state(tmp, "device-secret")
            self.assertEqual(got_staged, staged)
            self.assertEqual(got_sha, sha)
            with self.assertRaises(ValueError):
                verify_staged_state(tmp, "wrong-secret")
            state = os.path.join(tmp, STATE_FILE)
            with open(state, encoding="utf-8") as f:
                content = f.read().replace("agent.pkg", "evil.pkg")
            with open(state, "w", encoding="utf-8") as f:
                f.write(content)
            with self.assertRaises(ValueError):
                verify_staged_state(tmp, "device-secret")


if __name__ == "__main__":
    unittest.main()
