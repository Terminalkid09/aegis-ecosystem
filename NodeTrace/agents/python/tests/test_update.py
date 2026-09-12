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


if __name__ == "__main__":
    unittest.main()
