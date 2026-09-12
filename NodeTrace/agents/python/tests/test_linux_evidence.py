import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.linux_evidence import (
    decode_caps, parse_cap_eff, parse_authorized_keys, parse_lsmod,
    container_hint, list_unit_files, list_cron_entries, file_meta, collect,
    CAP_NAMES,
)


class TestLinuxEvidencePure(unittest.TestCase):
    def test_decode_caps(self):
        self.assertIn("SYS_ADMIN", decode_caps(1 << 20))
        self.assertIn("SYS_BOOT", decode_caps(1 << 21))
        self.assertIn("BPF", decode_caps((1 << 38) | (1 << 39)))
        self.assertEqual(decode_caps(0), [])
        self.assertEqual(decode_caps("nope"), [])
        self.assertEqual(decode_caps(-5), [])

    def test_parse_cap_eff(self):
        self.assertEqual(parse_cap_eff("Name:\tx\nCapEff:\t0000ffffffffffff\n"),
                         0xFFFFFFFFFFFF)
        self.assertEqual(parse_cap_eff("no caps here"), -1)
        self.assertEqual(parse_cap_eff(""), -1)

    def test_parse_authorized_keys(self):
        body = ("# comment\n"
                "\n"
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqNkG0w4oRZ9 user@host\n"
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCt3Gxm other\n"
                "invalid-line\n"
                "telnet XYZ bogus\n")
        out = parse_authorized_keys(body)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["algo"], "ssh-ed25519")
        self.assertEqual(len(out[0]["sha256"]), 64)
        self.assertEqual(out[0]["comment"], "user@host")
        # Mai la chiave in chiaro nel risultato.
        self.assertNotIn("AAAAC3Nza", str(out))

    def test_parse_lsmod(self):
        out = parse_lsmod("Module                  Size  Used by\n"
                          "nft_chain_nat          12288  0\n"
                          "bridge                327680  0\n")
        self.assertEqual(out, ["nft_chain_nat", "bridge"])
        self.assertEqual(parse_lsmod(""), [])

    def test_container_hint(self):
        self.assertEqual(
            container_hint("12:devices:/docker/ab12\n", "")["runtime"], "docker")
        self.assertEqual(
            container_hint("0::/kubepods/besteffort/pod1\n", "")["runtime"], "kubepods")
        bare = container_hint("12:devices:/init.scope\n", "init (1, #threads: 1)\n")
        self.assertFalse(bare["container"])
        self.assertEqual(bare["runtime"], "")

    def test_list_unit_files_tmp(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, "a.service"), "w").write("[Unit]")
            open(os.path.join(tmp, "b.txt"), "w").write("x")
            out = list_unit_files([tmp, "/definitely/not/here"])
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]["name"], "a.service")

    def test_list_cron_entries_tmp(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sub = os.path.join(tmp, "cron.d")
            os.mkdir(sub)
            open(os.path.join(sub, "job"), "w").write("* * * * * root true")
            out = list_cron_entries([sub, "/definitely/not/here"])
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]["entries"], 1)

    def test_file_meta_missing(self):
        self.assertIsNone(file_meta("/definitely/not/here-xyz"))

    def test_collect_shaped_no_content(self):
        ev = collect()
        self.assertIn("degraded", ev)
        blob = str(ev)
        # Mai chiavi private o contenuti sensibili.
        self.assertNotIn("PRIVATE", blob)

    def test_cap_names_cover_bpf_perfmon(self):
        self.assertEqual(CAP_NAMES[38], "BPF")
        self.assertEqual(CAP_NAMES[37], "PERFMON")
        self.assertEqual(CAP_NAMES[20], "SYS_ADMIN")
        self.assertEqual(CAP_NAMES[21], "SYS_BOOT")


if __name__ == "__main__":
    unittest.main()
