import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.linux_probe import (
    parse_kernel_release, kernel_supports_ebpf, parse_cap_eff,
    has_ebpf_caps, probe, auditd_available, systemd_available,
    sensor_mode, CAP_BPF, CAP_PERFMON,
)
from services.auditd import parse_record, AuditdTailer


class TestLinuxProbe(unittest.TestCase):
    def test_parse_kernel_release(self):
        self.assertEqual(parse_kernel_release("6.6.8-200.fc39.x86_64"), (6, 6, 8))
        self.assertEqual(parse_kernel_release("5.15.0-91-generic"), (5, 15, 0))
        self.assertEqual(parse_kernel_release("4.18"), (4, 18))
        self.assertEqual(parse_kernel_release("garbage"), ())
        self.assertEqual(parse_kernel_release(""), ())
        self.assertEqual(parse_kernel_release(None), ())

    def test_kernel_supports_ebpf(self):
        self.assertTrue(kernel_supports_ebpf("6.6.8"))
        self.assertTrue(kernel_supports_ebpf("5.8.0"))
        self.assertFalse(kernel_supports_ebpf("5.4.0-150-generic"))
        self.assertFalse(kernel_supports_ebpf("4.18.0"))
        self.assertFalse(kernel_supports_ebpf("nope"))

    def test_parse_cap_eff(self):
        self.assertEqual(parse_cap_eff("Name:\tbash\nCapEff:\t0000ffffffffffff\n"), 0xFFFFFFFFFFFF)
        self.assertEqual(parse_cap_eff("no caps here"), -1)
        self.assertEqual(parse_cap_eff(""), -1)

    def test_has_ebpf_caps(self):
        self.assertTrue(has_ebpf_caps(CAP_BPF | CAP_PERFMON))
        self.assertTrue(has_ebpf_caps(0xFFFFFFFFFFFF))  # root / privileged
        self.assertFalse(has_ebpf_caps(CAP_BPF))  # serve anche PERFMON
        self.assertFalse(has_ebpf_caps(0))
        self.assertFalse(has_ebpf_caps(-1))

    def test_probe_never_raises_and_shaped(self):
        p = probe()
        self.assertIn(p["profile"], ("full", "partial", "absent"))
        self.assertIn("reason", p)
        self.assertIn("kernel", p)

    def test_auditd_systemd_helpers_shaped(self):
        self.assertIsInstance(auditd_available(), str)
        self.assertIsInstance(systemd_available(), bool)

    def test_sensor_mode_matrix(self):
        self.assertEqual(sensor_mode("linux", True, False), "full")
        self.assertEqual(sensor_mode("Linux", True, True), "full")
        self.assertEqual(sensor_mode("linux", False, True), "partial")
        self.assertEqual(sensor_mode("linux", False, False), "fallback")
        self.assertEqual(sensor_mode("win32", False, False), "unavailable")
        self.assertEqual(sensor_mode("darwin", True, True), "unavailable")
        self.assertEqual(sensor_mode("", False, False), "unavailable")
        self.assertEqual(sensor_mode(None, False, False), "unavailable")


EXEC_RECORD = [
    'type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 '
    'a0=55b instances a1=1 items=0 ppid=100 pid=101 auid=1000 uid=1000 gid=1000 euid=1000 '
    'exe="/bin/bash" key="aegis-exec"',
    'type=EXECVE msg=audit(1700000000.123:456): argc=2 a0="bash" a1="-c"',
]


class TestAuditd(unittest.TestCase):
    def test_parse_exec(self):
        ev = parse_record(EXEC_RECORD)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["pid"], 101)
        self.assertEqual(ev["ppid"], 100)
        self.assertEqual(ev["uid"], 1000)
        self.assertEqual(ev["comm"], "bash")
        self.assertEqual(ev["filename"], "/bin/bash")
        self.assertEqual(ev["event_type"], "PROCESS_CREATED")
        self.assertEqual(ev["provenance"], "auditd")
        self.assertEqual(ev["schema_version"], 2)
        self.assertTrue(ev["event_id"])
        self.assertEqual(ev["ts_wall_ns"], int(1700000000.123 * 1e9))

    def test_rejects_non_exec(self):
        self.assertIsNone(parse_record([]))
        self.assertIsNone(parse_record(['type=PATH msg=audit(1.0:1): item=0 name="/x"']))
        self.assertIsNone(parse_record([
            'type=SYSCALL msg=audit(1700000000.1:1): arch=c000003e syscall=257 success=yes '
            'pid=5 ppid=1 uid=0 exe="/bin/x"']))  # openat, non exec
        self.assertIsNone(parse_record([
            'type=SYSCALL msg=audit(1700000000.1:1): arch=c000003e syscall=59 success=no '
            'pid=5 ppid=1 uid=0 exe="/bin/x"']))  # failed syscall
        self.assertIsNone(parse_record([
            'type=SYSCALL msg=audit(1700000000.1:1): arch=c000003e syscall=59 success=yes '
            'pid=0 ppid=1 uid=0 exe="/bin/x"']))

    def test_tailer_reads_file_and_survives_missing(self):
        import tempfile
        t = AuditdTailer("/definitely/missing/audit.log")
        self.assertEqual(t.poll(), [])
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("\n".join(EXEC_RECORD) + "\n")
            path = f.name
        try:
            t2 = AuditdTailer(path)
            evs = t2.poll()
            self.assertEqual(len(evs), 1)
            self.assertEqual(evs[0]["comm"], "bash")
            self.assertEqual(t2.poll(), [], "seconda poll senza append = vuota")
            with open(path, "a") as f:
                f.write("\n".join(EXEC_RECORD) + "\n")
            self.assertEqual(len(t2.poll()), 1, "append rilevato")
        finally:
            os.unlink(path)

    def test_a0_spoof_prefers_exe(self):
        # Audit: execve("/tmp/mal", ["bash"]) deve restare "mal", non "bash".
        spoof = [
            'type=SYSCALL msg=audit(1700000000.123:457): arch=c000003e syscall=59 success=yes '
            'pid=102 ppid=100 auid=1000 uid=1000 exe="/tmp/mal"',
            'type=EXECVE msg=audit(1700000000.123:457): argc=1 a0="bash"',
        ]
        ev = parse_record(spoof)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["comm"], "mal")
        self.assertEqual(ev["filename"], "/tmp/mal")

    def test_event_id_stable_per_serial(self):
        a = parse_record(EXEC_RECORD)
        b = parse_record(list(EXEC_RECORD))
        self.assertIsNotNone(a)
        self.assertEqual(a["event_id"], b["event_id"])
        self.assertTrue(a["event_id"].startswith("audit-"))

    def test_interleaved_records_not_mixed(self):
        import tempfile
        rec_b = [
            'type=SYSCALL msg=audit(1700000000.124:458): arch=c000003e syscall=59 success=yes '
            'pid=103 ppid=100 auid=1000 uid=0 exe="/usr/bin/evil"',
            'type=EXECVE msg=audit(1700000000.124:458): argc=1 a0="evil"',
        ]
        blob = "\n".join([EXEC_RECORD[0], rec_b[0], EXEC_RECORD[1], rec_b[1]]) + "\n"
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write(blob)
            path = f.name
        try:
            evs = AuditdTailer(path).poll()
            self.assertEqual(len(evs), 2)
            comms = sorted(e["comm"] for e in evs)
            self.assertEqual(comms, ["bash", "evil"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
