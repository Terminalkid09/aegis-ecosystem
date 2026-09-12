import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.ebpf import parse_line, event_to_report, collector_cmd, KernelEventBatcher, SeenCache

GOLDEN = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "..",
    "aegis-ebpf", "tests", "golden.jsonl",
)


class TestEbpfForward(unittest.TestCase):
    def test_parse_valid(self):
        ev = parse_line('{"pid":10,"ppid":1,"comm":"sh","filename":"/bin/sh","event_type":"PROCESS_CREATED"}')
        self.assertIsNotNone(ev)
        self.assertEqual(ev["pid"], 10)

    def test_parse_rejects(self):
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("not json"))
        self.assertIsNone(parse_line('{"foo":1}'))
        self.assertIsNone(parse_line('{"pid":0,"event_type":"PROCESS_CREATED"}'))
        self.assertIsNone(parse_line('{"pid":1,"event_type":"NOPE"}'))

    def test_mapping(self):
        rep = event_to_report(
            {"pid": 101, "ppid": 100, "comm": "echo", "filename": "/bin/echo",
             "event_type": "PROCESS_CREATED"},
            device_id="dev-1", hostname="h", ip_local="10.0.0.2",
            agent_version="1.0.0",
        )
        self.assertEqual(rep["agent_id"], "dev-1")
        self.assertEqual(rep["pid"], 101)
        self.assertEqual(rep["parent_pid"], 100)
        self.assertEqual(rep["process_name"], "echo")
        self.assertEqual(rep["process_path"], "/bin/echo")
        self.assertEqual(rep["event_type"], "PROCESS_CREATED")
        self.assertEqual(rep["agent_version"], "1.0.0")
        self.assertIn("timestamp", rep)

    def test_mapping_exit_no_parent(self):
        rep = event_to_report(
            {"pid": 5, "event_type": "PROCESS_EXITED"}, device_id="d")
        self.assertIsNone(rep["parent_pid"])
        self.assertEqual(rep["process_name"], "unknown")

    def test_mapping_connection(self):
        rep = event_to_report(
            {"pid": 9, "comm": "curl", "remote": "93.184.216.34:443",
             "event_type": "CONNECTION_ESTABLISHED"}, device_id="d")
        self.assertEqual(rep["event_type"], "CONNECTION_ESTABLISHED")
        self.assertEqual(rep["network_connections"],
                         [{"remote": "93.184.216.34:443", "state": "ESTABLISHED"}])
        self.assertEqual(rep["process_name"], "curl")

    def test_parse_connection(self):
        ev = parse_line('{"pid":9,"remote":"10.1.2.3:80","event_type":"CONNECTION_ESTABLISHED"}')
        self.assertIsNotNone(ev)

    def test_collector_cmd_excludes_self(self):
        cmd = collector_cmd("/opt/aegis/aegis-collector", "/opt/aegis/a.obj")
        self.assertIn("--exclude-pid", cmd)
        self.assertIn(str(os.getpid()), cmd)

    def test_batcher_size_flush(self):
        b = KernelEventBatcher(max_n=3, max_age_s=60.0)
        self.assertFalse(b.add({"a": 1}, now_s=0.0))
        self.assertFalse(b.add({"a": 2}, now_s=0.0))
        self.assertTrue(b.add({"a": 3}, now_s=0.0))
        self.assertEqual(len(b.drain()), 3)
        self.assertEqual(len(b), 0)

    def test_batcher_time_flush(self):
        b = KernelEventBatcher(max_n=100, max_age_s=2.0)
        self.assertFalse(b.add({"a": 1}, now_s=10.0))
        self.assertTrue(b.due(now_s=12.5))
        self.assertEqual(len(b.drain()), 1)

    def test_seen_cache_dedups_overlap(self):
        s = SeenCache(window_s=5.0)
        ev = {"pid": 9, "ppid": 1, "comm": "sh", "event_type": "PROCESS_CREATED"}
        self.assertFalse(s.check(ev, now_s=100.0))
        self.assertTrue(s.check(dict(ev), now_s=101.0), "stesso exec entro finestra")
        self.assertFalse(s.check(dict(ev), now_s=106.0), "finestra scaduta")
        other = dict(ev, pid=10)
        self.assertFalse(s.check(other, now_s=101.0))
        self.assertEqual(s.duplicates, 1)

    def test_seen_cache_tolerates_garbage(self):
        s = SeenCache()
        self.assertFalse(s.check({}, now_s=0.0))
        self.assertFalse(s.check({"pid": "x"}, now_s=0.0))
        self.assertFalse(s.check(None, now_s=0.0))
        self.assertEqual(s.duplicates, 0)

    def test_golden_lines_all_forwardable(self):
        if not os.path.exists(GOLDEN):
            self.skipTest("golden.jsonl assente (generato dal test kernel)")
        with open(GOLDEN, encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        self.assertGreaterEqual(len(lines), 3)
        for ln in lines:
            ev = parse_line(ln)
            self.assertIsNotNone(ev, f"riga golden non parsabile: {ln[:80]}")
            rep = event_to_report(ev, device_id="d")
            self.assertIn(rep["event_type"], ("PROCESS_CREATED", "PROCESS_EXITED", "CONNECTION_ESTABLISHED"))

    def test_mapping_v2_identity(self):
        rep = event_to_report(
            {"schema_version": 2, "event_id": "evt-9", "boot_id": "b1", "seq": 3,
             "ts_ns": 111, "ts_wall_ns": 222, "proc_start_ns": 100,
             "pid": 9, "ppid": 1, "comm": "sh", "filename": "/bin/sh",
             "provenance": "ebpf-full", "quality": "full",
             "event_type": "PROCESS_CREATED"},
            device_id="d")
        self.assertEqual(rep["event_id"], "evt-9")
        self.assertEqual(rep["schema_version"], 2)
        self.assertEqual(rep["boot_id"], "b1")
        self.assertEqual(rep["seq"], 3)
        self.assertEqual(rep["ts_monotonic_ns"], 111)
        self.assertEqual(rep["ts_wall_ns"], 222)
        self.assertEqual(rep["proc_start_ns"], 100)
        self.assertEqual(rep["provenance"], "ebpf-full")

    def test_mapping_generates_event_id(self):
        rep = event_to_report(
            {"pid": 3, "comm": "x", "event_type": "PROCESS_CREATED"}, device_id="d")
        self.assertTrue(rep["event_id"], "idempotenza di default anche senza event_id")
        self.assertEqual(rep["schema_version"], 2)

    def test_batcher_bound_counts_drops(self):
        b = KernelEventBatcher(max_n=100000, max_age_s=3600.0, max_items=5)
        for i in range(8):
            b.add({"i": i}, now_s=0.0)
        self.assertEqual(len(b), 5)
        self.assertEqual(b.dropped, 3)
        self.assertEqual(b.received, 8)
        out = b.drain()
        self.assertEqual(b.drained, 5)
        self.assertEqual(out[0], {"i": 3}, "scarta i più vecchi")
        self.assertIn("dropped", b.stats())


if __name__ == "__main__":
    unittest.main()
