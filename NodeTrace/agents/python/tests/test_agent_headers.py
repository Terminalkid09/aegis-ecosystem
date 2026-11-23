# SPDX-License-Identifier: AGPL-3.0-only
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent import Agent


class TestAgentHeaders(unittest.TestCase):
    def test_sends_only_the_fingerprint(self):
        agent = object.__new__(Agent)
        agent._identity_hash = "a" * 64
        agent._identity_b64 = "legacy-full-cert-must-not-leak"
        headers = agent._agent_headers("device-token", "agent-1")
        self.assertEqual(headers["X-Client-Cert-Hash"], "a" * 64)
        self.assertNotIn("X-Client-Cert", headers)

    def test_no_identity_sends_no_cert_header(self):
        agent = object.__new__(Agent)
        agent._identity_hash = None
        agent._identity_b64 = None
        headers = agent._agent_headers("device-token", "agent-1")
        self.assertNotIn("X-Client-Cert", headers)
        self.assertNotIn("X-Client-Cert-Hash", headers)


if __name__ == "__main__":
    unittest.main()
