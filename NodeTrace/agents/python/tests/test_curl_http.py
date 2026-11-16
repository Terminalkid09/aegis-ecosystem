# SPDX-License-Identifier: AGPL-3.0-only
import os
import stat
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils import curl_http


class TestCurlSecrets(unittest.TestCase):
    def test_headers_and_body_are_not_in_argv(self):
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = list(cmd)
            seen["input"] = kwargs.get("input")
            config_path = cmd[cmd.index("--config") + 1]
            seen["config_path"] = config_path
            with open(config_path, encoding="utf-8") as fh:
                seen["config"] = fh.read()
            seen["mode"] = stat.S_IMODE(os.stat(config_path).st_mode)

            class Result:
                stdout = "ok200"

            return Result()

        old_path, old_use = curl_http._CURL_PATH, curl_http._USE_CURL
        curl_http._CURL_PATH = "curl"
        curl_http._USE_CURL = True
        try:
            with mock.patch.object(curl_http.subprocess, "run", side_effect=fake_run):
                response = curl_http._curl_request(
                    "POST",
                    "https://aegis.local/api/v1/telemetry",
                    json_data={"secret": "body-secret"},
                    headers={
                        "Authorization": "Bearer device-secret",
                        "X-Client-Cert": "cert-secret",
                    },
                )
        finally:
            curl_http._CURL_PATH = old_path
            curl_http._USE_CURL = old_use

        self.assertEqual(response.status_code, 200)
        argv = " ".join(seen["cmd"])
        self.assertNotIn("device-secret", argv)
        self.assertNotIn("cert-secret", argv)
        self.assertNotIn("body-secret", argv)
        self.assertNotIn("-H", seen["cmd"])
        self.assertIn("device-secret", seen["config"])
        self.assertIn("cert-secret", seen["config"])
        self.assertIn("Content-Type: application/json", seen["config"])
        self.assertEqual(seen["input"], '{"secret": "body-secret"}')
        self.assertIn("--data-binary", seen["cmd"])
        self.assertFalse(os.path.exists(seen["config_path"]))
        if os.name != "nt":
            self.assertEqual(seen["mode"] & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
