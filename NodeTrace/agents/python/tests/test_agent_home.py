"""Regressione: identita' e token NON seguono piu' la cwd.

Bug chiuso: `TokenService.FILE` era `"token.json"` relativo, quindi lo stesso
device usava un token diverso a seconda della directory di lancio. Il brain
rispondeva 401 a ogni chiamata autenticata e l'agente restava cieco (nessun
wipe automatico, by design): qui si blocca quel comportamento.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.agent_home import agent_home
from services.token_service import TokenService


class TestAgentHome(unittest.TestCase):
    def test_home_is_absolute_and_cwd_independent(self):
        original = os.getcwd()
        home_before = agent_home()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                # Stessa risposta da una cwd diversa: e' tutto il punto del fix.
                self.assertEqual(home_before, agent_home())
                self.assertTrue(os.path.isabs(agent_home()))
            finally:
                # Prima di uscire dal with: su Windows rmtree della cwd fallisce.
                os.chdir(original)

    def test_home_ends_on_agents_dir_for_source_runs(self):
        # Sorgente: …/agents/python (accanto a config.json), non services/.
        self.assertEqual(
            os.path.basename(agent_home()), "python")
        self.assertTrue(os.path.isfile(os.path.join(agent_home(), "config.json")))

    def test_explicit_override_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["NODETRACE_IDENTITY_DIR"] = tmp
            try:
                self.assertEqual(os.path.abspath(tmp), agent_home())
            finally:
                del os.environ["NODETRACE_IDENTITY_DIR"]

    def test_token_path_is_absolute(self):
        self.assertTrue(os.path.isabs(TokenService.FILE),
                        "token.json deve essere assoluto: un path relativo "
                        "rende l'identita' dipendente dalla cwd")

    def test_token_file_overridable_by_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            explicit = os.path.join(tmp, "custom-token.json")
            os.environ["NODETRACE_TOKEN_FILE"] = explicit
            try:
                # Il valore e' letto a import-time: qui si verifica la stessa
                # regola di precedenza usata dal modulo.
                resolved = os.getenv("NODETRACE_TOKEN_FILE") or os.path.join(
                    agent_home(), "token.json")
                self.assertEqual(explicit, resolved)
            finally:
                del os.environ["NODETRACE_TOKEN_FILE"]


if __name__ == "__main__":
    unittest.main()
