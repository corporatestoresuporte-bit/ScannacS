"""Hook PreToolUse (executor imposto na sessão)."""

import unittest

import _pathshim  # noqa: F401

from agente import hook
from agente import scope as scope_mod
from agente.scope import Scope, Target


class TestHook(unittest.TestCase):
    def setUp(self):
        self._orig = scope_mod.load_scope
        self.scope = Scope(authorized=True, targets=[
            Target(name="s", type="domain", value="meusite.com",
                   allowed_tests=["headers"])])
        scope_mod.load_scope = lambda *a, **k: self.scope

    def tearDown(self):
        scope_mod.load_scope = self._orig

    def test_local_bash_allowed(self):
        self.assertEqual(hook.handle({"tool_name": "Bash",
                                      "tool_input": {"command": "ls -la"}}), 0)

    def test_out_of_scope_bash_denied(self):
        rc = hook.handle({"tool_name": "Bash",
                          "tool_input": {"command": "curl https://evil.example"}})
        self.assertEqual(rc, 2)

    def test_command_substitution_denied(self):
        rc = hook.handle({"tool_name": "Bash",
                          "tool_input": {"command": "curl https://$(cat h).com"}})
        self.assertEqual(rc, 2)

    def test_unauthorized_scope_denies_network(self):
        self.scope.authorized = False
        rc = hook.handle({"tool_name": "Bash",
                          "tool_input": {"command": "curl https://meusite.com"}})
        self.assertEqual(rc, 2)

    def test_webfetch_research_allowed(self):
        self.scope.authorized = False
        rc = hook.handle({"tool_name": "WebFetch",
                          "tool_input": {"url": "https://nvd.nist.gov/vuln/CVE-1"}})
        self.assertEqual(rc, 0)

    def test_webfetch_out_of_scope_denied(self):
        rc = hook.handle({"tool_name": "WebFetch",
                          "tool_input": {"url": "https://evil.example/x"}})
        self.assertEqual(rc, 2)

    def test_audit_trail_registra_decisao(self):
        """main() acrescenta a decisão à trilha de auditoria (prova de disparo)."""
        import io
        import json
        import tempfile
        from pathlib import Path

        from agente import config

        with tempfile.TemporaryDirectory() as td:
            orig_logs = config.LOGS_DIR
            orig_stdin = hook.sys.stdin
            config.LOGS_DIR = Path(td)
            try:
                hook.sys.stdin = io.StringIO(json.dumps(
                    {"tool_name": "Bash",
                     "tool_input": {"command": "curl https://evil.example"}}))
                rc = hook.main()
            finally:
                config.LOGS_DIR = orig_logs
                hook.sys.stdin = orig_stdin
            self.assertEqual(rc, 2)
            linhas = (Path(td) / "hook-audit.log").read_text(
                encoding="utf-8").strip().splitlines()
            self.assertEqual(len(linhas), 1)
            reg = json.loads(linhas[0])
            self.assertEqual(reg["tool"], "Bash")
            self.assertEqual(reg["decisao"], "bloqueado")
            self.assertEqual(reg["rc"], 2)


if __name__ == "__main__":
    unittest.main()
