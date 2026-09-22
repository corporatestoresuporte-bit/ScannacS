"""Smoke tests da CLI: version e o gate refletido em audit run."""

import io
import unittest
from contextlib import redirect_stdout

import _pathshim  # noqa: F401

from agente.cli import main


class TestCli(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_version(self):
        code, out = self._run(["version"])
        self.assertEqual(code, 0)
        self.assertIn("agente-vulnerabilidades", out)

    def test_audit_run_sem_confirm_bloqueia(self):
        # Sem --confirm e (provavelmente) sem escopo real => bloqueado.
        code, out = self._run(["audit", "run"])
        self.assertEqual(code, 2)
        self.assertIn("BLOQUEADA", out)

    def test_sem_comando_mostra_ajuda(self):
        code, _ = self._run([])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
