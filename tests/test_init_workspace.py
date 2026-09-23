"""init-workspace: materializa o workspace do Claude e preserva edições."""

import shutil
import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente.cli import main


class TestInitWorkspace(unittest.TestCase):
    def test_materializa_e_preserva(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            rc = main(["init-workspace", str(tmp)])
            self.assertEqual(rc, 0)
            self.assertTrue((tmp / "CLAUDE.md").exists())
            self.assertTrue((tmp / ".claude" / "settings.json").exists())
            self.assertTrue(
                (tmp / ".claude" / "agents" / "validador-achados.md").exists())
            self.assertTrue(any((tmp / ".claude" / "skills").iterdir()))
            # NÃO deve trazer segredo/escopo/sessão
            self.assertFalse((tmp / ".env").exists())
            self.assertFalse((tmp / "config" / "scope.toml").exists())
            # idempotente: edição do usuário é preservada
            (tmp / "CLAUDE.md").write_text("MEU EDIT", encoding="utf-8")
            main(["init-workspace", str(tmp)])
            self.assertEqual((tmp / "CLAUDE.md").read_text(encoding="utf-8"),
                             "MEU EDIT")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
