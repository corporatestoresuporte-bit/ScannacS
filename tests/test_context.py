"""Prompts master: frontmatter, importação, manifesto e contexto."""

import shutil
import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente import config, context


class TestContext(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = config.MASTERS_DIR
        config.MASTERS_DIR = self.tmp

    def tearDown(self):
        config.MASTERS_DIR = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_parse_frontmatter(self):
        meta, body = context.parse_frontmatter(
            "---\ntitle: X\norder: 5\nagents: a, b\n---\ncorpo aqui")
        self.assertEqual(meta["title"], "X")
        self.assertEqual(meta["order"], "5")
        self.assertEqual(meta["agents"], ["a", "b"])
        self.assertEqual(body.strip(), "corpo aqui")

    def test_no_frontmatter(self):
        meta, body = context.parse_frontmatter("só corpo")
        self.assertEqual(meta, {})
        self.assertEqual(body, "só corpo")

    def test_import_and_list(self):
        context.import_master("Objetivo: auditar web.", "web-metodo",
                              title="Método Web", order=10, purpose="prio",
                              agents="coordenador")
        masters = context.list_masters()
        self.assertEqual(len(masters), 1)
        self.assertEqual(masters[0].title, "Método Web")
        self.assertIn("auditar web", masters[0].body)

    def test_manifest_changes(self):
        context.import_master("A", "a", order=10)
        h1 = context.manifest_hash()
        context.import_master("B", "b", order=20)
        h2 = context.manifest_hash()
        self.assertNotEqual(h1, h2)

    def test_context_has_essential_rules(self):
        context.import_master("corpo", "p", order=10)
        c = context.assemble_context()
        self.assertIn("REGRAS ESSENCIAIS", c)
        self.assertIn("ESCOPO", c)
        self.assertIn("EVIDÊNCIA", c)

    def test_context_filters_by_agent(self):
        context.import_master("para web", "w", order=10, agents="investigador-web")
        context.import_master("para api", "a", order=20, agents="investigador-api")
        c = context.assemble_context(only_for_agent="investigador-web")
        self.assertIn("para web", c)
        self.assertNotIn("para api", c)


if __name__ == "__main__":
    unittest.main()
