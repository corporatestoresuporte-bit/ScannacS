"""Análise de código local (SAST-leve) — detecção em fixture sintética."""

import shutil
import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente import codereview


class TestCodeReview(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "src").mkdir()
        (self.tmp / "dist").mkdir()
        (self.tmp / "supabase" / "migrations").mkdir(parents=True)
        # service_role no frontend (crítico) + segredo
        (self.tmp / "src" / "config.ts").write_text(
            'export const KEY = "service_role";\n'
            'const api_key = "abcd1234efgh5678";\n', encoding="utf-8")
        # sink de XSS no bundle
        (self.tmp / "dist" / "app.js").write_text(
            'el.dangerouslySetInnerHTML = user;\n', encoding="utf-8")
        # migration sem RLS + política frouxa
        (self.tmp / "supabase" / "migrations" / "001.sql").write_text(
            "create table public.orders (id int);\n"
            "create policy p on public.orders using (true);\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_detecta_service_role_frontend(self):
        titles = [f.title for f in codereview.review(self.tmp)]
        self.assertTrue(any("admin do Supabase no lado do cliente" in t for t in titles))

    def test_detecta_xss_sink(self):
        titles = [f.title for f in codereview.review(self.tmp)]
        self.assertTrue(any("XSS" in t for t in titles))

    def test_detecta_rls_ausente_e_permissiva(self):
        titles = [f.title for f in codereview.review(self.tmp)]
        self.assertTrue(any("sem RLS" in t for t in titles))
        self.assertTrue(any("using (true)" in t for t in titles))

    def test_detecta_segredo(self):
        titles = [f.title for f in codereview.review(self.tmp)]
        self.assertTrue(any("segredo" in t.lower() for t in titles))

    def test_pasta_limpa_sem_achados(self):
        clean = Path(tempfile.mkdtemp())
        (clean / "src").mkdir()
        (clean / "src" / "ok.ts").write_text("export const x = 1;\n", encoding="utf-8")
        try:
            self.assertEqual(codereview.review(clean), [])
        finally:
            shutil.rmtree(clean, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
