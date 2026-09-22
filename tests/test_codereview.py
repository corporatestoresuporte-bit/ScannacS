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

    def test_detecta_abuso_de_logica_api(self):
        api = self.tmp / "src" / "api"
        api.mkdir(parents=True)
        (api / "orders.ts").write_text(
            "app.post('/orders', async (req, res) => {\n"
            "  const order = await db.insert({ ...req.body });\n"
            "  const role = req.body.role;\n"
            "  const price = req.body.price;\n"
            "  const rows = await db.select('*');\n"
            "  return res.json({ password: user.password });\n"
            "});\n", encoding="utf-8")
        titles = [f.title for f in codereview.review(self.tmp)]
        joined = " | ".join(titles)
        self.assertIn("mass assignment", joined)
        self.assertIn("papel/permissão vindo do corpo", joined)
        self.assertIn("preço/total confiando no cliente", joined)
        self.assertIn("dado sensível retornado", joined)
        self.assertIn("select *", joined)
        self.assertIn("Endpoint sem autenticação aparente", joined)
        self.assertIn("Sem rate-limit aparente", joined)

    def test_rota_com_auth_nao_flaga(self):
        api = self.tmp / "src" / "api2"
        api.mkdir(parents=True)
        (api / "safe.ts").write_text(
            "app.get('/me', requireAuth, async (req, res) => {\n"
            "  const u = await db.from('users').select('id,name')"
            ".eq('id', req.user.id);\n"
            "  return res.json(u);\n"
            "});\n", encoding="utf-8")
        titles = [f.title for f in codereview.review(self.tmp)
                  if "safe.ts" in (f.evidence_ids[0] if f.evidence_ids else "")]
        self.assertNotIn("Endpoint sem autenticação aparente", " | ".join(titles))

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
