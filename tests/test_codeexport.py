"""Exportação de trechos de código: redação + hash + versão."""

import shutil
import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente import codeexport, store
from agente.findings import Finding


class TestCodeExport(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._sd, self._ap = store.SESSIONS_DIR, store.ACTIVE_POINTER
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self.tmp, self.tmp / ".active"

    def tearDown(self):
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self._sd, self._ap
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_export_redige_e_hash(self):
        src = self.tmp / "app.ts"
        src.write_text('const api_key = "abcd1234efgh5678";\nconst x = 1;\n',
                       encoding="utf-8")
        sess = store.Session.create()
        f = Finding(target="t", title="segredo", evidence_ids=[f"{src}:1"])
        n = codeexport.export_snippets(sess, [f], version="abc123")
        self.assertEqual(n, 1)
        self.assertEqual(len(f.evidence_ids), 2)          # ref + snapshot
        art = Path(f.evidence_ids[1])
        self.assertTrue(art.exists())
        txt = art.read_text(encoding="utf-8")
        self.assertIn("sha256(arquivo):", txt)
        self.assertIn("abc123", txt)                       # versão registrada
        self.assertNotIn("abcd1234efgh5678", txt)          # segredo redigido
        self.assertIn("REDACTED", txt)

    def test_arquivo_inexistente_nao_exporta(self):
        sess = store.Session.create()
        f = Finding(target="t", title="x", evidence_ids=["nao/existe.ts:3"])
        self.assertEqual(codeexport.export_snippets(sess, [f]), 0)

    def test_export_redige_service_role_e_stripe(self):
        # regressão: o snippet dizia "segredos redigidos" mas vazava sk_live e JWT.
        # literais fictícios montados em runtime (concat) p/ não gravar no fonte
        # texto que o secret-scanning confunde com chave real.
        jwt = ("eyJhbGciOiJIUzI1NiJ9" + "." + "eyJyb2xlIjoic2VydmljZV9yb2xlIn0"
               + "." + "AAAA")
        sk = "sk_" + "live_" + "51H8x9aBcDeFgHiJkLmNoPqRs"
        src = self.tmp / "supabaseClient.js"
        src.write_text(
            "const SUPABASE_SERVICE_ROLE_KEY = '" + jwt + "'\n"
            'const apiSecret = "' + sk + '"\n',
            encoding="utf-8")
        sess = store.Session.create()
        f = Finding(target="t", title="segredo", evidence_ids=[f"{src}:1"])
        codeexport.export_snippets(sess, [f])
        txt = Path(f.evidence_ids[1]).read_text(encoding="utf-8")
        self.assertNotIn(sk, txt)
        self.assertNotIn(jwt, txt)
        self.assertIn("REDACTED", txt)


if __name__ == "__main__":
    unittest.main()
