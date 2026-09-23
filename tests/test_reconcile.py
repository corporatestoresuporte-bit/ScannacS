"""Reconciliação por ID: números e estabilidade após fechar/reabrir."""

import shutil
import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente import reconcile, store


class TestReconcile(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._sd, self._ap = store.SESSIONS_DIR, store.ACTIVE_POINTER
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self.tmp, self.tmp / ".active"

    def tearDown(self):
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self._sd, self._ap
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_numeros(self):
        fs = [
            {"title": "a", "target": "x", "status": "suspeita", "engine": "e1"},
            {"title": "a", "target": "x", "status": "suspeita", "engine": "e1"},  # dup
            {"title": "b", "target": "x", "status": "descartado", "engine": "e2",
             "validation": {"validated_by": "v"}},
        ]
        r = reconcile.reconcile(fs)
        self.assertEqual(r["bruto"], 3)
        self.assertEqual(r["unicos"], 2)
        self.assertEqual(r["duplicados"], 1)
        self.assertEqual(r["revisados"], 1)
        self.assertEqual(r["nao_revisados"], 2)
        self.assertEqual(r["por_estado"]["suspeita"], 2)

    def test_estavel_apos_fechar_reabrir(self):
        s = store.Session.create()
        s.add_finding({"title": "a", "target": "x", "status": "suspeita"})
        s.add_finding({"title": "b", "target": "x", "status": "suspeita"})
        r1 = reconcile.reconcile(s.findings())
        s.close()
        reopened = store.Session(s.id)          # reabre do disco
        r2 = reconcile.reconcile(reopened.findings())
        self.assertEqual(r1, r2)                 # mesmos números


if __name__ == "__main__":
    unittest.main()
