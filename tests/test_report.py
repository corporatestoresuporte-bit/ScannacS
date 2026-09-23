"""Relatório: achados INCONCLUSIVOS aparecem no corpo (não só na reconciliação)."""

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente import cli, store
from agente import scope as scope_mod
from agente.findings import Finding, Severity


class TestReport(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._sd, self._ap = store.SESSIONS_DIR, store.ACTIVE_POINTER
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self.tmp, self.tmp / ".active"
        self._ls = scope_mod.load_scope
        scope_mod.load_scope = lambda *a, **k: None

    def tearDown(self):
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self._sd, self._ap
        scope_mod.load_scope = self._ls
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_inconclusivos_no_corpo(self):
        sess = store.Session.create()
        f = Finding(target="lab", title="mass assignment", severity=Severity.HIGH,
                    evidence_ids=["a.js:8"])
        rec = sess.add_finding(f.to_dict())
        sess.update_finding(rec["id"], status="inconclusivo", validated_by="claude",
                            reason="precisa runtime para confirmar")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.print_report(sess)
        txt = out.getvalue()
        # o corpo mostra o bucket INCONCLUSIVOS com o título do achado
        self.assertIn("INCONCLUSIVOS", txt)
        self.assertIn("mass assignment", txt)
        # e não conta como não-revisado
        self.assertIn("NÃO REVISADOS (sem decisão registrada): 0", txt)


if __name__ == "__main__":
    unittest.main()
