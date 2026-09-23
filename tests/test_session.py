"""Persistência e retomada de sessão."""

import shutil
import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente import store


class TestSession(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._sd, self._ap = store.SESSIONS_DIR, store.ACTIVE_POINTER
        store.SESSIONS_DIR = self.tmp
        store.ACTIVE_POINTER = self.tmp / ".active"

    def tearDown(self):
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self._sd, self._ap
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_create_and_active(self):
        s = store.Session.create(environment="producao")
        self.assertEqual(store.Session.active().id, s.id)
        self.assertEqual(s.meta()["environment"], "producao")

    def test_tasks_findings_persist(self):
        s = store.Session.create()
        t = s.add_task({"agent": "web", "objective": "headers",
                        "target": "x", "status": "pending"})
        self.assertTrue(t["id"])
        s.update_task(t["id"], status="done")
        self.assertEqual(s.tasks()[0]["status"], "done")
        s.add_finding({"title": "f", "status": "suspeita"})
        self.assertEqual(len(s.findings()), 1)

    def test_resume(self):
        s = store.Session.create()
        sid = s.id
        # "reabre" pelo id
        again = store.Session(sid)
        again.set_active()
        self.assertEqual(store.Session.active().id, sid)

    def test_confirmado_sem_evidencia_vira_suspeita(self):
        s = store.Session.create()
        stored = s.add_finding({"title": "x", "target": "a.com",
                                "status": "confirmado", "evidence_ids": []})
        self.assertEqual(stored["status"], "suspeita")
        self.assertIn("rejeitada", stored.get("nota_validacao", ""))

    def test_manifesto_na_criacao(self):
        s = store.Session.create()
        m = s.meta()
        self.assertIn("version", m)
        self.assertIn("install_mode", m)
        self.assertEqual(m.get("hash_convention"), "sha256-bytes")

    def test_set_status_descartado_persiste_decisao(self):
        s = store.Session.create()
        f = s.add_finding({"title": "x", "target": "a.com", "status": "suspeita"})
        ok, _ = s.update_finding(f["id"], "descartado", "validador",
                                 "falso-positivo", ["reflexo encoded"])
        self.assertTrue(ok)
        got = s.findings()[0]
        self.assertEqual(got["status"], "descartado")
        self.assertEqual(got["validation"]["validated_by"], "validador")

    def test_set_status_confirmado_sem_evidencia_recusa(self):
        s = store.Session.create()
        f = s.add_finding({"title": "x", "target": "a.com", "status": "suspeita",
                           "evidence_ids": []})
        ok, msg = s.update_finding(f["id"], "confirmado", "validador", "achei")
        self.assertFalse(ok)
        self.assertEqual(s.findings()[0]["status"], "suspeita")

    def test_close_gera_cobertura(self):
        s = store.Session.create()
        s.add_finding({"title": "x", "target": "a.com", "status": "suspeita"})
        m = s.close()
        self.assertEqual(m["status"], "concluida")
        self.assertIn("cobertura", m)
        self.assertEqual(m["cobertura"]["nao_revisados"], 1)

    def test_limits_roundtrip(self):
        s = store.Session.create()
        s.save_limits({"h": {"count": 3}})
        self.assertEqual(s.limits()["h"]["count"], 3)


if __name__ == "__main__":
    unittest.main()
