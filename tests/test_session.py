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

    def test_limits_roundtrip(self):
        s = store.Session.create()
        s.save_limits({"h": {"count": 3}})
        self.assertEqual(s.limits()["h"]["count"], 3)


if __name__ == "__main__":
    unittest.main()
