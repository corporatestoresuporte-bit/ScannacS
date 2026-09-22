"""Motores de scan: detecção, seleção e caminhos sem rede."""

import shutil
import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente import audit as audit_mod
from agente import engines, store
from agente.evidence import CollectionStatus
from agente.scope import Scope, Target


class TestEngines(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._sd, self._ap = store.SESSIONS_DIR, store.ACTIVE_POINTER
        store.SESSIONS_DIR = self.tmp
        store.ACTIVE_POINTER = self.tmp / ".active"

    def tearDown(self):
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self._sd, self._ap
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_detect_tools_shape(self):
        d = engines.detect_tools()
        self.assertIn("nmap", d)
        self.assertIsInstance(d["nmap"], bool)

    def test_engines_for(self):
        self.assertTrue(any(e.name == "cabecalhos-seguranca"
                            for e in engines.engines_for("headers")))
        self.assertTrue(any(e.requires == "nmap"
                            for e in engines.engines_for("portas")))

    def test_headers_interpret_flags_missing(self):
        eng = engines.HeadersEngine()
        raw = "content-type: text/html\nserver: nginx"  # sem HSTS/CSP/XFO/XCTO
        t = Target(name="s", type="domain", value="x.com", allowed_tests=["headers"])
        susp = eng.interpret(t, raw, CollectionStatus.OK)
        titles = " ".join(f.title for f in susp)
        self.assertIn("Strict-Transport-Security", titles)
        self.assertIn("Content-Security-Policy", titles)

    def test_missing_tool_is_limitation_not_network(self):
        # motor externo com ferramenta inexistente => NO_ACCESS, sem tocar rede
        sess = store.Session.create()
        scope = Scope(authorized=True, targets=[Target(
            name="s", type="domain", value="meusite.com", allowed_tests=["nmap"])])
        eng = engines.ExternalToolEngine("faketool", ("faketool",),
                                         "ferramenta-inexistente-xyz", "faketool {host}")
        res = engines.run_engine(sess, scope, scope.targets[0], eng)
        self.assertEqual(res.evidence.status, CollectionStatus.NO_ACCESS)
        self.assertEqual(res.suspicions, [])

    def test_run_with_empty_engines_no_network(self):
        scope = Scope(authorized=True, targets=[Target(
            name="s", type="domain", value="meusite.com", allowed_tests=["headers"])])
        result = audit_mod.run(scope=scope, confirmed=True, engines=[])
        # engines=[] => nenhum motor roda; tarefa marcada como blocked
        self.assertFalse(result.executed)


if __name__ == "__main__":
    unittest.main()
