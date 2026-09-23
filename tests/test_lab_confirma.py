"""Laboratório executável (loopback): o motor CONFIRMA falha com evidência,
RECONHECE a correção e RECUSA confirmação forjada. Sem rede externa."""

import json
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import _pathshim  # noqa: F401

from agente import store
from agente.replay import Req, run_replay
from agente.scope import Scope, Target

CONTAS = {"1": {"id": 1, "nome": "Alice Lima", "saldo": "R$ 2.500,00", "d": "*"},
          "2": {"id": 2, "nome": "Bob Souza", "saldo": "R$ 9.800,00", "d": "*"}}


def _handler(vulneravel: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlparse(self.path)
            if u.path != "/api/conta":
                self.send_response(404); self.end_headers(); return
            qid = (parse_qs(u.query).get("id") or ["1"])[0]
            sess = None
            for p in (self.headers.get("Cookie") or "").split(";"):
                if p.strip().startswith("session="):
                    sess = p.strip().split("=", 1)[1]
            if vulneravel:
                conta = CONTAS.get(qid)
                self._j(200, conta) if conta else (
                    self.send_response(404), self.end_headers())
            elif not sess:
                self._j(401, {"erro": "sem sessao"})
            elif sess != qid:
                self._j(403, {"erro": "negado"})
            else:
                self._j(200, CONTAS[qid])

        def _j(self, code, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
    return H


class TestLabConfirma(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._sd, self._ap = store.SESSIONS_DIR, store.ACTIVE_POINTER
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self.tmp, self.tmp / ".active"
        self.srvs = []

    def tearDown(self):
        for s in self.srvs:
            s.shutdown()
            s.server_close()
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self._sd, self._ap
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _serve(self, vulneravel):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler(vulneravel))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.srvs.append(srv)
        return srv.server_address[1]

    def _scope(self, port):
        return Scope(authorized=True, targets=[Target(
            name="lab", type="url", value=f"http://127.0.0.1:{port}",
            allowed_tests=["all"], owner_verified=True,
            owner_verified_at="2026-09-23T00:00:00+00:00")])

    def _req(self, port):
        return Req(method="GET", url=f"http://127.0.0.1:{port}/api/conta?id=1",
                   headers={"Cookie": "session=1"}, fuzz_param="id")

    def test_confirma_vuln_reconhece_correcao_recusa_forjado(self):
        vp, fp = self._serve(True), self._serve(False)
        sess = store.Session.create(environment="lab")

        # VULNERÁVEL: IDOR reproduz -> confirmável com evidência
        vf = run_replay(sess, self._scope(vp), self._req(vp),
                        tests=["idor", "no-auth"], fuzz_value="2")
        idor = next(f for f in vf if "IDOR" in f.title or "BOLA" in f.title)
        pid = next(x["id"] for x in sess.findings() if x["title"] == idor.title)
        ok, _ = sess.update_finding(
            pid, status="confirmado", validated_by="v",
            reason="sessao 1 leu conta 2 (200 com dados de outro)",
            alternatives=["dado publico? nao: endpoint por-usuario"],
            confirmation_type="comportamento_reproduzido")
        self.assertTrue(ok, "IDOR reproduzida devia confirmar com evidência")

        # CORRIGIDO: mesmo probe não reproduz
        ff = run_replay(sess, self._scope(fp), self._req(fp),
                        tests=["idor", "no-auth"], fuzz_value="2")
        self.assertEqual(len(ff), 0, "versão corrigida não pode reproduzir a falha")

        # PORTÃO recusa confirmação sem evidência ligada
        from agente.findings import Finding, Severity, Status
        forj = sess.add_finding(Finding(
            target="127.0.0.1:0", title="forjado", status=Status.SUSPECTED,
            severity=Severity.CRITICAL).to_dict())
        ok2, _ = sess.update_finding(
            forj["id"], status="confirmado", validated_by="v", reason="sem prova",
            alternatives=["n/a"], confirmation_type="comportamento_reproduzido")
        self.assertFalse(ok2, "confirmação sem evidência tem de ser recusada")
        # e o achado forjado NÃO fica como confirmado
        st = next(x["status"] for x in sess.findings() if x["id"] == forj["id"])
        self.assertNotEqual(st, "confirmado")


if __name__ == "__main__":
    unittest.main()
