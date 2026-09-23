"""authbf — teste de resistência do login. Loopback, sem rede externa.
Cobre: sem-proteção -> achado; lockout -> para (proteção); credencial fraca ->
achado; guardrails (posse, efeito colateral, tetos)."""

import json
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import _pathshim  # noqa: F401

from agente import authbf, store
from agente.scope import Scope, Target


def _server(mode: str):
    state = {"n": 0}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            state["n"] += 1
            if mode == "lockout" and state["n"] > 3:
                return self._send(429, '{"error":"too many attempts"}')
            if mode == "weak" and '"admin"' in body and 'admin' in body.split('"pass"')[-1]:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "session=abc; HttpOnly")
                self.end_headers()
                self.wfile.write(b'{"ok":true,"token":"x"}')
                return
            self._send(401, '{"error":"invalid credentials"}')

        def _send(self, code, body):
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestAuthbf(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._sd, self._ap = store.SESSIONS_DIR, store.ACTIVE_POINTER
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self.tmp, self.tmp / ".active"
        self._sleep = authbf.time.sleep
        authbf.time.sleep = lambda *_a: None      # acelera os testes
        self.srvs = []

    def tearDown(self):
        authbf.time.sleep = self._sleep
        for s in self.srvs:
            s.shutdown(); s.server_close()
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self._sd, self._ap
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _scope(self, port):
        return Scope(authorized=True, targets=[Target(
            name="lab", type="url", value=f"http://127.0.0.1:{port}",
            allowed_tests=["all"], owner_verified=True,
            owner_verified_at="loopback")])

    def _cfg(self, port):
        return authbf.AuthConfig(
            url=f"http://127.0.0.1:{port}/login",
            body_template='{"user":"{user}","pass":"{pass}"}',
            content_type="json")

    def _creds(self):
        return [("admin", "admin"), ("u1", "x1"), ("u2", "x2"),
                ("u3", "x3"), ("u4", "x4"), ("u5", "x5")]

    def test_sem_protecao_vira_achado(self):
        srv = _server("open"); self.srvs.append(srv)
        port = srv.server_address[1]
        sess = store.Session.create(environment="authbf")
        fs = authbf.run_authbf(sess, self._scope(port), self._cfg(port),
                               self._creds(), allow_side_effects=True)
        titles = " ".join(f.title for f in fs)
        self.assertIn("sem proteção", titles.lower())
        self.assertTrue(any(f.severity.value == "media" for f in fs))

    def test_lockout_para_e_nao_alarma(self):
        srv = _server("lockout"); self.srvs.append(srv)
        port = srv.server_address[1]
        sess = store.Session.create(environment="authbf")
        fs = authbf.run_authbf(sess, self._scope(port), self._cfg(port),
                               self._creds(), allow_side_effects=True)
        # não deve haver achado de "sem proteção"; deve registrar proteção presente
        self.assertFalse(any("sem proteção" in f.title.lower() for f in fs))
        self.assertTrue(any(f.status.value == "descartado" for f in fs))

    def test_credencial_fraca_vira_achado_alto(self):
        srv = _server("weak"); self.srvs.append(srv)
        port = srv.server_address[1]
        sess = store.Session.create(environment="authbf")
        fs = authbf.run_authbf(sess, self._scope(port), self._cfg(port),
                               self._creds(), allow_side_effects=True)
        self.assertTrue(any("aceita" in f.title.lower()
                            and f.severity.value == "alta" for f in fs))

    def test_guardrail_efeito_colateral(self):
        srv = _server("open"); self.srvs.append(srv)
        port = srv.server_address[1]
        sess = store.Session.create(environment="authbf")
        with self.assertRaises(PermissionError):
            authbf.run_authbf(sess, self._scope(port), self._cfg(port),
                              self._creds(), allow_side_effects=False)

    def test_guardrail_sem_posse(self):
        srv = _server("open"); self.srvs.append(srv)
        port = srv.server_address[1]
        sc = self._scope(port)
        sc.targets[0].owner_verified = False
        sess = store.Session.create(environment="authbf")
        with self.assertRaises(PermissionError):
            authbf.run_authbf(sess, sc, self._cfg(port), self._creds(),
                              allow_side_effects=True)

    def test_artefato_nao_vaza_senha(self):
        srv = _server("open"); self.srvs.append(srv)
        port = srv.server_address[1]
        sess = store.Session.create(environment="authbf")
        authbf.run_authbf(sess, self._scope(port), self._cfg(port),
                          [("segredo_user", "senha_supersecreta_123")],
                          allow_side_effects=True)
        art = Path(sess.artifacts).rglob("*.txt")
        blob = " ".join(p.read_text(encoding="utf-8") for p in art)
        self.assertNotIn("senha_supersecreta_123", blob)


if __name__ == "__main__":
    unittest.main()
