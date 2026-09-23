"""SSRF ativo: canário pega servidor que busca URL externa; app seguro não flaga.
Loopback (o 'alvo' e o canário rodam em 127.0.0.1). Sem rede externa."""

import shutil
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import _pathshim  # noqa: F401

from agente import ssrf, store
from agente.replay import Req
from agente.scope import Scope, Target


def _fetcher(vulneravel: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlparse(self.path)
            url = (parse_qs(u.query).get("url") or [""])[0]
            if not vulneravel:
                # seguro: só busca mesmo-origem; recusa externo
                self._send(400, "destino não permitido")
                return
            try:                       # VULNERÁVEL: busca o que mandarem
                with urllib.request.urlopen(url, timeout=5) as r:
                    body = r.read(2000)
                self._send(200, "fetched:" + body.decode("utf-8", "replace"))
            except Exception as e:  # noqa: BLE001
                self._send(502, f"erro: {e}")

        def _send(self, code, text):
            b = text.encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


class TestSSRF(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._sd, self._ap = store.SESSIONS_DIR, store.ACTIVE_POINTER
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self.tmp, self.tmp / ".active"
        self.srvs = []

    def tearDown(self):
        for s in self.srvs:
            s.shutdown(); s.server_close()
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self._sd, self._ap
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _serve(self, vuln):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _fetcher(vuln))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.srvs.append(srv)
        return srv.server_address[1]

    def _scope(self, port):
        return Scope(authorized=True, targets=[Target(
            name="l", type="url", value=f"http://127.0.0.1:{port}",
            allowed_tests=["all"], owner_verified=True, owner_verified_at="loopback")])

    def _req(self, port):
        return Req(method="GET",
                   url=f"http://127.0.0.1:{port}/fetch?url=http://exemplo.invalido/",
                   headers={})

    def test_find_url_params(self):
        ps = ssrf.find_url_params("http://x/f?url=http://y&id=1&next=/a")
        self.assertIn("url", ps)
        self.assertIn("next", ps)
        self.assertNotIn("id", ps)
        pb = ssrf.find_url_params("http://x/f", '{"link":"http://z","n":1}')
        self.assertIn("link", pb)

    def test_ssrf_vulneravel_confirma(self):
        port = self._serve(True)
        sess = store.Session.create(environment="ssrf")
        fs = ssrf.run_ssrf(sess, self._scope(port), self._req(port), param="url")
        self.assertTrue(fs, "deveria achar SSRF (canário buscado)")
        self.assertTrue(any(f.severity.value == "critica" for f in fs))
        self.assertIn("SSRF", " ".join(f.title for f in fs))

    def test_app_seguro_nao_flaga(self):
        port = self._serve(False)
        sess = store.Session.create(environment="ssrf")
        fs = ssrf.run_ssrf(sess, self._scope(port), self._req(port), param="url")
        self.assertEqual(fs, [])

    def test_guardrail_sem_posse(self):
        port = self._serve(True)
        sc = self._scope(port); sc.targets[0].owner_verified = False
        sess = store.Session.create(environment="ssrf")
        with self.assertRaises(PermissionError):
            ssrf.run_ssrf(sess, sc, self._req(port), param="url")

    def test_sem_param_erro(self):
        port = self._serve(True)
        sess = store.Session.create(environment="ssrf")
        req = Req(method="GET", url=f"http://127.0.0.1:{port}/x", headers={})
        with self.assertRaises(ValueError):
            ssrf.run_ssrf(sess, self._scope(port), req)


if __name__ == "__main__":
    unittest.main()
