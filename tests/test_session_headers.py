"""Sessão autenticada aplicada a TODO fetch dos motores (passa WAF/login)."""

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import _pathshim  # noqa: F401

from agente import engines
from agente import webui


def _server():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            ck = self.headers.get("Cookie") or ""
            code = 200 if "sid=ok" in ck else 403
            b = b"<html>app</html>" if code == 200 else b"challenge"
            self.send_response(code)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestSessionHeaders(unittest.TestCase):
    def setUp(self):
        self.srv = _server()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/"

    def tearDown(self):
        engines.set_session_headers({})
        self.srv.shutdown(); self.srv.server_close()

    def test_fetch_usa_cookie_de_sessao(self):
        engines.set_session_headers({})
        s0, _h, _b, _e = engines._fetch(self.url)
        self.assertEqual(s0, 403)                    # sem cookie: WAF/login barra
        engines.set_session_headers({"Cookie": "sid=ok"})
        s1, _h, _b, _e = engines._fetch(self.url)
        self.assertEqual(s1, 200)                    # com cookie: alcança a app

    def test_apply_session_headers_do_curl(self):
        curl = f"curl '{self.url}' -H 'cookie: sid=ok'"
        webui._apply_session_headers({"authcapture": {"curl": curl}})
        s, _h, _b, _e = engines._fetch(self.url)
        self.assertEqual(s, 200)
        webui._apply_session_headers({})             # sem cURL -> limpa
        s2, _h, _b, _e = engines._fetch(self.url)
        self.assertEqual(s2, 403)


if __name__ == "__main__":
    unittest.main()
