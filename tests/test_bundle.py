"""Auditoria de segredo no bundle: acha service_role/sk_live servidos ao cliente.
Loopback, sem rede externa. Segredos montados em runtime (não ficam no fonte)."""

import base64
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import _pathshim  # noqa: F401

from agente import engines
from agente.evidence import CollectionStatus
from agente.scope import Target


def _service_role_jwt() -> str:
    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    pay = base64.urlsafe_b64encode(b'{"role":"service_role","iss":"supabase"}').decode().rstrip("=")
    return f"{hdr}.{pay}.{'A'*20}"


class TestBundleAudit(unittest.TestCase):
    def setUp(self):
        self.jwt = _service_role_jwt()
        self.sk = "sk_" + "live_" + "AbCdEf0123456789xyz"
        jwt, sk = self.jwt, self.sk

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/app.js":
                    body = (f'const KEY="{jwt}";const stripe="{sk}";'
                            'export const x=1;').encode()
                    ct = "application/javascript"
                else:
                    body = b'<html><body><script src="/app.js"></script></body></html>'
                    ct = "text/html"
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_jwt_service_role_detectado(self):
        self.assertTrue(engines._jwt_is_service_role(self.jwt))
        # anon key não deve disparar (sem backslash em f-string: compat 3.11)
        hdr = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
        anon_pay = base64.urlsafe_b64encode(b'{"role":"anon"}').decode().rstrip("=")
        anon = hdr + "." + anon_pay + ".AAAA"
        self.assertFalse(engines._jwt_is_service_role(anon))

    def test_scan_acha_segredos(self):
        hits = engines._scan_bundle_secrets(f'k="{self.jwt}";s="{self.sk}"')
        tipos = {h["tipo"] for h in hits}
        self.assertTrue(any("service_role" in t for t in tipos))
        self.assertTrue(any("Stripe" in t for t in tipos))
        # amostra é redigida (não contém o segredo cru)
        for h in hits:
            self.assertNotIn(self.sk, json.dumps(h))
            self.assertNotIn(self.jwt, json.dumps(h))

    def test_engine_acha_no_bundle_servido(self):
        eng = engines.BundleAuditEngine()
        tgt = Target(name="lab", type="url",
                     value=f"http://127.0.0.1:{self.port}/", allowed_tests=["all"])
        raw, status = eng.collect(tgt)
        self.assertEqual(status, CollectionStatus.OK)
        self.assertNotIn(self.sk, raw)          # artefato não vaza o segredo
        findings = eng.interpret(tgt, raw, status)
        titles = " ".join(f.title for f in findings)
        self.assertIn("service_role", titles)
        self.assertTrue(any(f.severity.value == "critica" for f in findings))


if __name__ == "__main__":
    unittest.main()
