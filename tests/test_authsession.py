"""Captura de sessão autenticada: parse do 'Copy as cURL' + redação. Sem rede."""

import unittest

import _pathshim  # noqa: F401

from agente import authsession as A


class TestAuthSession(unittest.TestCase):
    def test_parse_curl_basico(self):
        tok = "eyJ" + "abc.def.ghi"
        cmd = ("curl 'https://meusite.com/api/me' "
               "-H 'accept: application/json' "
               f"-H 'authorization: Bearer {tok}' "
               "-H 'cookie: sid=xyz123'")
        d = A.parse_curl(cmd)
        self.assertEqual(d["url"], "https://meusite.com/api/me")
        self.assertEqual(d["method"], "GET")
        self.assertEqual(d["headers"]["authorization"], f"Bearer {tok}")
        self.assertEqual(d["headers"]["cookie"], "sid=xyz123")
        self.assertTrue(A.has_auth(d["headers"]))

    def test_parse_curl_post_com_corpo(self):
        cmd = ("curl 'https://x/api/login' -X POST "
               "-H 'content-type: application/json' "
               "--data-raw '{\"u\":\"a\",\"p\":\"b\"}'")
        d = A.parse_curl(cmd)
        self.assertEqual(d["method"], "POST")
        self.assertIn('"u":"a"', d["body"])

    def test_data_implica_post(self):
        d = A.parse_curl("curl 'https://x/a' --data 'q=1'")
        self.assertEqual(d["method"], "POST")

    def test_multilinha_e_flags_sem_arg(self):
        cmd = ("curl 'https://x/api' \\\n"
               "  --compressed \\\n"
               "  -H 'cookie: a=b'")
        d = A.parse_curl(cmd)
        self.assertEqual(d["url"], "https://x/api")
        self.assertEqual(d["headers"]["cookie"], "a=b")

    def test_has_auth_falso(self):
        self.assertFalse(A.has_auth({"Accept": "application/json"}))

    def test_redige_token(self):
        red = A.redacted_headers({"authorization": "Bearer supersecreto",
                                  "cookie": "sid=abc", "accept": "json"})
        self.assertEqual(red["authorization"], "***REDACTED***")
        self.assertEqual(red["cookie"], "***REDACTED***")
        self.assertEqual(red["accept"], "json")
        self.assertNotIn("supersecreto", str(red))


if __name__ == "__main__":
    unittest.main()
