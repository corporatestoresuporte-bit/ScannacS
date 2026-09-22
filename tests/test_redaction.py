"""Segredos nunca podem aparecer em log/saída."""

import unittest

import _pathshim  # noqa: F401

from agente.logging_utils import redact


class TestRedaction(unittest.TestCase):
    def test_redige_token(self):
        out = redact("token=abc123XYZ")
        self.assertNotIn("abc123XYZ", out)
        self.assertIn("REDACTED", out)

    def test_redige_bearer(self):
        out = redact("Authorization: Bearer eyJhbGciOiJ.payload.sig")
        self.assertNotIn("eyJhbGciOiJ.payload.sig", out)
        self.assertIn("REDACTED", out)

    def test_redige_senha_e_apikey(self):
        out = redact("senha=SuperSecreta! api_key=KEY_987")
        self.assertNotIn("SuperSecreta!", out)
        self.assertNotIn("KEY_987", out)

    def test_texto_limpo_intacto(self):
        out = redact("nada sensível aqui")
        self.assertEqual(out, "nada sensível aqui")


if __name__ == "__main__":
    unittest.main()
