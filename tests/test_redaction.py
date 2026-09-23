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
        # token montado em runtime p/ nao deixar literal parecido-com-segredo no fonte
        tok = "eyJhbGciOiJ" + "." + "payload" + "." + "sig"
        out = redact("Authorization: Bearer " + tok)
        self.assertNotIn(tok, out)
        self.assertIn("REDACTED", out)

    def test_redige_senha_e_apikey(self):
        out = redact("senha=SuperSecreta! api_key=KEY_987")
        self.assertNotIn("SuperSecreta!", out)
        self.assertNotIn("KEY_987", out)

    def test_texto_limpo_intacto(self):
        out = redact("nada sensível aqui")
        self.assertEqual(out, "nada sensível aqui")

    # literais fictícios montados em runtime (concat) p/ não gravar no fonte um
    # texto que o secret-scanning confunde com chave real.
    _SK = "sk_" + "live_" + "51H8x9aBcDeFgHiJkLmNoPqRs"

    def test_redige_nome_camelcase_e_underscore(self):
        # apiSecret e SUPABASE_SERVICE_ROLE_KEY não casavam com \bnome\b antes.
        out = redact('const apiSecret = "' + self._SK + '"')
        self.assertNotIn(self._SK, out)
        out2 = redact("const SUPABASE_SERVICE_ROLE_KEY = 'valorsupersecreto123'")
        self.assertNotIn("valorsupersecreto123", out2)

    def test_redige_formato_stripe_e_jwt_sem_chave(self):
        # Segredo reconhecido pelo VALOR, sem nome de chave amigável.
        sk = "sk_" + "live_" + "ABCdef123456"
        out = redact("pagou com " + sk + " ok")
        self.assertNotIn(sk, out)
        jwt = ("eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NX0" + "."
               + "SflKxwRJSMeKKF2QT4")
        out2 = redact("cookie=" + jwt)
        self.assertNotIn(jwt, out2)

    def test_redige_aws_e_github(self):
        aws = "AKIA" + "IOSFODNN7EXAMPLE"
        gh = "ghp_" + "ABCdefGHIjklMNOpqrsTUVwxyz012345"
        out = redact(aws + " e " + gh)
        self.assertNotIn(aws, out)
        self.assertNotIn(gh, out)


if __name__ == "__main__":
    unittest.main()
