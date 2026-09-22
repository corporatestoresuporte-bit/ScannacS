"""Prova de posse: token determinístico + persistência do owner_verified."""

import unittest

import _pathshim  # noqa: F401

from agente import scope as sc
from agente.scope import Scope, Target


class TestOwnerVerify(unittest.TestCase):
    def test_token_deterministico(self):
        t1 = sc.expected_token("https://bybit.rzsolucoes.org/")
        t2 = sc.expected_token("bybit.rzsolucoes.org")
        self.assertEqual(t1, t2)  # url e host puro => mesmo token
        self.assertTrue(t1.startswith("rz-verify-"))
        self.assertTrue(t1.endswith("-owner-ok"))
        self.assertNotEqual(t1, sc.expected_token("outro.exemplo.com"))

    def test_roundtrip_owner_verified(self):
        s = Scope(authorized=True, targets=[Target(
            name="b", type="url", value="bybit.rzsolucoes.org",
            allowed_tests=["all"], owner_verified=True,
            owner_verified_at="2026-01-01T00:00:00+00:00")])
        back = Scope.from_dict(__import__("tomllib").loads(sc.to_toml(s)))
        self.assertTrue(back.targets[0].owner_verified)
        self.assertEqual(back.targets[0].owner_verified_at,
                         "2026-01-01T00:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
