"""Replay ativo: gating de posse/escopo + helpers (sem rede)."""

import json
import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente import replay
from agente.scope import Scope, Target


def _scope(verified: bool):
    return Scope(authorized=True, targets=[Target(
        name="s", type="url", value="https://meusite.com/api",
        allowed_tests=["all"], owner_verified=verified)])


class TestReplay(unittest.TestCase):
    def test_authorized_requer_posse(self):
        url = "https://meusite.com/api/x"
        self.assertFalse(replay.authorized_target(url, None)[0])
        self.assertFalse(replay.authorized_target(url, _scope(False))[0])
        self.assertTrue(replay.authorized_target(url, _scope(True))[0])

    def test_host_fora_do_escopo(self):
        self.assertFalse(
            replay.authorized_target("https://evil.example/x", _scope(True))[0])

    def test_run_replay_bloqueia_sem_posse(self):
        req = replay.Req(method="GET", url="https://meusite.com/api/x",
                         headers={}, body="")
        with self.assertRaises(PermissionError):
            replay.run_replay(None, _scope(False), req, ["no-auth"])

    def test_swap_param_query_e_corpo(self):
        u, b = replay._swap_param(
            "https://x/api?email=a@x.com&id=1",
            '{"email":"a@x.com"}', "email", "MARK")
        self.assertIn("email=MARK", u)
        self.assertIn('"email":"MARK"', b)

    def test_strip_auth(self):
        h = {"Authorization": "Bearer z", "Cookie": "s=1", "Accept": "json"}
        out = replay._strip_auth(h)
        self.assertNotIn("Authorization", out)
        self.assertNotIn("Cookie", out)
        self.assertIn("Accept", out)

    def test_load_request(self):
        tmp = Path(tempfile.mkdtemp()) / "r.json"
        tmp.write_text(json.dumps({"method": "post", "url": "https://x/y",
                                   "headers": {"A": "b"}, "body": "{}",
                                   "fuzz_param": "id"}), encoding="utf-8")
        r = replay.load_request(tmp)
        self.assertEqual(r.method, "POST")
        self.assertEqual(r.fuzz_param, "id")


if __name__ == "__main__":
    unittest.main()
