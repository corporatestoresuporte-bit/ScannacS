"""Replay ativo: gating de posse/escopo + helpers (sem rede)."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente import replay, store
from agente.evidence import CollectionStatus
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

    def test_metodo_que_muda_estado_nao_envia_sem_permissao(self):
        # DELETE sem --com-efeito-colateral: NENHUM envio (nem baseline)
        calls = []
        orig = replay._send
        replay._send = lambda *a, **k: (calls.append(1), (200, "x", CollectionStatus.OK))[1]
        try:
            req = replay.Req("DELETE", "https://meusite.com/api/x", {}, "")
            with self.assertRaises(PermissionError):
                replay.run_replay(None, _scope(True), req, ["no-auth"],
                                  allow_side_effects=False)
        finally:
            replay._send = orig
        self.assertEqual(calls, [])  # zero requisições enviadas

    def test_erro_conexao_nao_vira_achado_de_rate(self):
        tmp = Path(tempfile.mkdtemp())
        sd, ap = store.SESSIONS_DIR, store.ACTIVE_POINTER
        store.SESSIONS_DIR, store.ACTIVE_POINTER = tmp, tmp / ".active"
        orig = replay._send
        replay._send = lambda *a, **k: (None, "(erro de conexao)", CollectionStatus.ERROR)
        try:
            sess = store.Session.create()
            req = replay.Req("GET", "https://meusite.com/api/x", {}, "")
            found = replay.run_replay(sess, _scope(True), req, ["rate"], rate_n=3)
            self.assertFalse(any("rate-limit" in f.title for f in found))
            # evidência de erro não fica marcada como coleta OK
            self.assertTrue(any(e.get("status") != "ok" for e in sess.evidence()))
        finally:
            replay._send = orig
            store.SESSIONS_DIR, store.ACTIVE_POINTER = sd, ap
            shutil.rmtree(tmp, ignore_errors=True)

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

    def test_load_har(self):
        har = {"log": {"entries": [
            {"request": {"method": "get", "url": "https://meusite.com/api/x",
                         "headers": [{"name": "Authorization", "value": "Bearer z"},
                                     {"name": ":method", "value": "GET"}],
                         "postData": {"text": ""}}},
            {"request": {"method": "POST", "url": "https://meusite.com/api/y",
                         "headers": [], "postData": {"text": '{"a":1}'}}},
        ]}}
        p = Path(tempfile.mkdtemp()) / "t.har"
        p.write_text(json.dumps(har), encoding="utf-8")
        reqs = replay.load_har(p)
        self.assertEqual(len(reqs), 2)
        self.assertEqual(reqs[0].method, "GET")
        self.assertIn("Authorization", reqs[0].headers)
        self.assertNotIn(":method", reqs[0].headers)   # pseudo-header ignorado
        self.assertEqual(reqs[1].body, '{"a":1}')

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
