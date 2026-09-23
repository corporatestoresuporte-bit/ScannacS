"""App web local: servidor sobe, executor roda motor de código e gera relatório;
posse de loopback é automática; cancelamento marca a flag. Sem rede externa."""

import json
import shutil
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

import _pathshim  # noqa: F401

from agente import store, webui
from agente import scope as scope_mod


class TestWebUI(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._sd, self._ap = store.SESSIONS_DIR, store.ACTIVE_POINTER
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self.tmp / "s", self.tmp / ".active"
        (self.tmp / "s").mkdir(parents=True, exist_ok=True)
        # isola o escopo em disco
        self._ls, self._ss = scope_mod.load_scope, scope_mod.save_scope
        scope_mod.load_scope = lambda *a, **k: scope_mod.Scope()
        scope_mod.save_scope = lambda *a, **k: None
        # laboratório de código com um "segredo"
        self.lab = self.tmp / "code"
        self.lab.mkdir()
        (self.lab / "app.js").write_text(
            "const k = '" + "sk_" + "live_" + "AAbbCCddEEffGGhh112233'\n",
            encoding="utf-8")
        webui.STATE.clear()
        webui.STATE.update(webui._blank_state())

    def tearDown(self):
        store.SESSIONS_DIR, store.ACTIVE_POINTER = self._sd, self._ap
        scope_mod.load_scope, scope_mod.save_scope = self._ls, self._ss
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_verify_loopback_automatico(self):
        r = webui.verify_target("http://127.0.0.1:8000")
        self.assertTrue(r["ok"])
        self.assertEqual(r["method"], "loopback")

    def test_target_kind(self):
        self.assertEqual(webui.target_kind(str(self.lab)), "code")
        self.assertEqual(webui.target_kind("https://x.com"), "url")
        self.assertEqual(webui.target_kind("10.0.0.1"), "ip")

    def test_fluxo_codigo_gera_relatorio(self):
        proj = {"targets": [{"kind": "code", "value": str(self.lab)}],
                "mode": "ferramentas", "options": {}}
        self.assertTrue(webui.start_project(proj)["ok"])
        for _ in range(80):
            if webui._snapshot()["phase"] in ("scanned", "done", "cancelled"):
                break
            time.sleep(0.1)
        s = webui._snapshot()
        self.assertEqual(s["phase"], "scanned")     # modo ferramentas não chama Claude
        self.assertGreaterEqual(s["findings"], 1)   # achou o segredo
        self.assertIn("RELAT", s["report"])
        tools = [st["tool"] for st in s["steps"]]
        self.assertTrue(any("codereview" in t for t in tools))

    def test_http_serve_e_api(self):
        httpd = webui.serve(port=0, open_browser=False, block=False)
        try:
            base = f"http://127.0.0.1:{httpd.server_address[1]}"
            self.assertEqual(urllib.request.urlopen(base + "/", timeout=5).status, 200)
            st = json.loads(urllib.request.urlopen(base + "/api/state", timeout=5).read())
            self.assertIn("phase", st)
            deps = json.loads(urllib.request.urlopen(base + "/api/deps", timeout=5).read())
            self.assertIn("tools", deps)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_cancel_marca_flag(self):
        webui.cancel()
        self.assertTrue(webui._snapshot()["cancel"])


if __name__ == "__main__":
    unittest.main()
