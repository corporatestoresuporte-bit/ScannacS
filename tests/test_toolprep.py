"""Preparo do ambiente: diagnóstico, classificação por alvo e estados.
Hermético: não instala nada nem toca a rede."""

import unittest

import _pathshim  # noqa: F401

from agente import toolprep


class TestToolprep(unittest.TestCase):
    def setUp(self):
        # hermético e rápido: não executa ferramentas reais da máquina
        self._run, self._which, self._off = (
            toolprep._run, toolprep._which, toolprep._find_offpath)
        toolprep._run = lambda cmd, timeout=60: (127, "stub")
        toolprep._which = lambda name: None
        toolprep._find_offpath = lambda tool: ""

    def tearDown(self):
        toolprep._run = self._run
        toolprep._which = self._which
        toolprep._find_offpath = self._off

    def test_os_info(self):
        info = toolprep.os_info()
        self.assertIn(info["os"], ("windows", "linux"))
        self.assertIn("arch", info)
        self.assertIn("distro", info)

    def test_role_por_alvo(self):
        semgrep = toolprep._BY_KEY["semgrep"]
        nmap = toolprep._BY_KEY["nmap"]
        self.assertEqual(toolprep.role(semgrep, {"code"}), "complementar")
        self.assertEqual(toolprep.role(semgrep, {"server"}), "nao_aplicavel")
        self.assertEqual(toolprep.role(nmap, {"server"}), "necessaria")
        self.assertEqual(toolprep.role(nmap, {"code"}), "nao_aplicavel")

    def test_diagnose_code_tem_builtins_verdes(self):
        d = toolprep.diagnose({"code"})
        by = {t["key"]: t for t in d["tools"]}
        self.assertEqual(by["codereview"]["role"], "necessaria")
        self.assertTrue(by["codereview"]["green"])          # embutido = verde
        self.assertEqual(by["semgrep"]["role"], "complementar")
        self.assertTrue(by["semgrep"]["installable"])
        # sem essencial faltando (builtins cobrem o necessário p/ código)
        self.assertEqual(d["resumo"]["essenciais_faltando"], [])

    def test_diagnose_site_classifica_scanners(self):
        d = toolprep.diagnose({"site"})
        by = {t["key"]: t for t in d["tools"]}
        self.assertEqual(by["nuclei"]["role"], "complementar")
        self.assertEqual(by["zap"]["role"], "complementar")
        self.assertTrue(by["zap"]["intervention"])          # docker = intervenção
        self.assertEqual(by["semgrep"]["role"], "nao_aplicavel")

    def test_estados_possiveis(self):
        d = toolprep.diagnose({"code", "site", "server"})
        estados = {t["state"] for t in d["tools"]}
        # todo estado reportado é um dos definidos
        self.assertTrue(estados <= {"funcional", "nao_instalada",
                                    "instalada_nao_localizada", "incompativel",
                                    "precisa_config"})

    def test_prepare_pula_o_que_ja_funciona(self):
        # only=builtin => nada é instalado, é pulado como já funcional
        res = toolprep.prepare({"code"}, {}, only=["codereview"])
        self.assertIn("codereview", res["results"])
        self.assertTrue(res["results"]["codereview"]["ok"])
        self.assertTrue(res["results"]["codereview"].get("skipped"))


if __name__ == "__main__":
    unittest.main()
