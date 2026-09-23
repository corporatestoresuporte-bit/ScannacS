"""Adaptador Semgrep: parser (mock, sem o binário)."""

import json
import unittest

import _pathshim  # noqa: F401

from agente import sast


class TestSast(unittest.TestCase):
    def test_parse_semgrep(self):
        payload = json.dumps({"results": [
            {"check_id": "python.lang.security.audit.eval-detected",
             "path": "src/app.py", "start": {"line": 12},
             "extra": {"severity": "ERROR", "message": "eval é perigoso"}},
            {"check_id": "regra.info", "path": "src/x.py", "start": {"line": 3},
             "extra": {"severity": "INFO", "message": "aviso"}},
        ]})
        findings = sast.parse_semgrep(payload, target="meurepo")
        self.assertEqual(len(findings), 2)
        self.assertTrue(findings[0].title.startswith("Semgrep:"))
        self.assertEqual(findings[0].severity.value, "alta")     # ERROR->alta
        self.assertEqual(findings[0].evidence_ids[0], "src/app.py:12")
        self.assertEqual(findings[1].severity.value, "baixa")    # INFO->baixa

    def test_parse_semgrep_vazio(self):
        self.assertEqual(sast.parse_semgrep('{"results": []}'), [])
        self.assertEqual(sast.parse_semgrep("nao-json"), [])

    def test_run_semgrep_ausente_e_limitacao(self):
        # nesta máquina semgrep pode não existir -> retorna limitação (não crash)
        import shutil
        if shutil.which("semgrep") is None:
            findings, limits = sast.run_semgrep(__import__("pathlib").Path("."))
            self.assertEqual(findings, [])
            self.assertTrue(any("semgrep" in l for l in limits))


if __name__ == "__main__":
    unittest.main()
