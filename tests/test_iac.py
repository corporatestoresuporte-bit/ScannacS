"""Adaptador Trivy (IaC): parser (mock, sem o binário)."""

import json
import unittest

import _pathshim  # noqa: F401

from agente import iac


class TestIac(unittest.TestCase):
    def test_parse_trivy(self):
        payload = json.dumps({"Results": [
            {"Target": "Dockerfile",
             "Misconfigurations": [
                 {"ID": "DS002", "Title": "Image user should not be root",
                  "Severity": "HIGH", "Description": "roda como root",
                  "Resolution": "adicione USER",
                  "CauseMetadata": {"StartLine": 1},
                  "References": ["https://avd.aquasec.com/DS002"]}]}]})
        findings = iac.parse_trivy(payload, target="repo")
        self.assertEqual(len(findings), 1)
        self.assertIn("DS002", findings[0].title)
        self.assertEqual(findings[0].severity.value, "alta")
        self.assertEqual(findings[0].evidence_ids[0], "Dockerfile:1")

    def test_parse_trivy_vazio(self):
        self.assertEqual(iac.parse_trivy('{"Results": []}'), [])
        self.assertEqual(iac.parse_trivy("nao-json"), [])

    def test_run_ausente_e_limitacao(self):
        import shutil
        from pathlib import Path
        if shutil.which("trivy") is None:
            findings, limits = iac.run_trivy_config(Path("."))
            self.assertEqual(findings, [])
            self.assertTrue(any("trivy" in l for l in limits))


if __name__ == "__main__":
    unittest.main()
