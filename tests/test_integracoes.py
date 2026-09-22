"""Verifica que os componentes dos dois repositórios foram incorporados."""

import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente import config

ROOT = config.ROOT
CLAUDE = ROOT / ".claude"

ACSK_SKILLS = [
    "performing-security-headers-audit",
    "performing-ssl-tls-security-assessment",
    "testing-for-xss-vulnerabilities",
    "exploiting-sql-injection-vulnerabilities",
    "testing-for-broken-access-control",
    "testing-api-security-with-owasp-top-10",
    "testing-for-json-web-token-vulnerabilities",
    "performing-web-application-vulnerability-triage",
]


class TestIntegracoes(unittest.TestCase):
    def test_acsk_skills_present_with_banner_and_license(self):
        for name in ACSK_SKILLS:
            d = CLAUDE / "skills" / name
            self.assertTrue((d / "SKILL.md").exists(), f"falta SKILL.md {name}")
            self.assertTrue((d / "LICENSE").exists(), f"falta LICENSE {name}")
            txt = (d / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn("NOTA DE ADAPTAÇÃO", txt, f"sem banner em {name}")

    def test_raptor_derived_skills_present(self):
        for s in ("triagem-validacao", "coordenacao-agentes"):
            self.assertTrue((CLAUDE / "skills" / s / "SKILL.md").exists())

    def test_agents_present(self):
        for a in ("validador-achados", "investigador-web", "investigador-api",
                  "investigador-auth", "investigador-infra"):
            self.assertTrue((CLAUDE / "agents" / f"{a}.md").exists(), a)

    def test_raptor_ports_in_code(self):
        # R1/R2 portados em verdict.py
        from agente import verdict
        self.assertTrue(hasattr(verdict, "read_verdict"))
        self.assertTrue(hasattr(verdict, "EvidenceTier"))

    def test_third_party_licenses(self):
        d = ROOT / "THIRD_PARTY_LICENSES"
        self.assertTrue(any("RAPTOR" in p.name for p in d.glob("*")))
        self.assertTrue(any("Cybersecurity" in p.name for p in d.glob("*")))

    def test_claude_config_present(self):
        self.assertTrue((ROOT / "CLAUDE.md").exists())
        self.assertTrue((CLAUDE / "settings.json").exists())
        self.assertTrue((CLAUDE / "commands" / "auditoria.md").exists())

    def test_integracoes_doc(self):
        self.assertTrue((ROOT / "docs" / "integracoes.md").exists())


if __name__ == "__main__":
    unittest.main()
