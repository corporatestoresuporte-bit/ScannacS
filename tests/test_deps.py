"""Scanner de dependências (OSV): parsing + interpretação sem rede."""

import shutil
import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente import deps


class TestDeps(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_parse_requirements(self):
        pairs = deps._parse_requirements(
            "flask==2.0.1\n# comentario\nrequests == 2.25.0\nsemver>=1\n")
        self.assertIn(("flask", "2.0.1"), pairs)
        self.assertIn(("requests", "2.25.0"), pairs)
        self.assertTrue(all(n != "semver" for n, _ in pairs))  # sem == é ignorado

    def test_parse_package_lock_v2(self):
        txt = '{"packages": {"node_modules/lodash": {"version": "4.17.19"}}}'
        self.assertIn(("lodash", "4.17.19"), deps._parse_package_lock(txt))

    def test_collect_deps(self):
        (self.tmp / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")
        got = deps.collect_deps(self.tmp)
        self.assertIn(("PyPI", "flask", "2.0.1"), got)

    def test_run_deps_com_vuln_mock(self):
        (self.tmp / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")

        def fake(eco, name, ver):
            return [{"id": "GHSA-xxxx", "aliases": ["CVE-2099-0001"],
                     "summary": "falha X", "database_specific": {"severity": "HIGH"}}]

        findings, limits = deps.run_deps(self.tmp, None, querier=fake)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cve, "CVE-2099-0001")
        self.assertEqual(findings[0].cve_source, "osv.dev")
        self.assertEqual(findings[0].severity.value, "alta")
        self.assertEqual(limits, [])

    def test_run_deps_base_indisponivel_e_limitacao(self):
        (self.tmp / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")

        def boom(eco, name, ver):
            raise OSError("sem rede")

        findings, limits = deps.run_deps(self.tmp, None, querier=boom)
        self.assertEqual(findings, [])
        self.assertTrue(any("indispon" in l for l in limits))  # limitação, não "seguro"

    def test_sem_lockfile_e_limitacao(self):
        findings, limits = deps.run_deps(self.tmp, None, querier=lambda *a: [])
        self.assertEqual(findings, [])
        self.assertTrue(any("lockfile" in l for l in limits))


if __name__ == "__main__":
    unittest.main()
