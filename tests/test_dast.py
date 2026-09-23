"""Adaptador ZAP (DAST): parser (mock, sem Docker)."""

import json
import unittest

import _pathshim  # noqa: F401

from agente import dast


class TestDast(unittest.TestCase):
    def test_parse_zap(self):
        payload = json.dumps({"site": [
            {"@name": "http://alvo", "alerts": [
                {"alert": "Missing Anti-clickjacking Header", "riskcode": "2",
                 "desc": "sem X-Frame-Options", "solution": "adicione o header",
                 "instances": [{"uri": "http://alvo/"}]},
                {"alert": "Info", "riskcode": "0", "desc": "x",
                 "instances": []}]}]})
        findings = dast.parse_zap(payload)
        self.assertEqual(len(findings), 2)
        self.assertTrue(findings[0].title.startswith("ZAP:"))
        self.assertEqual(findings[0].severity.value, "media")   # risco 2
        self.assertEqual(findings[0].evidence_ids, ["http://alvo/"])
        self.assertEqual(findings[1].severity.value, "info")    # risco 0

    def test_parse_zap_vazio(self):
        self.assertEqual(dast.parse_zap('{"site": []}'), [])
        self.assertEqual(dast.parse_zap("nao-json"), [])


if __name__ == "__main__":
    unittest.main()
