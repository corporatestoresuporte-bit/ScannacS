"""Executor controlado: decisões de escopo e rate-limit."""

import unittest

import _pathshim  # noqa: F401

from agente.executor import (check_and_consume, decide, extract_hosts,
                             touches_protected, uses_network)
from agente.scope import Scope, Target


def _scope(authorized=True):
    return Scope(authorized=authorized, targets=[
        Target(name="site", type="domain", value="meusite.com",
               allowed_tests=["headers"]),
        Target(name="api", type="url", value="https://api.meusite.com",
               allowed_tests=["api"]),
    ])


class TestExecutor(unittest.TestCase):
    def test_local_command_allowed(self):
        self.assertTrue(decide("ls -la", _scope()).allow)
        self.assertTrue(decide("python -m agente version", None).allow)

    def test_local_grep_with_network_keyword_allowed(self):
        # BUGFIX: grep/cat mencionando curl/http como ARGUMENTO é LOCAL.
        self.assertFalse(uses_network('grep -rE "curl|wget|http://" .'))
        self.assertTrue(decide('grep -rE "curl|wget" .', _scope()).allow)
        self.assertTrue(decide('cat urls.txt', _scope()).allow)
        # python SEM url = local; com url = rede (ver test_interpretador_com_url)
        self.assertFalse(uses_network('python scan.py --flag local'))

    def test_network_when_tool_is_executable(self):
        self.assertTrue(uses_network("curl https://meusite.com"))
        self.assertTrue(uses_network("ls; nmap meusite.com"))

    def test_interpretador_com_url_conta_como_rede(self):
        self.assertTrue(uses_network(
            'python -c "import urllib.request as u; u.urlopen(\'https://evil.example\')"'))
        self.assertTrue(uses_network("node app.js https://api.evil.example"))

    def test_propria_cli_agente_nao_e_rede(self):
        # a CLI do projeto se auto-limita; não deve ser regateada pelo hook
        self.assertFalse(uses_network("python -m agente scan https://meusite.com"))
        self.assertFalse(uses_network("python tools/guard.py"))

    def test_network_without_scope_denied(self):
        d = decide("curl -sI https://meusite.com", None)
        self.assertFalse(d.allow)

    def test_network_unauthorized_denied(self):
        d = decide("curl -sI https://meusite.com", _scope(authorized=False))
        self.assertFalse(d.allow)

    def test_out_of_scope_denied(self):
        d = decide("curl -sI https://evil.example", _scope())
        self.assertFalse(d.allow)
        self.assertIn("fora do escopo", d.reason)

    def test_in_scope_allowed(self):
        d = decide("curl -sI https://meusite.com/x", _scope())
        self.assertTrue(d.allow, msg=d.reason)
        self.assertIn("meusite.com", d.targets)

    def test_mixed_targets_denies_if_any_out(self):
        d = decide("curl https://meusite.com && curl https://evil.example", _scope())
        self.assertFalse(d.allow)

    def test_protected_path_write_denied(self):
        self.assertTrue(touches_protected("echo x >> config/scope.toml"))
        d = decide("sed -i s/false/true/ config/scope.toml", _scope())
        self.assertFalse(d.allow)

    def test_network_without_host_denied(self):
        # comando de rede sem host identificável => falha fechada
        d = decide("nmap", _scope())
        self.assertFalse(d.allow)

    def test_uses_network_and_hosts(self):
        self.assertTrue(uses_network("curl https://x.com"))
        self.assertFalse(uses_network("cat file.txt"))
        self.assertIn("meusite.com", extract_hosts("curl https://meusite.com/a"))

    def test_rate_limit(self):
        limits = {}
        ok, _, limits = check_and_consume(limits, "h", rps=1.0, max_per_run=2)
        self.assertTrue(ok)
        ok2, reason, limits = check_and_consume(limits, "h", rps=1.0, max_per_run=2)
        # segundo imediato: sem tokens
        self.assertFalse(ok2)


if __name__ == "__main__":
    unittest.main()
