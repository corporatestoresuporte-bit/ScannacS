"""O portão de autorização deve falhar fechado (negar por padrão)."""

import unittest

import _pathshim  # noqa: F401  (ajusta o sys.path)

from agente import audit as audit_mod
from agente.scope import Scope, Target, evaluate_gate


class TestScopeGate(unittest.TestCase):
    def test_sem_escopo_bloqueia(self):
        gate = evaluate_gate(None)
        self.assertFalse(gate.allowed)
        self.assertTrue(any("escopo não definido" in r for r in gate.reasons))

    def test_escopo_nao_autorizado_bloqueia(self):
        scope = Scope(
            authorized=False,
            targets=[Target(name="site", type="domain", value="exemplo.com",
                            allowed_tests=["headers"])],
        )
        gate = evaluate_gate(scope)
        self.assertFalse(gate.allowed)
        self.assertTrue(any("não autorizado" in r for r in gate.reasons))

    def test_sem_alvos_bloqueia(self):
        scope = Scope(authorized=True, targets=[])
        gate = evaluate_gate(scope)
        self.assertFalse(gate.allowed)
        self.assertTrue(any("nenhum alvo" in r for r in gate.reasons))

    def test_alvo_localhost_recusado(self):
        scope = Scope(
            authorized=True,
            targets=[Target(name="dev", type="url", value="http://localhost:8000",
                            allowed_tests=["headers"])],
        )
        gate = evaluate_gate(scope)
        self.assertFalse(gate.allowed)
        self.assertTrue(any("máquina de desenvolvimento" in r for r in gate.reasons))

    def test_alvo_sem_testes_permitidos_bloqueia(self):
        scope = Scope(
            authorized=True,
            targets=[Target(name="site", type="domain", value="exemplo.com",
                            allowed_tests=[])],
        )
        gate = evaluate_gate(scope)
        self.assertFalse(gate.allowed)

    def test_escopo_valido_libera(self):
        scope = Scope(
            authorized=True,
            environment="producao",
            targets=[Target(name="site", type="domain", value="exemplo.com",
                            allowed_tests=["headers", "tls"])],
        )
        gate = evaluate_gate(scope)
        self.assertTrue(gate.allowed, msg=str(gate.reasons))

    def test_run_bloqueia_sem_confirmacao(self):
        scope = Scope(
            authorized=True,
            targets=[Target(name="site", type="domain", value="exemplo.com",
                            allowed_tests=["headers"])],
        )
        with self.assertRaises(audit_mod.AuditBlocked):
            audit_mod.run(scope=scope, confirmed=False)

    def test_run_dry_run_nao_executa(self):
        scope = Scope(
            authorized=True,
            targets=[Target(name="site", type="domain", value="exemplo.com",
                            allowed_tests=["headers"])],
        )
        # dry_run + engines=[] garantem que NADA toca a rede no teste
        result = audit_mod.run(scope=scope, confirmed=True, dry_run=True)
        self.assertFalse(result.executed)


if __name__ == "__main__":
    unittest.main()
