"""Runner de auditoria.

Nesta fase da fundação NÃO há scanners reais nem provedor de IA — essa
escolha é adiada até os prompts master e o escopo chegarem. O runner já
implementa o esqueleto seguro:

  1. preflight(): aplica o portão de autorização (scope.evaluate_gate).
  2. plan():      lista o que SERIA executado por alvo (sem tocar na rede).
  3. run():       recusa sem autorização + confirmação; com tudo válido,
                  ainda não executa scanners (nenhum motor registrado),
                  devolvendo um resultado explícito de "não verificado".

Os motores (engines) reais serão registrados em ENGINES quando definidos.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import scope as scope_mod
from .findings import Finding, Severity, Status
from .logging_utils import get_logger

logger = get_logger("agente.audit")

# Registro de motores de scan. Vazio de propósito nesta fase.
# Futuro: {"headers": HeadersEngine, "tls": TlsEngine, ...}
ENGINES: dict[str, object] = {}


class AuditBlocked(Exception):
    """Levantada quando a auditoria é solicitada sem autorização/escopo."""

    def __init__(self, reasons: list[str]):
        self.reasons = reasons
        super().__init__("; ".join(reasons))


@dataclass
class AuditResult:
    executed: bool
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def preflight(scope: scope_mod.Scope | None = None) -> scope_mod.GateResult:
    """Carrega o escopo (se não vier pronto) e aplica o portão."""
    if scope is None:
        scope = scope_mod.load_scope()
    return scope_mod.evaluate_gate(scope)


def plan(scope: scope_mod.Scope | None = None) -> list[str]:
    """Descreve o que SERIA executado por alvo. Não faz nenhuma requisição."""
    gate = preflight(scope)
    lines: list[str] = []
    if gate.scope is None:
        return ["Sem escopo — nada a planejar."]
    for t in gate.scope.targets:
        tests = ", ".join(t.allowed_tests) or "(nenhum teste permitido)"
        excl = ", ".join(t.exclusions) or "nenhuma"
        lines.append(
            f"[{t.type}] {t.name or t.value} -> {t.value} | testes: {tests} "
            f"| exclusões: {excl}"
        )
    if not ENGINES:
        lines.append(
            "AVISO: nenhum motor de scan registrado ainda (fase de fundação)."
        )
    return lines


def run(scope: scope_mod.Scope | None = None, confirmed: bool = False) -> AuditResult:
    """Executa a auditoria — ou recusa, falhando fechado.

    Requer, cumulativamente:
      - portão de autorização aprovado (escopo + authorized + alvos válidos);
      - `confirmed=True` (a CLI só passa isso com --confirm / confirmação).
    """
    gate = preflight(scope)
    if not gate.allowed:
        logger.warning("Auditoria bloqueada: %s", "; ".join(gate.reasons))
        raise AuditBlocked(gate.reasons)

    if not confirmed:
        raise AuditBlocked(
            ["execução não confirmada — rode com --confirm para autorizar o início"]
        )

    if not ENGINES:
        logger.info("Escopo válido, mas nenhum motor de scan registrado.")
        notes = [
            "Escopo autorizado e válido.",
            "Nenhum motor de scan registrado nesta fase — nada foi executado.",
            "Integre os motores em audit.ENGINES após definir os prompts master.",
        ]
        findings = [
            Finding(
                target=t.value,
                title="Auditoria não executada (sem motores)",
                status=Status.NOT_CHECKED,
                severity=Severity.INFO,
                impact="Nenhum — nenhuma verificação foi realizada "
                       "(fase de fundação: ENGINES vazio).",
                remediation="Registrar motores reais e reexecutar.",
            )
            for t in (gate.scope.targets if gate.scope else [])
        ]
        return AuditResult(executed=False, findings=findings, notes=notes)

    # Caminho futuro: iterar ENGINES por alvo respeitando allowed_tests.
    raise NotImplementedError("Execução de motores ainda não implementada.")
