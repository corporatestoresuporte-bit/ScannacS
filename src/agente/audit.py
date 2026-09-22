"""Runner de auditoria — agora com os motores de scan ligados.

Fluxo do `run()` (só com escopo autorizado + confirmação):
  1. portão de autorização (scope.evaluate_gate);
  2. sessão ativa (cria se não houver);
  3. para cada alvo × cada teste permitido, seleciona o(s) motor(es) e executa
     via `engines.run_engine` (escopo + rate-limit + evidência preservada);
  4. registra tarefas (estado) e suspeitas; NUNCA confirma sozinho.

`plan()` e `dry_run=True` descrevem sem tocar na rede.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import engines as engines_mod
from . import scope as scope_mod
from .logging_utils import get_logger
from .store import Session

logger = get_logger("agente.audit")


class AuditBlocked(Exception):
    def __init__(self, reasons: list[str]):
        self.reasons = reasons
        super().__init__("; ".join(reasons))


@dataclass
class AuditResult:
    executed: bool
    findings: list = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    session: str = ""


def preflight(scope: scope_mod.Scope | None = None) -> scope_mod.GateResult:
    if scope is None:
        scope = scope_mod.load_scope()
    return scope_mod.evaluate_gate(scope)


def available_engines() -> list:
    return engines_mod.all_engines()


def plan(scope: scope_mod.Scope | None = None) -> list[str]:
    gate = preflight(scope)
    if gate.scope is None:
        return ["Sem escopo — nada a planejar."]
    tools = engines_mod.detect_tools()
    lines = [f"Ferramentas externas: " +
             ", ".join(f"{t}{'(ok)' if ok else '(-)'}" for t, ok in tools.items())]
    for t in gate.scope.targets:
        for key in t.allowed_tests:
            engs = (engines_mod.all_engines() if key.lower() in ALL_KEYS
                    else engines_mod.engines_for(key))
            if not engs:
                lines.append(f"[{t.value}] teste '{key}': (sem motor)")
            for e in engs:
                avail = "" if e.available() else " (ferramenta ausente -> limitacao)"
                lines.append(f"[{t.value}] {key} -> motor {e.name}{avail}")
    return lines


ALL_KEYS = {"all", "tudo", "*", "completo", "full", "todos"}


def run(scope: scope_mod.Scope | None = None, confirmed: bool = False,
        dry_run: bool = False, session: Session | None = None,
        engines: list | None = None, rps: float = 5.0,
        max_per_run: int = 500) -> AuditResult:
    """Executa a auditoria — ou recusa, falhando fechado.

    `engines`: se passado (ex.: [] nos testes), sobrepõe o registro para não
    tocar na rede. Caso contrário usa `engines_for(key)` por teste; a chave
    'all'/'tudo' roda TODOS os motores. `rps`/`max_per_run` controlam a
    intensidade (modo agressivo eleva os dois) — sempre DENTRO do escopo.
    """
    if scope is None:
        scope = scope_mod.load_scope()
    gate = preflight(scope)
    if not gate.allowed:
        logger.warning("Auditoria bloqueada: %s", "; ".join(gate.reasons))
        raise AuditBlocked(gate.reasons)
    if not confirmed:
        raise AuditBlocked(["execução não confirmada — autorize (DISPARAR "
                            "AUDITORIA) ou use --confirm"])

    if dry_run:
        return AuditResult(executed=False, notes=plan(scope))

    sess = session or Session.active() or Session.create(
        environment=scope.environment, scope_hash=scope_mod.scope_hash(scope))
    sess.update_meta(status="auditando")

    override = engines is not None
    executed = False
    for t in scope.targets:
        for key in t.allowed_tests:
            if override:
                engs = engines
            elif key.lower() in ALL_KEYS:
                engs = engines_mod.all_engines()
            else:
                engs = engines_mod.engines_for(key)
            if not engs:
                sess.add_task({"agent": "coordenador", "objective": f"teste {key}",
                               "target": t.value, "tool": "-", "status": "blocked",
                               "result_format": "evidencia",
                               "note": "sem motor para este teste"})
                continue
            for e in engs:
                task = sess.add_task({"agent": e.name, "objective": f"teste {key}",
                                      "target": t.value, "tool": getattr(e, "requires", None) or e.name,
                                      "allowed_tools": [getattr(e, "requires", None) or "builtin"],
                                      "status": "in_progress", "result_format": "evidencia"})
                res = engines_mod.run_engine(sess, scope, t, e,
                                             rps=rps, max_per_run=max_per_run)
                executed = True
                st = "done" if res.evidence.status.value == "ok" else "not_verified"
                sess.update_task(task["id"], status=st,
                                 note=res.evidence.result_summary[:120])

    findings = sess.findings()
    notes = [f"Auditoria executada na sessão {sess.id}.",
             f"Evidências: {len(sess.evidence())} | suspeitas/achados: {len(findings)}.",
             "Suspeitas exigem validação (validador-achados) para confirmar."]
    return AuditResult(executed=executed, findings=findings, notes=notes, session=sess.id)
