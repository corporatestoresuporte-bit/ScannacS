"""Modelo de achado (finding) + PORTÃO DE CONFIRMAÇÃO (spec §7).

Regras convertidas em código:
  - Toda hipótese começa como SUSPEITA.
  - Um achado só vira CONFIRMADO com: alvo correto, >=1 evidência utilizável
    (ferramenta + artefato preservado + hash + coleta OK), registro de
    validação (quem/quando + explicações alternativas consideradas), veredito
    tri-estado is_true_positive == True (abstenção NÃO confirma), e um tipo de
    confirmação demonstrado.
  - Explorabilidade só pode ser afirmada no nível comprovado (reproduzido).
  - Associação a CVE exige fonte consultada + verificação de aplicabilidade.
  - "Concordância entre agentes" é heurística: não confirma nada.

`can_confirm()` devolve (ok, faltando[]). A CLI recusa publicar como confirmado
quando faltando não está vazio.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum

from .evidence import Evidence
from .verdict import EvidenceTier, TIER_RANK, read_verdict


class Status(str, Enum):
    NOT_CHECKED = "nao_verificado"
    SUSPECTED = "suspeita"
    DISMISSED = "descartado"      # suspeita investigada e refutada
    CONFIRMED = "confirmado"
    INFO = "informativo"


class Severity(str, Enum):
    INFO = "info"
    LOW = "baixa"
    MEDIUM = "media"
    HIGH = "alta"
    CRITICAL = "critica"


class ConfirmationType(str, Enum):
    """O que foi demonstrado na confirmação (spec §7)."""

    CODE_FLAW = "falha_no_codigo"
    VULN_CONFIG = "configuracao_vulneravel"
    REPRODUCED = "comportamento_reproduzido"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Validation:
    """Registro da etapa de validação de um achado."""

    validated_by: str = ""              # agente/pessoa que validou
    validated_at: str = ""
    alternative_explanations: list[str] = field(default_factory=list)
    method: str = ""                    # como foi validado
    # veredito tri-estado (True/False/None). None = abstenção.
    is_true_positive: bool | None = None
    is_exploitable: bool | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    """Um achado de auditoria."""

    target: str
    title: str
    status: Status = Status.SUSPECTED         # começa como suspeita
    severity: Severity = Severity.INFO
    impact: str = ""
    reproduction: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    engine: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    confirmation_type: ConfirmationType | None = None
    exploitability: str = ""                  # só afirmar no nível comprovado
    cve: str = ""
    cve_source: str = ""                      # fonte consultada
    cve_applicability: str = ""               # verificação de aplicabilidade
    validation: Validation = field(default_factory=Validation)
    created_at: str = field(default_factory=_now)
    id: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        d["confirmation_type"] = (
            self.confirmation_type.value if self.confirmation_type else None
        )
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


def _best_tier(evs: list[Evidence]) -> EvidenceTier | None:
    tiers = [getattr(e, "tier", None) for e in evs]
    tiers = [t for t in tiers if isinstance(t, EvidenceTier)]
    if not tiers:
        return None
    return max(tiers, key=lambda t: TIER_RANK[t])


def validate_confirmation(finding: dict, evidences: list[dict]) -> tuple[bool, list[str]]:
    """Valida um achado-DICT contra as evidências-DICT da sessão (boundary de
    gravação). Espelha `can_confirm`, mas opera sobre os dados persistidos e
    exige que a evidência esteja LIGADA e presente na sessão.
    """
    missing: list[str] = []
    if not str(finding.get("target", "")).strip():
        missing.append("alvo do achado não definido")

    ids = set(finding.get("evidence_ids", []) or [])
    linked = [e for e in evidences if e.get("id") in ids]
    usable = [e for e in linked
              if e.get("status") == "ok" and e.get("artifact_path")
              and e.get("artifact_sha256") and e.get("tool")]
    if not usable:
        missing.append("sem evidência utilizável ligada ao achado na sessão")

    v = finding.get("validation") or {}
    if not (v.get("validated_by") and v.get("validated_at")):
        missing.append("sem registro de validação")
    if not v.get("alternative_explanations"):
        missing.append("validação não considerou explicações alternativas")
    if read_verdict(v, "is_true_positive") is not True:
        missing.append("veredito is_true_positive não é True")
    if not finding.get("confirmation_type"):
        missing.append("confirmation_type ausente")

    # explorabilidade só com evidência reproduzida
    if str(finding.get("exploitability", "")).strip() or read_verdict(v, "is_exploitable") is True:
        tiers = [e.get("tier") for e in usable]
        if EvidenceTier.REPRODUCED.value not in tiers:
            missing.append("explorabilidade sem evidência reproduzida")

    if str(finding.get("cve", "")).strip():
        if not str(finding.get("cve_source", "")).strip():
            missing.append("CVE sem fonte consultada")
        if not str(finding.get("cve_applicability", "")).strip():
            missing.append("CVE sem verificação de aplicabilidade")

    return (not missing, missing)


def can_confirm(finding: Finding, evidences: list[Evidence]) -> tuple[bool, list[str]]:
    """Aplica o portão de confirmação. Devolve (ok, faltando).

    `evidences` são as evidências efetivamente ligadas a este achado.
    """
    missing: list[str] = []

    if not finding.target.strip():
        missing.append("alvo do achado não definido")

    usable = [e for e in evidences if e.is_usable]
    if not usable:
        missing.append(
            "sem evidência utilizável (precisa de ferramenta + artefato "
            "preservado + hash + coleta OK)"
        )

    v = finding.validation
    if not (v.validated_by and v.validated_at):
        missing.append("sem registro de validação (validated_by/validated_at)")
    if not v.alternative_explanations:
        missing.append("validação não considerou explicações alternativas")

    # Veredito tri-estado: precisa ser explicitamente True.
    tp = read_verdict(v.to_dict(), "is_true_positive")
    if tp is not True:
        missing.append(
            "veredito is_true_positive não é True (abstenção/negativo não confirma)"
        )

    if finding.confirmation_type is None:
        missing.append(
            "confirmation_type ausente (falha_no_codigo | configuracao_vulneravel "
            "| comportamento_reproduzido)"
        )

    # Explorabilidade só no nível comprovado (evidência reproduzida).
    if finding.exploitability.strip() or read_verdict(v.to_dict(), "is_exploitable") is True:
        best = _best_tier(usable)
        if best is None or TIER_RANK[best] < TIER_RANK[EvidenceTier.REPRODUCED]:
            missing.append(
                "explorabilidade afirmada sem evidência reproduzida "
                "(comportamento_reproduzido)"
            )

    # CVE exige fonte + aplicabilidade.
    if finding.cve.strip():
        if not finding.cve_source.strip():
            missing.append(f"CVE {finding.cve} sem fonte consultada (cve_source)")
        if not finding.cve_applicability.strip():
            missing.append(
                f"CVE {finding.cve} sem verificação de aplicabilidade "
                "ao componente/versão"
            )

    return (not missing, missing)
