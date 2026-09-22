"""Modelo de achado (finding).

Todo achado carrega: evidência, impacto, reprodução e orientação de correção.
O `status` separa claramente suspeita, confirmado e não verificado — nunca
se afirma vulnerabilidade sem confirmação.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Status(str, Enum):
    """Estado de verificação de um achado."""

    NOT_CHECKED = "nao_verificado"   # verificação não realizada
    SUSPECTED = "suspeita"           # indício, ainda não confirmado
    CONFIRMED = "confirmado"         # reproduzido com evidência
    INFO = "informativo"             # observação sem risco direto


class Severity(str, Enum):
    INFO = "info"
    LOW = "baixa"
    MEDIUM = "media"
    HIGH = "alta"
    CRITICAL = "critica"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    """Um achado de auditoria, pronto para virar relatório."""

    target: str
    title: str
    status: Status = Status.NOT_CHECKED
    severity: Severity = Severity.INFO
    evidence: str = ""            # o que foi observado (sem segredos)
    impact: str = ""             # por que importa
    reproduction: str = ""       # passos para reproduzir
    remediation: str = ""        # como corrigir
    references: list[str] = field(default_factory=list)
    engine: str = ""             # ferramenta/motor que produziu o achado
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
