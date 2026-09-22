"""Veredito tri-estado do validador + graduação de evidência.

ADAPTADO DE RAPTOR (MIT) — arquivos de origem:
  - core/run/finding_status.py  (read_verdict tri-estado, VERDICT_KEYS)
  - core/evidence/__init__.py   (EvidenceTier, TIER_RANK, stronger)
  Repositório: https://github.com/gadievron/raptor  (commit a1996f8)
  Copyright (c) 2025-2026 Gadi Evron, Daniel Cuthbert, Thomas Dullien
  (Halvar Flake), Michael Bargury, John Cartwright. Licença MIT.
  Ver docs/integracoes.md e THIRD_PARTY_LICENSES/ para o texto da licença.

Por que importar isto: a lição central do RAPTOR é que o LLM só levanta
HIPÓTESE; quem dá o veredito é a evidência mecânica. Dois pontos concretos:

  1. Veredito tri-estado (True / False / None-abstenção). Nunca tratar
     ausência de veredito como NEGATIVO — isso rebaixa achado cuja análise
     apenas falhou. `read_verdict` devolve bool só quando é bool de verdade.
  2. Graduação de evidência: runtime observado > prova > estrutural >
     cabeçalho > heurística/LLM. "Concordância entre agentes" é heurística —
     não substitui evidência (spec §7).
"""

from __future__ import annotations

from enum import Enum

# Campos de veredito com semântica tri-estado (True / False / abstido).
VERDICT_KEYS = ("is_true_positive", "is_exploitable")


def read_verdict(record: dict | None, key: str) -> bool | None:
    """Leitura tri-estado de um campo de veredito booleano.

    Devolve o valor apenas quando é um bool genuíno. Chave ausente, None
    explícito (abstenção — análise malformada, não um veredito), registro
    não-dict ou qualquer forma não-bool leem como None.

        read_verdict(r, "is_exploitable") is True    # confirmado
        read_verdict(r, "is_exploitable") is False   # negativo explícito
        read_verdict(r, "is_exploitable") is None    # abstenção / sem veredito

    NUNCA aplicar truthiness, `not` ou `.get(default)` bool a esses campos:
    esse idioma lê abstenção como veredito NEGATIVO.
    """
    if not isinstance(record, dict):
        return None
    value = record.get(key)
    return value if isinstance(value, bool) else None


class EvidenceTier(str, Enum):
    """Quão perto uma observação está da verdade de campo (ground truth).

    Adaptado de RAPTOR core/evidence. Reordenado para auditoria de app/rede:
    o topo é comportamento reproduzido; o fundo é heurística/LLM (mais fraco).
    """

    REPRODUCED = "comportamento_reproduzido"   # PoC reproduziu o efeito
    TOOL_OBSERVED = "observado_por_ferramenta"  # ferramenta capturou o fato
    CONFIG_PROVED = "config_comprovada"        # config vulnerável demonstrada
    RESPONSE_BACKED = "resposta_http"          # resposta/artefato bruto
    HEURISTIC = "heuristica"                   # LLM / padrão / suposição


TIER_RANK: dict[EvidenceTier, int] = {
    EvidenceTier.REPRODUCED: 4,
    EvidenceTier.TOOL_OBSERVED: 3,
    EvidenceTier.CONFIG_PROVED: 2,
    EvidenceTier.RESPONSE_BACKED: 1,
    EvidenceTier.HEURISTIC: 0,
}


def stronger(a: EvidenceTier, b: EvidenceTier) -> EvidenceTier:
    """Devolve o tier mais próximo da verdade de campo."""
    return a if TIER_RANK[a] >= TIER_RANK[b] else b


def is_mechanical(tier: EvidenceTier) -> bool:
    """Tier vale como evidência mecânica (acima de heurística)?"""
    return TIER_RANK[tier] > TIER_RANK[EvidenceTier.HEURISTIC]
