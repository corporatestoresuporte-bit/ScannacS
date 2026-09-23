"""Reconciliação por ID dos achados (bater JSON × interface × relatório).

Números determinísticos, calculados sempre do MESMO findings.json — logo,
`finding list`, `report` e `reconcile` conferem, inclusive após fechar/reabrir.
"""

from __future__ import annotations

from collections import Counter


def reconcile(findings: list[dict]) -> dict:
    bruto = len(findings)
    estados = Counter(f.get("status", "?") for f in findings)
    chave = {(f.get("title", ""), f.get("target", "")) for f in findings}
    revisados = sum(1 for f in findings
                    if (f.get("validation") or {}).get("validated_by"))
    origem = Counter(f.get("engine", "?") for f in findings)
    return {
        "bruto": bruto,
        "unicos": len(chave),
        "duplicados": bruto - len(chave),
        "por_estado": dict(estados),
        "revisados": revisados,
        "nao_revisados": bruto - revisados,
        "por_origem": dict(origem),
    }
