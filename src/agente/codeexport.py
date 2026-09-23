"""Exporta trechos de código dos achados (reprodutibilidade + auditabilidade).

Para cada achado com referência `arquivo:linha`, grava um artefato com:
  - o trecho (± contexto), com SEGREDOS REDIGIDOS;
  - o caminho e a linha;
  - a versão/commit analisada;
  - o sha256 do ARQUIVO inteiro (verificável).
Preserva os artefatos existentes; não inclui o repositório todo nem segredos.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .logging_utils import redact

_REF = re.compile(r"^(.*):(\d+)$")


def _parse_ref(ev: str) -> tuple[str, int]:
    m = _REF.match(ev or "")
    if m:
        return m.group(1), int(m.group(2))
    return (ev or ""), 0


def export_snippets(session, findings, context: int = 5, version: str = "") -> int:
    """Grava um artefato de trecho por achado de código. Devolve quantos."""
    outdir = session.artifacts / "code"
    outdir.mkdir(parents=True, exist_ok=True)
    n = 0
    for f in findings:
        ev = f.evidence_ids[0] if getattr(f, "evidence_ids", None) else ""
        path, line = _parse_ref(ev)
        p = Path(path)
        if not p.is_file():
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        sha = hashlib.sha256(raw).hexdigest()
        lines = raw.decode("utf-8", "replace").splitlines()
        a = max(0, line - 1 - context)
        b = min(len(lines), line + context) if line else min(len(lines), context * 2)
        body = "\n".join(f"{i+1}: {lines[i]}" for i in range(a, b))
        red = redact(body)
        art = outdir / f"snippet-{n:04d}.txt"
        art.write_text(
            f"# arquivo: {path}\n# linha: {line}\n# versao: {version or '-'}\n"
            f"# sha256(arquivo): {sha}\n# (segredos redigidos)\n\n{red}\n",
            encoding="utf-8")
        f.evidence_ids = [ev, str(art)]
        n += 1
    return n
