#!/usr/bin/env python3
"""Sincroniza o workspace do Claude para dentro do pacote (para o wheel).

Copia CLAUDE.md, AGENTS.md, .claude/, prompts/ e THIRD_PARTY_LICENSES/ do
checkout para src/agente/data/workspace/, que é o que `agente init-workspace`
materializa. Rode ANTES de empacotar/release. Não copia segredos/escopo/
sessões/relatórios (não estão nesses itens).
"""

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DST = ROOT / "src" / "agente" / "data" / "workspace"
ITEMS = ["CLAUDE.md", "AGENTS.md", ".claude", "prompts", "THIRD_PARTY_LICENSES"]
# nunca copiar (defesa: caso apareçam dentro de um item)
DENY = {"scope.toml", "settings.local.json", ".env"}


def _ignore(_dir, names):
    return [n for n in names if n in DENY or n == "__pycache__"]


def main() -> int:
    if DST.exists():
        shutil.rmtree(DST)
    DST.mkdir(parents=True)
    for item in ITEMS:
        src = ROOT / item
        if not src.exists():
            print(f"aviso: {item} ausente, pulando")
            continue
        # `.claude` é pasta oculta e o setuptools a exclui do wheel — empacota
        # como `claude_ws`; o init-workspace renomeia de volta no destino.
        dstname = "claude_ws" if item == ".claude" else item
        dst = DST / dstname
        if src.is_dir():
            shutil.copytree(src, dst, ignore=_ignore)
        else:
            shutil.copy2(src, dst)
        print(f"ok: {item}" + (" (empacotado como claude_ws)" if dstname != item else ""))
    n = sum(1 for _ in DST.rglob("*") if _.is_file())
    print(f"workspace empacotado: {n} arquivo(s) em {DST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
