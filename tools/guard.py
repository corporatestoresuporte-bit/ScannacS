#!/usr/bin/env python3
"""Entrada do hook PreToolUse (executor controlado).

O Claude Code chama este script (via .claude/settings.json) antes de cada
ferramenta, com JSON no stdin. Ele descobre a raiz do projeto pelo próprio
caminho — não depende de variável de ambiente nem de caminho absoluto com
acento/espaço embutido no settings.json.

Sai com 2 (+motivo no stderr) para BLOQUEAR; 0 para permitir.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    from agente.hook import main
except Exception as exc:  # se o pacote nem importa, não trava a sessão
    sys.stderr.write(f"[executor-controlado] aviso: hook indisponível ({exc})\n")
    sys.exit(0)

if __name__ == "__main__":
    sys.exit(main())
