#!/usr/bin/env python3
"""Banner dark exibido ao entrar no repo (hook SessionStart do Claude Code)
e pelo iniciador. Mostra o estado curto e lembra de digitar /scan.

ANSI escuro (fundo preto / ciano-verde). Se o terminal não renderizar ANSI,
o texto continua legível.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:  # UTF-8 defensivo
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

C = "\033[96m"   # ciano
G = "\033[92m"   # verde
D = "\033[90m"   # cinza
BG = "\033[40m"  # fundo preto
R = "\033[0m"

def _state() -> str:
    try:
        from agente import scope as sc, context as cx
        from agente.store import Session
        s = sc.load_scope()
        alvos = len(s.targets) if s else 0
        auth = "SIM" if (s and s.authorized) else "nao"
        prompts = len(cx.list_masters())
        sess = Session.active()
        sid = sess.id if sess else "nenhuma"
        return f"prompts:{prompts}  alvos:{alvos}  autorizado:{auth}  sessao:{sid}"
    except Exception:
        return "estado indisponivel"

def main() -> int:
    b = [
        f"{BG}{C}",
        "  +-------------------------------------------------+",
        "  |   AGENTE-VULNERABILIDADES  -  auditoria segura   |",
        "  +-------------------------------------------------+",
        f"{D}  {_state()}{R}",
        f"{G}  Digite  /scan  para configurar/rodar a auditoria.{R}",
        f"{D}  (nada roda fora do escopo autorizado){R}",
        "",
    ]
    print("\n".join(b))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
