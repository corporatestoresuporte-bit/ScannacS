"""Handler do PreToolUse — a barreira que o Claude Code chama antes de cada
ferramenta. É o ponto onde o executor controlado é IMPOSTO na sessão: nenhum
agente contorna o escopo por um caminho alternativo.

Doutrina de barreira adaptada de RAPTOR (MIT):
  .claude/hooks/bash-command-allowlist.py + webfetch-domain-allowlist.py
  (rejeição de metacaracteres / substituição de comando, falha fechada).
  https://github.com/gadievron/raptor (commit a1996f8). Ver docs/integracoes.md.

Contrato do hook (Claude Code): lê JSON no stdin com tool_name e tool_input.
Para NEGAR: sai com código 2 e escreve o motivo no stderr (o texto volta ao
agente). Para PERMITIR: sai 0.
"""

from __future__ import annotations

import json
import re
import sys

from . import scope as scope_mod
from .executor import check_and_consume, decide, extract_hosts, uses_network
from .store import Session

# Substituição de comando escondendo alvo em ação de rede => negar.
_CMD_SUBST = re.compile(r"\$\(|`|\$\{")

# Domínios de pesquisa permitidos para WebFetch (consulta de CVE etc.),
# mesmo fora do escopo de alvos — é pesquisa, não ação contra o alvo.
RESEARCH_HOSTS = {
    "nvd.nist.gov", "cve.mitre.org", "www.cve.org", "cve.org",
    "first.org", "www.first.org", "cwe.mitre.org", "owasp.org",
    "www.exploit-db.com", "exploit-db.com",
}

DENY = 2
ALLOW = 0


def _deny(reason: str) -> int:
    sys.stderr.write(f"[executor-controlado] BLOQUEADO: {reason}\n")
    return DENY


def _host_of_url(url: str) -> str:
    m = re.match(r"https?://([^/\s:\"']+)", url, re.I)
    return (m.group(1).lower() if m else "")


def handle(payload: dict) -> int:
    tool = payload.get("tool_name") or payload.get("tool") or ""
    ti = payload.get("tool_input") or payload.get("toolInput") or {}
    scope = scope_mod.load_scope()

    # ---- Bash ------------------------------------------------------------
    if tool == "Bash":
        command = ti.get("command", "") if isinstance(ti, dict) else str(ti)
        if uses_network(command) and _CMD_SUBST.search(command):
            return _deny("substituição de comando em ação de rede "
                         "(alvo pode estar escondido) — falha fechada")
        d = decide(command, scope)
        if not d.allow:
            return _deny(d.reason)
        # rate-limit compartilhado por alvo
        if d.targets:
            sess = Session.active()
            if sess is not None:
                limits = sess.limits()
                rps = 5.0
                maxrun = 500
                st = scope_mod.load_scope()
                for h in d.targets:
                    ok, reason, limits = check_and_consume(limits, h, rps, maxrun)
                    if not ok:
                        sess.save_limits(limits)
                        return _deny(reason)
                sess.save_limits(limits)
        return ALLOW

    # ---- WebFetch --------------------------------------------------------
    if tool == "WebFetch":
        url = ti.get("url", "") if isinstance(ti, dict) else str(ti)
        host = _host_of_url(url)
        if host in RESEARCH_HOSTS:
            return ALLOW
        if scope is None or not scope.authorized:
            return _deny("WebFetch bloqueado — escopo não autorizado "
                         "(só pesquisa de referência é permitida antes disso)")
        from .executor import _host_in_scope, _scope_hosts
        if host and _host_in_scope(host, _scope_hosts(scope)):
            return ALLOW
        return _deny(f"WebFetch fora do escopo: {host or url}")

    # ---- WebSearch e demais: pesquisa/local, permitido -------------------
    return ALLOW


def _audit(tool: str, rc: int) -> None:
    """Trilha de auditoria: registra que o hook FOI chamado e a decisão.
    Só acrescenta — nunca lê/decide por aqui. Falha em silêncio (não brica)."""
    try:
        import datetime as _dt

        from . import config as _cfg
        _cfg.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        line = json.dumps({
            "ts": _dt.datetime.now().isoformat(timespec="seconds"),
            "tool": tool or "?",
            "decisao": "permitido" if rc == ALLOW else "bloqueado",
            "rc": rc,
        }, ensure_ascii=False)
        with open(_cfg.LOGS_DIR / "hook-audit.log", "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    raw = ""
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        rc = handle(payload)
        _audit(payload.get("tool_name") or payload.get("tool") or "", rc)
        return rc
    except Exception:  # nunca brica a sessão; falha fechada só se cheirar a rede
        low = raw.lower()
        if any(t in low for t in ("curl", "http://", "https://", "nmap", "wget",
                                  "sqlmap", "nuclei", "ssh ")):
            return _deny("entrada do hook ilegível em ação de rede — negado "
                         "por precaução")
        return ALLOW


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
