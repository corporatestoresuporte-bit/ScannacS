"""Executor controlado — o único caminho legítimo para ações externas.

Toda execução externa (comandos de rede, ferramentas de scan, fetch web) deve
passar por aqui. A política:

  1. Enquanto o escopo não estiver AUTORIZADO, comandos de rede são negados.
  2. Autorizado, um comando de rede só passa se TODOS os hosts-alvo estiverem
     no escopo (match exato pelo host do alvo). Fora do escopo => negado.
  3. Rate-limit por alvo (balde compartilhado) evita que vários agentes
     estourem juntos o limite definido.
  4. Arquivos de configuração autorizada e de evidência são protegidos contra
     escrita/remoção por comandos (anti-adulteração pelos investigadores).

A extração de host a partir de linha de comando é heurística e assume falha
fechada: na dúvida sobre um comando de rede, nega. Comandos locais inofensivos
(ls, cat, python -m agente, git ...) passam para não travar o coordenador.
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass

from .scope import Scope

# Ferramentas que caracterizam ação de REDE / externa.
NETWORK_TOOLS = {
    "curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp",
    "ftp", "nmap", "masscan", "nikto", "sqlmap", "ffuf", "gobuster", "dirb",
    "wfuzz", "httpx", "nuclei", "whatweb", "wpscan", "amass", "subfinder",
    "dnsx", "dig", "nslookup", "host", "ping", "traceroute", "tracert",
    "openssl", "sslscan", "sslyze", "testssl", "testssl.sh", "hydra",
    "medusa", "nc.exe", "curl.exe",
}

# Caminhos protegidos contra escrita por comandos.
PROTECTED_SUBSTRINGS = (
    "config/scope.toml",
    "config\\scope.toml",
    "config/settings.toml",
    "config\\settings.toml",
    "findings.json",
    "evidence.json",
    "session.json",
    "/artifacts/",
    "\\artifacts\\",
)

# Padrões de escrita/remoção perigosos.
_WRITE_PATTERNS = [
    re.compile(r"\brm\b"),
    re.compile(r"\bmv\b"),
    re.compile(r"\bcp\b"),
    re.compile(r"\btee\b"),
    re.compile(r"\bsed\b\s+-i"),
    re.compile(r">>?"),          # redirecionamento
    re.compile(r"Remove-Item", re.I),
    re.compile(r"Set-Content", re.I),
    re.compile(r"Out-File", re.I),
]

_URL_RE = re.compile(r"https?://([^/\s:\"']+)", re.I)
_HOSTISH_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.I)
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


@dataclass
class Decision:
    allow: bool
    reason: str = ""
    targets: tuple[str, ...] = ()


def _first_token(command: str) -> str:
    cmd = command.strip()
    # remove prefixos comuns de shell
    for lead in ("sudo ", "time ", "env "):
        if cmd.lower().startswith(lead):
            cmd = cmd[len(lead):].strip()
    m = re.match(r"[\"']?([^\s\"']+)", cmd)
    tok = (m.group(1) if m else cmd).lower()
    return tok.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def uses_network(command: str) -> bool:
    """O comando invoca alguma ferramenta de rede/externa?"""
    low = command.lower()
    tokens = set(re.findall(r"[a-z0-9_.-]+", low))
    if tokens & NETWORK_TOOLS:
        return True
    # URL explícita também conta.
    return bool(_URL_RE.search(command))


def extract_hosts(command: str) -> list[str]:
    """Extrai hosts/IPs candidatos de um comando. Heurístico."""
    hosts: list[str] = []
    for m in _URL_RE.finditer(command):
        hosts.append(m.group(1).lower())
    for m in _IPV4_RE.finditer(command):
        hosts.append(m.group(1))
    for m in _HOSTISH_RE.finditer(command):
        h = m.group(1).lower()
        # ignora nomes de arquivo com extensão comum
        if not h.endswith((".py", ".txt", ".json", ".md", ".toml", ".sh",
                            ".ps1", ".cmd", ".log", ".html", ".js", ".ts")):
            hosts.append(h)
    # dedup preservando ordem
    seen: set[str] = set()
    out: list[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _scope_hosts(scope: Scope) -> set[str]:
    hosts: set[str] = set()
    for t in scope.targets:
        v = t.value.strip().lower()
        for pref in ("http://", "https://"):
            if v.startswith(pref):
                v = v[len(pref):]
        hosts.add(v.split("/")[0].split(":")[0])
    return hosts


def _host_in_scope(host: str, scope_hosts: set[str]) -> bool:
    host = host.lower()
    if host in scope_hosts:
        return True
    # IP dentro de algum alvo? (só match exato — sem expandir faixas)
    try:
        ip = ipaddress.ip_address(host)
        return str(ip) in scope_hosts
    except ValueError:
        return False


def touches_protected(command: str) -> bool:
    """Comando tenta escrever/remover arquivo protegido?"""
    if not any(p in command for p in PROTECTED_SUBSTRINGS):
        return False
    return any(p.search(command) for p in _WRITE_PATTERNS)


def decide(command: str, scope: Scope | None) -> Decision:
    """Decide allow/deny para um comando. Falha fechada em ações de rede."""
    if touches_protected(command):
        return Decision(False, "comando tenta alterar configuração autorizada "
                               "ou registro de evidência (protegido)")

    if not uses_network(command):
        return Decision(True, "comando local (sem rede)")

    if scope is None:
        return Decision(False, "escopo não definido — ação de rede bloqueada")

    if not scope.authorized:
        return Decision(False, "escopo não autorizado — ação de rede bloqueada "
                               "até DISPARAR AUDITORIA")

    hosts = extract_hosts(command)
    if not hosts:
        return Decision(False, "ação de rede sem host identificável — negada "
                               "por precaução (falha fechada)")

    scope_hosts = _scope_hosts(scope)
    fora = [h for h in hosts if not _host_in_scope(h, scope_hosts)]
    if fora:
        return Decision(False, f"host(s) fora do escopo: {', '.join(fora)}",
                        targets=tuple(hosts))

    return Decision(True, "alvos dentro do escopo", targets=tuple(hosts))


# -- Rate limiting (balde por alvo, compartilhado entre agentes) --------------

def check_and_consume(limits: dict, host: str, rps: float = 5.0,
                      max_per_run: int = 500) -> tuple[bool, str, dict]:
    """Token bucket simples por host. Devolve (ok, motivo, limits_atualizado).

    - rps: reposição de tokens por segundo.
    - max_per_run: teto absoluto de requisições por alvo na sessão.
    """
    now = time.time()
    b = limits.get(host, {"tokens": rps, "updated": now, "count": 0})
    # repõe tokens
    elapsed = max(0.0, now - b.get("updated", now))
    b["tokens"] = min(rps, b.get("tokens", rps) + elapsed * rps)
    b["updated"] = now

    if b.get("count", 0) >= max_per_run:
        limits[host] = b
        return (False, f"teto de {max_per_run} requisições atingido para {host}", limits)

    if b["tokens"] < 1.0:
        limits[host] = b
        return (False, f"rate-limit: aguarde (host {host} > {rps}/s)", limits)

    b["tokens"] -= 1.0
    b["count"] = b.get("count", 0) + 1
    limits[host] = b
    return (True, "ok", limits)
