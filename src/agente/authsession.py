"""Captura de sessão autenticada — você cola o "Copy as cURL" (DevTools) de uma
requisição JÁ logada; a ferramenta extrai método/URL/headers (cookie/token)/corpo
e passa a testar COMO usuário logado (IDOR/BOLA/rota logada de verdade).

Nunca exibe o token cru em relatório: `redacted_headers()` redige os valores
sensíveis. Guardado por sessão; o teste ativo continua gated por escopo+posse.
"""

from __future__ import annotations

import shlex

from .logging_utils import redact

_NOARG = {"--compressed", "-s", "--silent", "-k", "--insecure", "-i",
          "--include", "-L", "--location", "-v", "--verbose", "-#", "-g",
          "--globoff", "-4", "-6", "--http1.1", "--http2"}
_AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token",
                 "x-csrf-token", "x-xsrf-token")


def _normalize(cmd: str) -> str:
    """Junta continuações de linha (bash \\ , cmd ^) num comando só."""
    cmd = cmd.replace("\\\n", " ").replace("^\n", " ").replace("`\n", " ")
    return cmd.replace("\r", " ").replace("\n", " ").strip()


def parse_curl(cmd: str) -> dict:
    """Extrai {method,url,headers,body} de um comando cURL (formato bash do
    DevTools). Robusto a aspas e flags sem argumento."""
    try:
        toks = shlex.split(_normalize(cmd), posix=True)
    except ValueError:
        toks = _normalize(cmd).split()
    url, method, body = None, None, ""
    headers: dict = {}
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == "curl":
            i += 1; continue
        if t in ("-H", "--header") and i + 1 < len(toks):
            k, _, v = toks[i + 1].partition(":")
            if k.strip():
                headers[k.strip()] = v.strip()
            i += 2; continue
        if t in ("-b", "--cookie") and i + 1 < len(toks):
            headers["Cookie"] = toks[i + 1]; i += 2; continue
        if t in ("-X", "--request") and i + 1 < len(toks):
            method = toks[i + 1].upper(); i += 2; continue
        if t in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
                 "--data-urlencode") and i + 1 < len(toks):
            body = toks[i + 1]; i += 2; continue
        if t in ("-A", "--user-agent") and i + 1 < len(toks):
            headers["User-Agent"] = toks[i + 1]; i += 2; continue
        if t in ("-e", "--referer") and i + 1 < len(toks):
            headers["Referer"] = toks[i + 1]; i += 2; continue
        if t in _NOARG:
            i += 1; continue
        if t.startswith("-"):
            # flag desconhecida: pula o argumento se houver
            i += 2 if (i + 1 < len(toks) and not toks[i + 1].startswith("-")) else 1
            continue
        if url is None and t.lower().startswith(("http://", "https://")):
            url = t
        i += 1
    if method is None:
        method = "POST" if body else "GET"
    return {"method": method, "url": url or "", "headers": headers, "body": body}


def cookie_header(cookie: str) -> dict:
    return {"Cookie": cookie.strip()} if cookie.strip() else {}


def has_auth(headers: dict) -> bool:
    low = {k.lower() for k in headers}
    return any(a in low for a in _AUTH_HEADERS)


def redacted_headers(headers: dict) -> dict:
    """Cópia com valores sensíveis redigidos (p/ relatório/log)."""
    out = {}
    for k, v in headers.items():
        out[k] = "***REDACTED***" if k.lower() in _AUTH_HEADERS else redact(v)
    return out
