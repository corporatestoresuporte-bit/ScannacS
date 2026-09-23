"""Sondas de API moderna: GraphQL e WebSocket (leitura, autorizado).

GraphQL: descobre o endpoint e checa se a INTROSPECTION está exposta (o "mapa"
completo da API — normalmente desligado em produção). Só envia a query de
introspection (leitura), nunca mutation.

WebSocket: acha URLs ws://|wss:// no HTML/JS e faz o HANDSHAKE (Upgrade) sem
credencial — se o servidor responder 101, o endpoint aceita conexão anônima
(indício, precisa checar se troca dados sensíveis depois).

Gated por escopo+posse (via engine/executor). Nada de payload destrutivo.
"""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import urllib.request
from urllib.parse import urlsplit

from .engines import _BROWSER_HEADERS, _fetch

_GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1",
              "/query", "/gql", "/api/gql", "/graphql/console"]
_INTROSPECTION = '{"query":"{__schema{queryType{name} types{name}}}"}'
_WS_RE = re.compile(r"""(wss?://[A-Za-z0-9._\-:/%?=&]+)""", re.I)


def _base(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def graphql_introspection(endpoint: str, timeout: int = 12) -> dict:
    """Envia a introspection. Devolve {status, enabled, types, endpoint}."""
    data = _INTROSPECTION.encode("utf-8")
    headers = {**_BROWSER_HEADERS, "Content-Type": "application/json"}
    req = urllib.request.Request(endpoint, data=data, method="POST",
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(200_000).decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        try:
            body = e.read(50_000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            body = ""
        status = e.code
    except Exception as e:  # noqa: BLE001
        return {"endpoint": endpoint, "status": None, "enabled": False,
                "types": 0, "err": str(e)}
    enabled = '"__schema"' in body or '"queryType"' in body
    types = 0
    if enabled:
        try:
            d = json.loads(body)
            types = len(((d.get("data") or {}).get("__schema") or {}).get("types") or [])
        except Exception:  # noqa: BLE001
            types = body.count('"name"')
    return {"endpoint": endpoint, "status": status, "enabled": enabled,
            "types": types}


def discover_graphql(base_url: str, timeout: int = 12) -> list[dict]:
    """Testa caminhos comuns; devolve os que respondem à introspection."""
    base = _base(base_url)
    out = []
    for path in _GQL_PATHS:
        r = graphql_introspection(base + path, timeout=timeout)
        if r.get("enabled"):
            out.append(r)
    return out


def find_ws_urls(text: str, base_url: str = "") -> list[str]:
    urls = []
    seen = set()
    for m in _WS_RE.findall(text or ""):
        u = m.rstrip('"\'',)
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def ws_handshake(ws_url: str, timeout: int = 10) -> dict:
    """Faz o Upgrade WebSocket sem credencial. Devolve {status, accepted}."""
    p = urlsplit(ws_url)
    host = p.hostname or ""
    secure = p.scheme == "wss"
    port = p.port or (443 if secure else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
           f"User-Agent: {_BROWSER_HEADERS['User-Agent']}\r\n\r\n")
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        sock = ssl.create_default_context().wrap_socket(
            raw, server_hostname=host) if secure else raw
        sock.sendall(req.encode())
        resp = sock.recv(1024).decode("utf-8", "replace")
        sock.close()
    except Exception as e:  # noqa: BLE001
        return {"url": ws_url, "status": None, "accepted": False, "err": str(e)}
    first = resp.splitlines()[0] if resp else ""
    accepted = "101" in first and "switching protocols" in first.lower()
    status = 101 if accepted else (int(re.search(r"\b(\d{3})\b", first).group(1))
                                   if re.search(r"\b(\d{3})\b", first) else None)
    return {"url": ws_url, "status": status, "accepted": accepted}
