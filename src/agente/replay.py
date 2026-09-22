"""Replay/IDOR ao vivo — teste ATIVO e AUTORIZADO de abuso de lógica/API.

Você captura UMA requisição autenticada (DevTools > Copy > ...) e salva num
JSON; a ferramenta manda variações dela para diagnosticar a classe que scanner
genérico não pega:

  - sem-auth : remove Authorization/Cookie -> ainda responde com dados?
  - idor     : troca o id/e-mail do objeto -> volta dado de outro usuário?
  - mass     : injeta campo de privilégio no corpo (role/is_admin) -> aceita?
  - rate     : rajada curta -> aparece 429/limite?

REGRAS (impostas):
  - só roda contra host no ESCOPO e com POSSE comprovada (owner_verified);
  - por padrão só métodos seguros (GET/HEAD); métodos que mudam estado
    (POST/PUT/PATCH/DELETE) exigem --com-efeito-colateral (pode criar/alterar
    dados no SEU app);
  - cada resultado é SUSPEITA, com a resposta preservada (redigida) como
    evidência; quem confirma é o validador.

Formato do JSON de requisição:
  {
    "method": "GET",
    "url": "https://alvo/api/orders?email=eu@x.com",
    "headers": {"Authorization": "Bearer ...", "Content-Type": "application/json"},
    "body": "",                # string (ex.: JSON) ou ""
    "fuzz_param": "email"      # (opcional) campo/param a variar no teste idor
  }
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .evidence import CollectionStatus, Evidence, preserve_artifact
from .findings import ConfirmationType, Finding, Severity, Status
from .scope import Scope, _host_of
from .verdict import EvidenceTier

SAFE_METHODS = {"GET", "HEAD"}
_AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token")


@dataclass
class Req:
    method: str
    url: str
    headers: dict
    body: str = ""
    fuzz_param: str = ""


def load_request(path: Path) -> Req:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return Req(method=str(d.get("method", "GET")).upper(),
               url=str(d["url"]),
               headers=dict(d.get("headers", {})),
               body=str(d.get("body", "") or ""),
               fuzz_param=str(d.get("fuzz_param", "")))


def authorized_target(url: str, scope: Scope | None) -> tuple[bool, str]:
    """Só libera host no escopo E com posse comprovada."""
    if scope is None:
        return (False, "escopo não definido")
    host = _host_of(url)
    for t in scope.targets:
        if _host_of(t.value) == host:
            if not t.owner_verified:
                return (False, f"posse de {host} não comprovada "
                               "(rode `agente scope verify`)")
            return (True, "ok")
    return (False, f"host {host} fora do escopo")


def _send(method: str, url: str, headers: dict, body: str,
          timeout: int = 20) -> tuple[int | None, str, CollectionStatus]:
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": "agente-auditoria",
                                          **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(200_000).decode("utf-8", "replace")
            return (resp.status, raw, CollectionStatus.OK)
    except urllib.error.HTTPError as e:  # noqa: PERF203
        try:
            raw = e.read(50_000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            raw = ""
        return (e.code, raw, CollectionStatus.OK)
    except Exception as e:  # noqa: BLE001
        return (None, f"(erro: {e})", CollectionStatus.ERROR)


def _strip_auth(headers: dict) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in _AUTH_HEADERS}


def _swap_param(url: str, body: str, param: str, marker: str) -> tuple[str, str]:
    """Troca param na query e no corpo por um marcador (teste de IDOR)."""
    new_url = re.sub(rf"([?&]{re.escape(param)}=)[^&]*", rf"\g<1>{marker}", url)
    new_body = body
    if body:
        new_body = re.sub(rf'("{re.escape(param)}"\s*:\s*")[^"]*(")',
                          rf"\g<1>{marker}\g<2>", body)
    return (new_url, new_body)


def _evidence(session, req_desc: str, url: str, status, raw: str,
              summary: str, tier=EvidenceTier.TOOL_OBSERVED) -> str:
    ev = Evidence(target=_host_of(url), tool="replay", params=req_desc, source=url,
                  result_summary=summary[:200], status=CollectionStatus.OK,
                  tier=tier, exit_code=status if isinstance(status, int) else None)
    stored = session.add_evidence(ev.to_dict())
    ev.id = stored["id"]
    path, digest = preserve_artifact(session.artifacts, ev.id,
                                     f"[{req_desc}] status={status}\n\n{raw}")
    evs = session.evidence()
    for e in evs:
        if e.get("id") == ev.id:
            e["artifact_path"], e["artifact_sha256"] = path, digest
    from .store import write_json
    write_json(session.dir / "evidence.json", evs)
    return ev.id


def _looks_like_data(status, raw: str) -> bool:
    return isinstance(status, int) and status == 200 and len(raw.strip()) > 40


def run_replay(session, scope: Scope | None, req: Req, tests: list[str],
               fuzz_value: str = "__idor_probe__",
               allow_side_effects: bool = False, rate_n: int = 12) -> list[Finding]:
    ok, reason = authorized_target(req.url, scope)
    if not ok:
        raise PermissionError(reason)

    state_changing = req.method not in SAFE_METHODS
    findings: list[Finding] = []

    # baseline (requisição original)
    base_status, base_raw, _ = _send(req.method, req.url, req.headers, req.body)
    base_id = _evidence(session, f"{req.method} baseline", req.url, base_status,
                        base_raw, f"baseline status={base_status}")

    # 1) sem autenticação
    if "no-auth" in tests or "sem-auth" in tests:
        s, raw, _ = _send(req.method, req.url, _strip_auth(req.headers), req.body)
        eid = _evidence(session, f"{req.method} SEM auth", req.url, s, raw,
                        f"sem-auth status={s}")
        if _looks_like_data(s, raw):
            findings.append(Finding(
                target=_host_of(req.url),
                title="Endpoint responde SEM autenticação (dados retornados)",
                status=Status.SUSPECTED, severity=Severity.HIGH,
                impact="Rota devolve dados sem token/cookie = acesso não "
                       "autenticado.",
                remediation="Exigir sessão/token válido antes de responder.",
                engine="replay", evidence_ids=[eid, base_id]))

    # 2) IDOR/BOLA (troca do id/e-mail do objeto)
    if ("idor" in tests) and req.fuzz_param:
        val = fuzz_value
        u2, b2 = _swap_param(req.url, req.body, req.fuzz_param, val)
        s, raw, _ = _send(req.method, u2, req.headers, b2)
        eid = _evidence(session, f"IDOR {req.fuzz_param}={val}", u2, s, raw,
                        f"idor status={s}")
        if _looks_like_data(s, raw):
            findings.append(Finding(
                target=_host_of(req.url),
                title=f"Possível IDOR/BOLA em '{req.fuzz_param}' (objeto de outro)",
                status=Status.SUSPECTED, severity=Severity.HIGH,
                impact="Trocar o identificador retornou dados de outro objeto/"
                       "usuário — checar se é dado alheio.",
                remediation="Validar no servidor que o objeto pertence ao "
                            "usuário autenticado (auth.uid()).",
                engine="replay", evidence_ids=[eid, base_id]))

    # 3) mass assignment (injeta privilégio no corpo)
    if "mass" in tests:
        if state_changing and not allow_side_effects:
            findings.append(Finding(
                target=_host_of(req.url),
                title="Teste de mass assignment pulado (método muda estado)",
                status=Status.NOT_CHECKED, severity=Severity.INFO,
                impact="Não testado para evitar efeito colateral.",
                remediation="Reexecutar com --com-efeito-colateral se for seguro.",
                engine="replay"))
        else:
            probe = "__probe_admin__"
            body = req.body or "{}"
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    obj["role"] = probe
                    obj["is_admin"] = True
                    inj = json.dumps(obj)
                else:
                    inj = body
            except json.JSONDecodeError:
                inj = body
            s, raw, _ = _send(req.method, req.url, req.headers, inj)
            eid = _evidence(session, f"{req.method} mass-assignment", req.url, s,
                            raw, f"mass status={s}")
            if probe in raw or '"is_admin":true' in raw.replace(" ", "").lower():
                findings.append(Finding(
                    target=_host_of(req.url),
                    title="Possível mass assignment (campo de privilégio aceito)",
                    status=Status.SUSPECTED, severity=Severity.CRITICAL,
                    impact="Servidor refletiu/aceitou role/is_admin do corpo = "
                           "escalada de privilégio.",
                    remediation="Aceitar só allowlist de campos; definir papel "
                                "no servidor.",
                    engine="replay", evidence_ids=[eid, base_id]))

    # 4) rate-limit (rajada curta)
    if "rate" in tests:
        codes = []
        for _ in range(max(3, rate_n)):
            s, _r, _st = _send(req.method, req.url, req.headers, req.body, timeout=10)
            codes.append(s)
            time.sleep(0.05)
        limited = any(c == 429 for c in codes)
        eid = _evidence(session, f"rate x{len(codes)}", req.url, codes[-1],
                        f"codigos: {codes}",
                        f"rate: 429? {'sim' if limited else 'nao'}")
        if not limited:
            findings.append(Finding(
                target=_host_of(req.url),
                title="Sem rate-limit observado (nenhum 429 na rajada)",
                status=Status.SUSPECTED, severity=Severity.MEDIUM,
                impact="Sem limite, dá para brute-force de login e abuso de API.",
                remediation="Aplicar rate-limit por IP/rota, sobretudo no login.",
                engine="replay", evidence_ids=[eid]))

    for f in findings:
        session.add_finding(f.to_dict())
    return findings
