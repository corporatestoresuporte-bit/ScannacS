"""Teste de RESISTÊNCIA do login a força-bruta — DEFENSIVO e AUTORIZADO.

Objetivo: provar se a autenticação do SEU próprio alvo aplica proteção
(rate-limit, bloqueio, atraso). Não é ferramenta de invasão: é para confirmar
que o login resiste. Guardrails DUROS (não passam do teto):

  - só host no ESCOPO e com POSSE comprovada (owner_verified);
  - método que muda estado (POST) exige allow_side_effects explícito;
  - CONTAS DE TESTE fornecidas por você (lista curta);
  - tentativas <= MAX_ATTEMPTS; intervalo >= MIN_DELAY; duração <= MAX_DURATION;
  - PARA na hora ao detectar bloqueio (429/403/lockout) OU sucesso.

Nunca grava senha no artefato (redigido). Distingue-se da descoberta de conteúdo
(caminhos) — aqui é tentativa de AUTENTICAÇÃO, com contas de teste e limites.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .evidence import CollectionStatus, Evidence, preserve_artifact
from .findings import Finding, Severity, Status
from .replay import authorized_target
from .scope import _host_of
from .verdict import EvidenceTier

# tetos de segurança — o usuário pode pedir MENOS, nunca MAIS.
MAX_ATTEMPTS = 25
MIN_DELAY = 0.5          # segundos entre tentativas
MAX_DURATION = 120       # segundos no total

_BLOCK_MARKERS = ("too many", "rate limit", "rate-limit", "locked", "lockout",
                  "bloquead", "tente novamente", "try again later",
                  "muitas tentativas", "captcha")
_SUCCESS_MARKERS = ("set-cookie", "token", "dashboard", "bem-vindo", "welcome",
                    "logout", "sair")


@dataclass
class AuthConfig:
    url: str
    body_template: str                 # contém {user} e {pass}
    content_type: str = "json"         # "json" | "form"
    headers: dict = field(default_factory=dict)
    method: str = "POST"


def _render(tmpl: str, user: str, pw: str) -> str:
    return tmpl.replace("{user}", user).replace("{pass}", pw)


def _send(cfg: AuthConfig, user: str, pw: str, timeout: int = 15):
    body = _render(cfg.body_template, user, pw).encode("utf-8")
    ct = ("application/json" if cfg.content_type == "json"
          else "application/x-www-form-urlencoded")
    headers = {"User-Agent": "scannacs-authbf", "Content-Type": ct, **cfg.headers}
    req = urllib.request.Request(cfg.url, data=body, method=cfg.method,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(20_000).decode("utf-8", "replace")
            sc = "set-cookie" in {k.lower() for k in resp.headers.keys()}
            return (resp.status, raw, sc)
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read(20_000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        return (e.code, raw, False)
    except Exception as e:  # noqa: BLE001
        return (None, f"(erro: {e})", False)


def _looks_blocked(status, body: str) -> bool:
    if status in (429, 403):
        return True
    low = (body or "").lower()
    return any(m in low for m in _BLOCK_MARKERS)


def _looks_success(status, body: str, has_cookie: bool, base_status,
                   base_len: int) -> bool:
    if status is None:
        return False
    low = (body or "").lower()
    if status in (301, 302, 303, 307, 308) and has_cookie:
        return True
    if has_cookie and status == 200 and status != base_status:
        return True
    # mudança forte de corpo + marcador de sessão
    if abs(len(body or "") - base_len) > max(80, base_len // 2) and \
            any(m in low for m in _SUCCESS_MARKERS):
        return True
    return False


def run_authbf(session, scope, cfg: AuthConfig, creds: list[tuple[str, str]],
               max_attempts: int = 10, delay: float = 1.0,
               max_duration: int = 60, allow_side_effects: bool = False) -> list[Finding]:
    ok, reason = authorized_target(cfg.url, scope)
    if not ok:
        raise PermissionError(reason)
    if cfg.method.upper() != "GET" and not allow_side_effects:
        raise PermissionError(
            f"{cfg.method} no login muda estado; nenhum envio feito. Use "
            "--com-efeito-colateral (contas de TESTE no SEU alvo).")
    if not creds:
        raise ValueError("informe ao menos uma conta de teste (usuario, senha)")

    # aplica os tetos de segurança
    cap = min(max_attempts, MAX_ATTEMPTS, len(creds))
    delay = max(delay, MIN_DELAY)
    deadline = time.time() + min(max_duration, MAX_DURATION)
    host = _host_of(cfg.url)

    # baseline: credencial claramente errada (assinatura de FALHA)
    b_status, b_body, _bc = _send(cfg, "__scannacs_probe__", "__definitely_wrong__")
    base_len = len(b_body or "")

    log = [{"i": 0, "fase": "baseline", "status": b_status, "len": base_len}]
    blocked_at = None
    success_at = None
    sent = 0
    for idx, (user, pw) in enumerate(creds[:cap], start=1):
        if time.time() > deadline:
            log.append({"i": idx, "nota": "parou: teto de duração"})
            break
        status, body, cookie = _send(cfg, user, pw)
        sent += 1
        entry = {"i": idx, "status": status, "len": len(body or ""),
                 "cookie": cookie}   # sem usuário/senha no artefato
        if _looks_blocked(status, body):
            entry["evento"] = "bloqueio detectado"
            log.append(entry)
            blocked_at = idx
            break                     # PARA: proteção presente (bom)
        if _looks_success(status, body, cookie, b_status, base_len):
            entry["evento"] = "possível sucesso (credencial de teste aceita)"
            log.append(entry)
            success_at = idx
            break                     # PARA: achou credencial fraca
        log.append(entry)
        time.sleep(delay)

    # evidência (sem senhas)
    import json
    raw = json.dumps({"alvo": cfg.url, "tentativas_enviadas": sent,
                      "bloqueio_em": blocked_at, "sucesso_em": success_at,
                      "log": log}, ensure_ascii=False, indent=2)
    ev = Evidence(target=cfg.url, tool="authbf",
                  params=f"login resilience x{sent}", source=cfg.url,
                  result_summary=(f"enviadas={sent} bloqueio={blocked_at} "
                                  f"sucesso={success_at}")[:200],
                  status=CollectionStatus.OK, tier=EvidenceTier.TOOL_OBSERVED)
    stored = session.add_evidence(ev.to_dict())
    ev.id = stored["id"]
    path, digest = preserve_artifact(session.artifacts, ev.id, raw)
    evs = session.evidence()
    for e in evs:
        if e.get("id") == ev.id:
            e["artifact_path"], e["artifact_sha256"] = path, digest
    from .store import write_json
    write_json(session.dir / "evidence.json", evs)

    findings: list[Finding] = []
    if success_at:
        findings.append(Finding(
            target=host, title="Credencial de teste aceita no login",
            status=Status.SUSPECTED, severity=Severity.HIGH,
            impact="Uma das contas de teste autenticou — credencial fraca/padrão.",
            remediation="Remover/!trocar credenciais padrão; exigir senha forte.",
            engine="authbf", evidence_ids=[ev.id]))
    elif blocked_at:
        # proteção presente: NÃO é achado; registra como limitação positiva
        findings.append(Finding(
            target=host, title="Login bloqueou a força-bruta (proteção presente)",
            status=Status.DISMISSED, severity=Severity.INFO,
            impact=f"O login barrou na tentativa {blocked_at} (429/403/lockout).",
            remediation="Nada a fazer — controle anti-brute-force funcionando.",
            engine="authbf", evidence_ids=[ev.id]))
    elif sent >= min(cap, 5):
        findings.append(Finding(
            target=host, title="Login sem proteção anti-força-bruta observável",
            status=Status.SUSPECTED, severity=Severity.MEDIUM,
            impact=f"{sent} tentativas seguidas sem 429/bloqueio — permite "
                   "brute-force/credential-stuffing.",
            remediation="Aplicar rate-limit por IP/conta, bloqueio temporário "
                        "e/ou CAPTCHA após poucas falhas.",
            engine="authbf", evidence_ids=[ev.id]))

    for f in findings:
        session.add_finding(f.to_dict())
    return findings
