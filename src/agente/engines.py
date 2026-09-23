"""Motores de scan — "liga" as ferramentas de auditoria.

Dois tipos:
  - EMBUTIDOS (sempre disponíveis, stdlib): cabeçalhos de segurança, TLS,
    fingerprint HTTP. Não dependem de instalar nada.
  - FERRAMENTAS EXTERNAS (rodam SE instaladas): nmap, nuclei, sqlmap, sslyze,
    nikto, whatweb, dig, gobuster, ffuf, wpscan. Sem a ferramenta => registro
    de LIMITAÇÃO (verificação inconclusiva), nunca achado inventado.

Regras impostas aqui (spec §7/§8):
  - Só roda contra alvo EXATO do escopo, e cada comando passa pelo executor
    controlado (executor.decide) + rate-limit compartilhado por alvo.
  - Toda saída vira EVIDÊNCIA com artefato preservado (redigido).
  - Interpretação gera SUSPEITA (nunca confirma sozinha; quem confirma é o
    validador, via findings.can_confirm).
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import config
from .evidence import CollectionStatus, Evidence, preserve_artifact
from .executor import check_and_consume, decide, uses_network
from .findings import Finding, Severity, Status
from .scope import Scope, Target
from .verdict import EvidenceTier

WORDLIST = config.WORDLIST   # empacotada no pacote (resolve instalado tb)

# Ferramentas externas conhecidas (nome do binário no PATH).
EXTERNAL_TOOLS = [
    "nmap", "nuclei", "sqlmap", "sslyze", "nikto", "whatweb", "dig",
    "gobuster", "ffuf", "wpscan", "testssl", "wafw00f", "openssl", "curl",
]


def detect_tools() -> dict[str, bool]:
    """Quais ferramentas externas estão instaladas (no PATH)."""
    return {t: shutil.which(t) is not None for t in EXTERNAL_TOOLS}


def _host(t: Target) -> str:
    v = t.value.strip().lower()
    for p in ("http://", "https://"):
        if v.startswith(p):
            v = v[len(p):]
    return v.split("/")[0].split(":")[0]


def _url(t: Target) -> str:
    v = t.value.strip()
    if v.startswith(("http://", "https://")):
        return v
    return "https://" + v


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EngineResult:
    evidence: Evidence
    suspicions: list[Finding] = field(default_factory=list)


class Engine:
    """Base de um motor. `keys` casa com allowed_tests do alvo."""

    name = "engine"
    keys: tuple[str, ...] = ()
    requires: str | None = None   # ferramenta externa exigida, se houver
    timeout: int = 120            # teto de tempo por execução (s)

    def available(self) -> bool:
        return self.requires is None or shutil.which(self.requires) is not None

    def command(self, target: Target) -> str:
        raise NotImplementedError

    def interpret(self, target: Target, raw: str, status: CollectionStatus) -> list[Finding]:
        return []

    def tier(self) -> EvidenceTier:
        return EvidenceTier.TOOL_OBSERVED


# Cabeçalhos de navegador real: WAF (Cloudflare/Vercel) devolve 403 pra UA de
# bot e às vezes pra HEAD. Usar isto + fallback HEAD->GET evita "sem-acesso".
_BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/125.0.0.0 Safari/537.36"),
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,*/*;q=0.8"),
    "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
}


def _fetch(url: str, timeout: int = 15, method: str = "GET",
           want_body: bool = False):
    """GET/HEAD com cara de navegador. Se HEAD levar 403/405, cai pra GET.
    Devolve (status, headers_dict, body_or_'', err_or_None)."""
    for m in ([method, "GET"] if method == "HEAD" else [method]):
        req = urllib.request.Request(url, method=m, headers=_BROWSER_HEADERS)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = (resp.read(400_000).decode("utf-8", "replace")
                        if want_body else "")
                return (resp.status, dict(resp.headers.items()), body, None)
        except urllib.error.HTTPError as e:
            if m == "HEAD" and e.code in (403, 405):
                continue  # tenta GET
            body = ""
            try:
                body = e.read(200_000).decode("utf-8", "replace") if want_body else ""
            except Exception:  # noqa: BLE001
                pass
            return (e.code, dict(e.headers.items()) if e.headers else {}, body, None)
        except Exception as e:  # noqa: BLE001
            return (None, {}, "", str(e))
    return (None, {}, "", "sem resposta")


# ------------------------------------------------------------------ embutidos
class HeadersEngine(Engine):
    name = "cabecalhos-seguranca"
    keys = ("headers", "cabecalhos", "cabecalhos-seguranca", "security-headers")

    def command(self, target: Target) -> str:
        return f"[builtin] GET {_url(target)} (cabeçalhos)"

    def collect(self, target: Target) -> tuple[str, CollectionStatus]:
        status, hdrs, _body, err = _fetch(_url(target), method="HEAD")
        if err is not None:
            return (f"(erro/sem-acesso: {err})", CollectionStatus.NO_ACCESS)
        if status is not None and status >= 400:
            # respondeu, mas negou (ex.: 403 WAF): ainda dá pra ler os headers
            if not hdrs:
                return (f"(erro/sem-acesso: HTTP {status})", CollectionStatus.NO_ACCESS)
        raw = f"status: {status}\n" + "\n".join(f"{k}: {v}" for k, v in hdrs.items())
        return (raw, CollectionStatus.OK)

    def interpret(self, target, raw, status):
        if status != CollectionStatus.OK:
            return []
        low = raw.lower()
        faltam = [h for h, k in (
            ("Strict-Transport-Security", "strict-transport-security"),
            ("Content-Security-Policy", "content-security-policy"),
            ("X-Frame-Options", "x-frame-options"),
            ("X-Content-Type-Options", "x-content-type-options"),
        ) if k not in low]
        out = []
        for h in faltam:
            out.append(Finding(
                target=target.value, title=f"Cabeçalho de segurança ausente: {h}",
                status=Status.SUSPECTED, severity=Severity.LOW,
                impact=f"Sem {h}, o navegador perde uma proteção.",
                remediation=f"Configurar o cabeçalho {h}.",
                engine=self.name))
        return out


class TlsEngine(Engine):
    name = "tls"
    keys = ("tls", "ssl", "certificado")

    def command(self, target: Target) -> str:
        return f"[builtin] TLS handshake {_host(target)}:443"

    def collect(self, target: Target) -> tuple[str, CollectionStatus]:
        host = _host(target)
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=15) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    proto = ss.version()
        except Exception as e:  # noqa: BLE001
            return (f"(erro/sem-acesso: {e})", CollectionStatus.NO_ACCESS)
        raw = f"protocolo: {proto}\nvalido_ate: {cert.get('notAfter')}\n" \
              f"emissor: {cert.get('issuer')}\nsubject: {cert.get('subject')}"
        return (raw, CollectionStatus.OK)

    def interpret(self, target, raw, status):
        if status != CollectionStatus.OK:
            return []
        out = []
        if "TLSv1.0" in raw or "TLSv1.1" in raw:
            out.append(Finding(
                target=target.value, title="Protocolo TLS obsoleto em uso",
                status=Status.SUSPECTED, severity=Severity.MEDIUM,
                impact="TLS 1.0/1.1 são fracos.",
                remediation="Exigir TLS 1.2+.", engine=self.name))
        return out


class HttpFingerprintEngine(Engine):
    name = "http-fingerprint"
    keys = ("http", "fingerprint", "recon", "recon-passivo")

    def command(self, target: Target) -> str:
        return f"[builtin] fingerprint {_url(target)}"

    def collect(self, target: Target) -> tuple[str, CollectionStatus]:
        status, hdrs, _body, err = _fetch(_url(target), method="GET")
        if err is not None:
            return (f"(erro/sem-acesso: {err})", CollectionStatus.NO_ACCESS)
        raw = f"status: {status}\n" + "\n".join(f"{k}: {v}" for k, v in hdrs.items())
        return (raw, CollectionStatus.OK)


# ------------------------------------------- auditoria do bundle/JS (segredo SPA)
_SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
_INLINE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)

# formatos de segredo de ALTA confiança que NUNCA deveriam ir pro cliente.
# (anon key do Supabase é pública por design -> NÃO entra aqui.)
_BUNDLE_SECRETS = [
    ("Stripe secret (sk_live/sk_test)", "critica",
     re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}")),
    ("AWS access key id", "critica", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", "critica", re.compile(r"\bghp_[A-Za-z0-9]{20,}")),
    ("Google API key", "alta", re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}")),
    ("Chave privada (PEM)", "critica",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
_JWT = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{4,}")


def _jwt_is_service_role(tok: str) -> bool:
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = base64.urlsafe_b64decode(payload).decode("utf-8", "replace")
        return '"role":"service_role"' in data.replace(" ", "")
    except Exception:  # noqa: BLE001
        return False


def _scan_bundle_secrets(text: str) -> list[dict]:
    """Acha segredos de alta confiança. Devolve tipo+severidade+amostra REDIGIDA
    (nunca o segredo cru)."""
    hits: list[dict] = []
    seen: set = set()
    for label, sev, rx in _BUNDLE_SECRETS:
        for m in rx.finditer(text):
            val = m.group(0)
            key = (label, val[:12])
            if key in seen:
                continue
            seen.add(key)
            hits.append({"tipo": label, "sev": sev,
                         "amostra": val[:6] + "…(redigido)"})
    for m in _JWT.finditer(text):
        tok = m.group(0)
        if _jwt_is_service_role(tok):
            key = ("service_role", tok[:12])
            if key in seen:
                continue
            seen.add(key)
            hits.append({"tipo": "Supabase service_role key (JWT)",
                         "sev": "critica", "amostra": "eyJ…(redigido)"})
    return hits


class BundleAuditEngine(Engine):
    """Baixa o HTML + os scripts MESMO-ORIGEM (leitura) e procura segredo que
    vazou pro cliente. É o risco real de SPA/Supabase que scan externo não pega."""
    name = "bundle-audit"
    keys = ("bundle", "js", "segredo-bundle", "bundle-audit")

    def command(self, target: Target) -> str:
        return f"[builtin] auditoria de segredo no bundle {_url(target)}"

    def _same_origin_srcs(self, html: str, base: str, host: str) -> list[str]:
        from urllib.parse import urljoin, urlparse
        out, seen = [], set()
        for src in _SCRIPT_SRC.findall(html):
            full = urljoin(base, src)
            if urlparse(full).hostname == host and full not in seen:
                seen.add(full)
                out.append(full)
        return out

    def collect(self, target: Target) -> tuple[str, CollectionStatus]:
        base = _url(target)
        host = _host(target)
        status, _h, html, err = _fetch(base, want_body=True)
        if err is not None:
            return (f"(erro/sem-acesso: {err})", CollectionStatus.NO_ACCESS)
        secrets: list[dict] = []
        # scripts inline
        for inline in _INLINE.findall(html or ""):
            for hit in _scan_bundle_secrets(inline):
                secrets.append({**hit, "arquivo": "(inline no HTML)"})
        srcs = self._same_origin_srcs(html or "", base, host)
        scanned = 0
        for s in srcs[:25]:            # teto de arquivos
            st, _hh, body, e = _fetch(s, want_body=True, timeout=20)
            if e is not None or not body:
                continue
            scanned += 1
            for hit in _scan_bundle_secrets(body):
                secrets.append({**hit, "arquivo": s})
        raw = json.dumps({"scripts_encontrados": len(srcs),
                          "scripts_lidos": scanned,
                          "segredos": secrets}, ensure_ascii=False, indent=2)
        return (raw, CollectionStatus.OK)

    def interpret(self, target, raw, status):
        if status != CollectionStatus.OK:
            return []
        try:
            d = json.loads(raw)
        except Exception:  # noqa: BLE001
            return []
        sevmap = {"critica": Severity.CRITICAL, "alta": Severity.HIGH,
                  "media": Severity.MEDIUM}
        out = []
        for s in d.get("segredos", []):
            out.append(Finding(
                target=target.value,
                title=f"Segredo no bundle do cliente: {s['tipo']}",
                status=Status.SUSPECTED,
                severity=sevmap.get(s.get("sev"), Severity.HIGH),
                impact="Segredo servido no JS do navegador — qualquer visitante "
                       f"consegue ler ({s.get('arquivo','')}).",
                remediation="Tirar o segredo do front; usar backend/variável "
                            "server-side; ROTACIONAR a chave exposta.",
                engine=self.name))
        return out


class ApiProbeEngine(Engine):
    """GraphQL (introspection) + WebSocket (handshake sem auth). Leitura."""
    name = "api-graphql-ws"
    keys = ("graphql", "websocket", "ws", "api-moderna", "api-graphql-ws")

    def command(self, target: Target) -> str:
        return f"[builtin] GraphQL/WebSocket probe {_url(target)}"

    def collect(self, target: Target) -> tuple[str, CollectionStatus]:
        from . import apiprobe
        base = _url(target)
        host = _host(target)
        _s, _h, html, err = _fetch(base, want_body=True)
        gql = apiprobe.discover_graphql(base)
        ws_urls = apiprobe.find_ws_urls(html or "")
        for s in BundleAuditEngine()._same_origin_srcs(html or "", base, host)[:15]:
            _st, _hh, body, e = _fetch(s, want_body=True, timeout=20)
            if e is None and body:
                ws_urls += apiprobe.find_ws_urls(body)
        ws_urls = list(dict.fromkeys(ws_urls))[:5]
        ws = [apiprobe.ws_handshake(w) for w in ws_urls]
        raw = json.dumps({"graphql": gql, "ws": ws, "ws_urls": ws_urls},
                         ensure_ascii=False, indent=2)
        return (raw, CollectionStatus.OK)

    def interpret(self, target, raw, status):
        if status != CollectionStatus.OK:
            return []
        try:
            d = json.loads(raw)
        except Exception:  # noqa: BLE001
            return []
        out = []
        for g in d.get("graphql", []):
            if g.get("enabled"):
                out.append(Finding(
                    target=target.value,
                    title="GraphQL com introspection habilitada",
                    status=Status.SUSPECTED, severity=Severity.MEDIUM,
                    impact=f"O schema inteiro da API está exposto ({g.get('types')} "
                           f"tipos) em {g.get('endpoint')} — facilita mapear ataques.",
                    remediation="Desabilitar introspection em produção; exigir auth "
                                "no endpoint GraphQL.", engine=self.name))
        for w in d.get("ws", []):
            if w.get("accepted"):
                out.append(Finding(
                    target=target.value,
                    title="WebSocket aceita conexão sem autenticação",
                    status=Status.SUSPECTED, severity=Severity.MEDIUM,
                    impact=f"Handshake 101 em {w.get('url')} sem credencial — "
                           "verificar se troca dados sensíveis sem autenticar.",
                    remediation="Exigir token/sessão no handshake; validar origem.",
                    engine=self.name))
        return out


# ---------------------------------------------------------- ferramentas externas
class ExternalToolEngine(Engine):
    """Wrapper genérico: roda o binário se existir; senão, limitação."""

    def __init__(self, name, keys, requires, template, tier=EvidenceTier.TOOL_OBSERVED,
                 timeout=120):
        self.name = name
        self.keys = keys
        self.requires = requires
        self._template = template
        self._tier = tier
        self.timeout = timeout

    def command(self, target: Target) -> str:
        return self._template.format(host=_host(target), url=_url(target))

    def tier(self) -> EvidenceTier:
        return self._tier

    def interpret(self, target, raw, status):
        if status != CollectionStatus.OK:
            return []
        # Parsing por-ferramenta é vasto; registra suspeita apontando ao artefato.
        return [Finding(
            target=target.value,
            title=f"Revisar saída de {self.requires} (ver artefato)",
            status=Status.SUSPECTED, severity=Severity.INFO,
            impact="Requer análise/validação da saída bruta preservada.",
            remediation="Validar com o validador-achados.",
            engine=self.name)]


def _external() -> list[ExternalToolEngine]:
    return [
        ExternalToolEngine("nmap", ("portas", "ports", "nmap"), "nmap",
                           "nmap -Pn -T4 -F {host}", timeout=300),
        ExternalToolEngine("nuclei", ("nuclei", "vuln-scan"), "nuclei",
                           "nuclei -silent -nc -timeout 10 -u {url}", timeout=1200),
        ExternalToolEngine("sqlmap", ("sqli", "sqlmap"), "sqlmap",
                           "sqlmap -u {url} --batch --crawl=2 --forms "
                           "--level=1 --risk=1", timeout=900),
        ExternalToolEngine("sslyze", ("sslyze",), "sslyze", "sslyze {host}"),
        ExternalToolEngine("testssl", ("testssl",), "testssl", "testssl {host}"),
        ExternalToolEngine("nikto", ("nikto",), "nikto", "nikto -h {url}"),
        ExternalToolEngine("whatweb", ("whatweb",), "whatweb", "whatweb {url}"),
        ExternalToolEngine("dig", ("dns", "dig"), "dig",
                           "dig {host} ANY +noall +answer"),
        ExternalToolEngine("wafw00f", ("waf", "wafw00f"), "wafw00f", "wafw00f {url}"),
        ExternalToolEngine("wpscan", ("wpscan", "wordpress"), "wpscan",
                           "wpscan --url {url} --no-banner"),
    ]


class ContentDiscoveryEngine(Engine):
    """Descoberta de conteúdo / força-bruta de caminhos (ffuf ou gobuster).

    Usa a wordlist embutida (data/wordlists/comum.txt). Prefere ffuf; cai para
    gobuster. Roda faseado, com escopo + rate-limit, como qualquer motor.
    """

    name = "descoberta-conteudo"
    keys = ("conteudo", "content", "fuzz", "dirscan", "descoberta",
            "bruteforce", "forca-bruta", "brute-force", "diretorios")
    timeout = 300

    def available(self) -> bool:
        return shutil.which("ffuf") is not None or shutil.which("gobuster") is not None

    def _tool(self) -> str | None:
        if shutil.which("ffuf"):
            return "ffuf"
        if shutil.which("gobuster"):
            return "gobuster"
        return None

    def command(self, target: Target) -> str:
        url = _url(target).rstrip("/")
        wl = str(WORDLIST)
        if shutil.which("ffuf"):
            # -ac (auto-calibração) remove o falso-positivo de SPA que responde
            # 200 para qualquer caminho (catch-all).
            # -rate limita requisições/seg (evita rajada não controlada); -t
            # concorrência. Mantém o tráfego agregado dentro de um teto.
            return (f'ffuf -w "{wl}" -u {url}/FUZZ -ac '
                    f'-mc 200,201,204,301,302,307,401,403 -t 20 -rate 40 -s')
        if shutil.which("gobuster"):
            return f'gobuster dir -u {url} -w "{wl}" -q -t 20 --delay 25ms'
        return f'[indisponível] ffuf/gobuster não instalados ({url})'

    def interpret(self, target, raw, status):
        if status != CollectionStatus.OK or not raw.strip():
            return []
        return [Finding(
            target=target.value,
            title="Caminhos/recursos descobertos (revisar saída)",
            status=Status.SUSPECTED, severity=Severity.INFO,
            impact="Recursos expostos podem revelar admin/backup/config.",
            remediation="Revisar cada caminho e restringir o que não deve ser público.",
            engine=self.name)]


def all_engines() -> list[Engine]:
    return [HeadersEngine(), TlsEngine(), HttpFingerprintEngine(),
            BundleAuditEngine(), ApiProbeEngine(), ContentDiscoveryEngine(),
            *_external()]


def engines_for(test_key: str) -> list[Engine]:
    k = test_key.strip().lower()
    return [e for e in all_engines() if k in e.keys]


# --------------------------------------------------------- execução controlada
def _run_cancellable(command, eng_timeout, on_proc, should_cancel):
    """Executa comando externo com terminação real em caso de cancelamento.

    on_proc(proc) registra o processo p/ o chamador; should_cancel() é checado
    em loop e, se True, o processo (e a árvore) é encerrado. Devolve (raw,rc,status).
    """
    import time as _t
    creationflags = 0
    preexec = None
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        preexec = os.setsid  # grupo próprio p/ matar a árvore
    try:
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                encoding="utf-8", errors="replace",
                                creationflags=creationflags, preexec_fn=preexec)
    except Exception as e:  # noqa: BLE001
        return (f"(erro: {e})", None, CollectionStatus.ERROR)
    if on_proc:
        on_proc(proc)
    deadline = _t.time() + (eng_timeout or 120)
    while True:
        try:
            out, err = proc.communicate(timeout=0.4)
            raw = (out or "") + (("\n[stderr]\n" + err) if err else "")
            rc = proc.returncode
            status = CollectionStatus.OK if rc == 0 else CollectionStatus.ERROR
            return (raw, rc, status)
        except subprocess.TimeoutExpired:
            if should_cancel and should_cancel():
                _terminate_tree(proc)
                return ("(cancelado pelo usuário)", None, CollectionStatus.ERROR)
            if _t.time() > deadline:
                _terminate_tree(proc)
                return ("(timeout)", None, CollectionStatus.TIMEOUT)


def _terminate_tree(proc) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True)
        else:
            import signal
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def run_engine(session, scope: Scope, target: Target, engine: Engine,
               rps: float = 5.0, max_per_run: int = 500,
               timeout: int = 120, on_proc=None, should_cancel=None) -> EngineResult:
    """Roda um motor contra um alvo, com escopo + rate-limit + evidência.

    `on_proc`/`should_cancel` (opcionais) habilitam cancelamento real do
    processo externo em execução (usado pelo app web)."""
    host = _host(target)
    command = engine.command(target)
    tool_label = getattr(engine, "requires", None) or engine.name

    # 1) motor indisponível (ferramenta ausente) -> limitação, não achado
    if not engine.available():
        ev = Evidence(target=target.value, tool=tool_label, params=command,
                      source=target.value,
                      result_summary=f"ferramenta ausente para {engine.name}",
                      status=CollectionStatus.NO_ACCESS, tier=EvidenceTier.HEURISTIC)
        session.add_evidence(ev.to_dict())
        return EngineResult(evidence=ev, suspicions=[])

    # 2) escopo: TODO comando de rede passa pelo executor controlado
    if uses_network(command):
        dec = decide(command, scope)
        if not dec.allow:
            ev = Evidence(target=target.value, tool=tool_label, params=command,
                          source=target.value,
                          result_summary=f"bloqueado pelo executor: {dec.reason}",
                          status=CollectionStatus.NO_ACCESS, tier=EvidenceTier.HEURISTIC)
            session.add_evidence(ev.to_dict())
            return EngineResult(evidence=ev, suspicions=[])

    # 3) rate-limit compartilhado por alvo
    limits = session.limits()
    ok, reason, limits = check_and_consume(limits, host, rps, max_per_run)
    session.save_limits(limits)
    if not ok:
        ev = Evidence(target=target.value, tool=engine.name, params=command,
                      source=target.value, result_summary=reason,
                      status=CollectionStatus.NO_ACCESS, tier=EvidenceTier.HEURISTIC)
        session.add_evidence(ev.to_dict())
        return EngineResult(evidence=ev, suspicions=[])

    # 4) coleta
    if isinstance(engine, (HeadersEngine, TlsEngine, HttpFingerprintEngine,
                           BundleAuditEngine, ApiProbeEngine)):
        raw, status = engine.collect(target)
        rc = 0 if status == CollectionStatus.OK else None
    else:
        eng_timeout = getattr(engine, "timeout", timeout) or timeout
        if on_proc is not None or should_cancel is not None:
            raw, rc, status = _run_cancellable(command, eng_timeout,
                                               on_proc, should_cancel)
        else:
            try:
                proc = subprocess.run(command, shell=True, capture_output=True,
                                      text=True, encoding="utf-8", errors="replace",
                                      timeout=eng_timeout)
                raw = (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr else "")
                rc = proc.returncode
                status = CollectionStatus.OK if rc == 0 else CollectionStatus.ERROR
            except subprocess.TimeoutExpired:
                raw, rc, status = "(timeout)", None, CollectionStatus.TIMEOUT
            except Exception as e:  # noqa: BLE001
                raw, rc, status = f"(erro: {e})", None, CollectionStatus.ERROR

    # 5) evidência + artefato
    ev = Evidence(target=target.value, tool=(engine.requires or engine.name),
                  params=command, source=target.value,
                  result_summary=(raw[:200].replace("\n", " ") if raw else ""),
                  status=status, tier=engine.tier(), exit_code=rc)
    stored = session.add_evidence(ev.to_dict())
    ev.id = stored["id"]
    path, digest = preserve_artifact(session.artifacts, ev.id, raw or "")
    evs = session.evidence()
    for e in evs:
        if e.get("id") == ev.id:
            e["artifact_path"], e["artifact_sha256"] = path, digest
    from .store import write_json
    write_json(session.dir / "evidence.json", evs)
    ev.artifact_path, ev.artifact_sha256 = path, digest

    # 6) interpretação -> suspeitas (nunca confirma)
    suspicions = engine.interpret(target, raw or "", status) if status == CollectionStatus.OK else []
    for f in suspicions:
        f.evidence_ids = [ev.id]
        session.add_finding(f.to_dict())
    return EngineResult(evidence=ev, suspicions=suspicions)
