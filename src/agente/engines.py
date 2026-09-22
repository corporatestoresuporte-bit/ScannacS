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

WORDLIST = config.ROOT / "data" / "wordlists" / "comum.txt"

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


# ------------------------------------------------------------------ embutidos
class HeadersEngine(Engine):
    name = "cabecalhos-seguranca"
    keys = ("headers", "cabecalhos", "cabecalhos-seguranca", "security-headers")

    def command(self, target: Target) -> str:
        return f"[builtin] GET {_url(target)} (cabeçalhos)"

    def collect(self, target: Target) -> tuple[str, CollectionStatus]:
        req = urllib.request.Request(_url(target), method="HEAD",
                                     headers={"User-Agent": "agente-auditoria"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                hdrs = dict(resp.headers.items())
        except Exception as e:  # noqa: BLE001
            return (f"(erro/sem-acesso: {e})", CollectionStatus.NO_ACCESS)
        raw = "\n".join(f"{k}: {v}" for k, v in hdrs.items())
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
        req = urllib.request.Request(_url(target),
                                     headers={"User-Agent": "agente-auditoria"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = f"status: {resp.status}\n" + \
                      "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        except Exception as e:  # noqa: BLE001
            return (f"(erro/sem-acesso: {e})", CollectionStatus.NO_ACCESS)
        return (raw, CollectionStatus.OK)


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
            return (f'ffuf -w "{wl}" -u {url}/FUZZ -ac '
                    f'-mc 200,201,204,301,302,307,401,403 -t 40 -s')
        if shutil.which("gobuster"):
            return f'gobuster dir -u {url} -w "{wl}" -q -t 40'
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
            ContentDiscoveryEngine(), *_external()]


def engines_for(test_key: str) -> list[Engine]:
    k = test_key.strip().lower()
    return [e for e in all_engines() if k in e.keys]


# --------------------------------------------------------- execução controlada
def run_engine(session, scope: Scope, target: Target, engine: Engine,
               rps: float = 5.0, max_per_run: int = 500,
               timeout: int = 120) -> EngineResult:
    """Roda um motor contra um alvo, com escopo + rate-limit + evidência."""
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
    if isinstance(engine, (HeadersEngine, TlsEngine, HttpFingerprintEngine)):
        raw, status = engine.collect(target)
        rc = 0 if status == CollectionStatus.OK else None
    else:
        try:
            eng_timeout = getattr(engine, "timeout", timeout) or timeout
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
