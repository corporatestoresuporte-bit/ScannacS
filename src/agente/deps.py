"""Scanner de dependências vulneráveis via OSV (https://osv.dev).

Lê lockfiles do projeto (requirements.txt, package-lock.json, package.json) e
consulta a base OSV — fonte oficial de advisories, sem chave. Fonte, versão da
consulta e horário ficam na evidência.

Regras (spec §9):
  - "dependência afetada" != "exploração comprovada" — tudo entra como SUSPEITA.
  - sem versão confiável => candidata; base indisponível => LIMITAÇÃO
    (inconclusivo), nunca "sem vulnerabilidades".
  - CVSS descreve severidade; não prova explorabilidade sozinho.

Rede: consulta só api.osv.dev (pesquisa de advisory, não ataque ao alvo).
`querier` é injetável para teste sem rede.
"""

from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .findings import Finding, Severity, Status

OSV_URL = "https://api.osv.dev/v1/query"
_SKIP = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".claude",
         "worktrees", "dist"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_requirements(text: str) -> list[tuple[str, str]]:
    out = []
    for raw in text.splitlines():
        line = raw.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9.\-+!]+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _parse_package_lock(text: str) -> list[tuple[str, str]]:
    out = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    # lockfile v2/v3: {"packages": {"node_modules/x": {"version": ...}}}
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue
        name = path.split("node_modules/")[-1]
        ver = meta.get("version")
        if name and ver:
            out.append((name, ver))
    # lockfile v1: {"dependencies": {"x": {"version": ...}}}
    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict) and meta.get("version"):
            out.append((name, meta["version"]))
    return out


def collect_deps(root: Path) -> list[tuple[str, str, str]]:
    """(ecossistema, nome, versão) a partir dos lockfiles do projeto."""
    deps: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for p in root.rglob("*"):
        if not p.is_file() or any(part in _SKIP for part in p.parts):
            continue
        eco = None
        if p.name == "requirements.txt":
            eco, pairs = "PyPI", _parse_requirements(_read(p))
        elif p.name == "package-lock.json":
            eco, pairs = "npm", _parse_package_lock(_read(p))
        else:
            continue
        for name, ver in pairs:
            key = (eco, name, ver)
            if key not in seen:
                seen.add(key)
                deps.append(key)
    return deps


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def query_osv(ecosystem: str, name: str, version: str, timeout: int = 15) -> list[dict]:
    """Consulta OSV para 1 pacote. Devolve lista de vulns (pode ser vazia).

    Levanta OSError/urllib error se a base estiver indisponível (o chamador
    trata como limitação, não como 'sem vulnerabilidade')."""
    body = json.dumps({"version": version,
                       "package": {"name": name, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request(OSV_URL, data=body,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "ScannacS-deps"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    return data.get("vulns", []) or []


def _severity(vuln: dict) -> Severity:
    """Severidade a partir do database_specific do advisory (quando houver)."""
    sev = (vuln.get("database_specific") or {}).get("severity", "")
    return {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW}.get(str(sev).upper(), Severity.MEDIUM)


def run_deps(root: Path, session=None, querier=query_osv,
             target: str = "") -> tuple[list[Finding], list[str]]:
    """Roda o scan de dependências. Devolve (achados, limitações)."""
    target = target or root.name
    deps = collect_deps(root)
    findings: list[Finding] = []
    limits: list[str] = []
    if not deps:
        limits.append("nenhum lockfile suportado encontrado "
                      "(requirements.txt / package-lock.json)")
        return findings, limits

    for eco, name, ver in deps:
        try:
            vulns = querier(eco, name, ver)
        except Exception as e:  # noqa: BLE001  base indisponível = limitação
            limits.append(f"OSV indisponível para {name}@{ver}: {e}")
            continue
        for v in vulns:
            vid = v.get("id", "?")
            aliases = v.get("aliases", []) or []
            cve = next((a for a in aliases if a.startswith("CVE-")), "")
            f = Finding(
                target=target,
                title=f"Dependência vulnerável: {name}@{ver} ({vid})",
                status=Status.SUSPECTED, severity=_severity(v),
                impact=(v.get("summary") or "Dependência afetada por advisory "
                        "(afetada != exploração comprovada).")[:300],
                remediation="Atualizar para uma versão corrigida (ver advisory).",
                engine="deps-osv",
                references=[f"https://osv.dev/vulnerability/{vid}"],
                cve=cve, cve_source="osv.dev" if cve else "",
                cve_applicability=f"{eco} {name}=={ver} consultado em {_now()}" if cve else "",
            )
            findings.append(f)
            if session is not None:
                session.add_finding(f.to_dict())
    return findings, limits
