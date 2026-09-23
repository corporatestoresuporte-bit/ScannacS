"""Adaptador OWASP ZAP (DAST).

Duas vias:
  - `parse_zap(json)` — converte um relatório JSON do ZAP em achados (testável).
  - `run_zap_baseline(url)` — roda o ZAP baseline via Docker (se disponível);
    senão, LIMITAÇÃO. Só contra alvo autorizado (o chamador aplica o escopo).

Cada alerta vira SUSPEITA (o ZAP aponta; confirmação é do validador).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .findings import Finding, Severity, Status

_RISK = {3: Severity.HIGH, 2: Severity.MEDIUM, 1: Severity.LOW, 0: Severity.INFO}


def parse_zap(stdout: str, target: str = "") -> list[Finding]:
    """Converte o JSON do ZAP (relatório tradicional) em achados."""
    out: list[Finding] = []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return out
    for site in data.get("site", []) or []:
        stgt = site.get("@name", "") or target
        for a in site.get("alerts", []) or []:
            try:
                risk = int(a.get("riskcode", "1"))
            except (TypeError, ValueError):
                risk = 1
            sev = _RISK.get(risk, Severity.LOW)
            inst = a.get("instances") or []
            uri = (inst[0].get("uri", "") if inst else "")
            name = a.get("alert") or a.get("name") or "alerta"
            out.append(Finding(
                target=target or stgt, title=f"ZAP: {name}",
                status=Status.SUSPECTED, severity=sev,
                impact=(a.get("desc") or "")[:300],
                remediation=(a.get("solution") or "")[:200],
                engine="dast-zap",
                evidence_ids=[uri] if uri else [],
                references=[a.get("reference", "")][:1]))
    return out


def run_zap_baseline(url: str, timeout: int = 900, target: str = "",
                     host_network: bool = False) -> tuple[list[Finding], list[str]]:
    """Roda o ZAP baseline via Docker. Devolve (achados, limitações)."""
    if shutil.which("docker") is None:
        return [], ["docker ausente — ZAP baseline indisponível "
                    "(veja https://www.zaproxy.org para instalar)"]
    outdir = Path(tempfile.mkdtemp())
    cmd = ["docker", "run", "--rm"]
    if host_network:
        cmd += ["--network", "host"]
    cmd += ["-v", f"{outdir}:/zap/wrk:rw", "ghcr.io/zaproxy/zaproxy",
            "zap-baseline.py", "-t", url, "-J", "report.json", "-I"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], [f"ZAP excedeu {timeout}s (inconclusivo)"]
    except Exception as e:  # noqa: BLE001
        return [], [f"falha ao executar ZAP: {e}"]
    report = outdir / "report.json"
    if not report.exists():
        return [], ["ZAP não gerou report.json (inconclusivo)"]
    return parse_zap(report.read_text(encoding="utf-8", errors="replace"),
                     target=target or url), []
