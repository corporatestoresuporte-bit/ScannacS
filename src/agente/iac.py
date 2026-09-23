"""Adaptador Trivy — misconfiguração de IaC/containers (`trivy config`).

Roda `trivy config --format json` se o binário existir; senão, LIMITAÇÃO.
Parser separado da execução (testável sem o binário). Cada misconfig vira
SUSPEITA com id/severidade/arquivo:linha.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .findings import Finding, Severity, Status

_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "UNKNOWN": Severity.INFO}


def parse_trivy(stdout: str, target: str = "") -> list[Finding]:
    """Converte a saída JSON do `trivy config` em achados (testável)."""
    out: list[Finding] = []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return out
    for res in data.get("Results", []) or []:
        tgt = res.get("Target", "")
        for m in res.get("Misconfigurations", []) or []:
            sev = _SEV.get(str(m.get("Severity", "")).upper(), Severity.MEDIUM)
            line = (m.get("CauseMetadata") or {}).get("StartLine", 0)
            mid = m.get("ID", "?")
            out.append(Finding(
                target=target or tgt,
                title=f"Trivy IaC: {mid} {m.get('Title', '')}".strip(),
                status=Status.SUSPECTED, severity=sev,
                impact=(m.get("Description") or "")[:300],
                remediation=(m.get("Resolution") or "Corrigir a configuração.")[:200],
                engine="iac-trivy",
                evidence_ids=[f"{tgt}:{line}"],
                references=(m.get("References") or [])[:2]))
    return out


def run_trivy_config(path: Path, timeout: int = 600,
                     target: str = "") -> tuple[list[Finding], list[str]]:
    """Roda `trivy config` contra uma pasta. Devolve (achados, limitações)."""
    if shutil.which("trivy") is None:
        return [], ["trivy não instalado (IaC/misconfig indisponível) — "
                    "instale de https://trivy.dev (Windows/Linux/macOS)"]
    cmd = ["trivy", "config", "--quiet", "--format", "json", str(path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], [f"trivy excedeu {timeout}s (inconclusivo)"]
    except Exception as e:  # noqa: BLE001
        return [], [f"falha ao executar trivy: {e}"]
    findings = parse_trivy(proc.stdout or "", target=target)
    limits: list[str] = []
    if proc.returncode not in (0, 1) and not findings:
        limits.append(f"trivy retornou código {proc.returncode} "
                      f"(stderr: {(proc.stderr or '')[:160]})")
    return findings, limits
