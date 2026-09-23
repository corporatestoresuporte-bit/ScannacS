"""Adaptador Semgrep (SAST real).

Roda `semgrep --json` se o binário existir; senão, devolve LIMITAÇÃO (não
"seguro"). O parser é separado da execução, para teste sem o binário.

Cada resultado vira SUSPEITA (SAST aponta padrão; confirmação é do validador),
com arquivo:linha, regra e severidade do próprio Semgrep.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .findings import Finding, Severity, Status

_SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


def parse_semgrep(stdout: str, target: str = "") -> list[Finding]:
    """Converte a saída JSON do Semgrep em achados. (testável sem o binário)"""
    out: list[Finding] = []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return out
    for r in data.get("results", []) or []:
        extra = r.get("extra", {}) or {}
        sev = _SEV.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM)
        path = r.get("path", "?")
        line = (r.get("start", {}) or {}).get("line", 0)
        rule = r.get("check_id", "semgrep")
        msg = (extra.get("message") or rule)[:300]
        out.append(Finding(
            target=target or path, title=f"Semgrep: {rule}",
            status=Status.SUSPECTED, severity=sev,
            impact=msg, remediation="Revisar o padrão apontado pela regra.",
            engine="sast-semgrep", evidence_ids=[f"{path}:{line}"],
            references=[f"https://semgrep.dev/r/{rule}"]))
    return out


def run_semgrep(path: Path, config: str = "auto", timeout: int = 600,
                target: str = "") -> tuple[list[Finding], list[str]]:
    """Roda Semgrep contra uma pasta local. Devolve (achados, limitações)."""
    if shutil.which("semgrep") is None:
        return [], ["semgrep não instalado (SAST real indisponível) — "
                    "instale com `pip install semgrep` (Linux/macOS/WSL)"]
    # exclui libs/build (senão varre node_modules e leva 1h); teto por regra
    _EXC = ["node_modules", "dist", "build", "out", ".next", "coverage",
            ".turbo", ".cache", "vendor", ".git"]
    cmd = ["semgrep", "--json", "--quiet", "--config", config,
           "--timeout", "30", "--timeout-threshold", "3"]
    for e in _EXC:
        cmd += ["--exclude", e]
    cmd.append(str(path))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], [f"semgrep excedeu {timeout}s (inconclusivo)"]
    except Exception as e:  # noqa: BLE001
        return [], [f"falha ao executar semgrep: {e}"]
    findings = parse_semgrep(proc.stdout or "", target=target)
    limits: list[str] = []
    if proc.returncode not in (0, 1) and not findings:  # 1 = achou algo
        limits.append(f"semgrep retornou código {proc.returncode} "
                      f"(stderr: {(proc.stderr or '')[:160]})")
    return findings, limits
