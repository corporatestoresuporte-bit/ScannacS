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


def _terminate_tree(proc) -> None:
    """Mata o processo E a árvore (semgrep gera semgrep-core/osemgrep como netos;
    matar só o pai deixa o neto vivo segurando o pipe -> trava)."""
    import os
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


def run_semgrep(path: Path, config: str = "auto", timeout: int = 300,
                target: str = "") -> tuple[list[Finding], list[str]]:
    """Roda Semgrep contra uma pasta local. Devolve (achados, limitações).

    Teto de tempo REAL: no timeout mata a árvore (semgrep-core incluso), senão
    o neto sobrevive e o scan fica preso por horas.
    """
    import os
    if shutil.which("semgrep") is None:
        return [], ["semgrep não instalado (SAST real indisponível) — "
                    "instale com `pip install semgrep` (Linux/macOS/WSL)"]
    _EXC = ["node_modules", "dist", "build", "out", ".next", "coverage",
            ".turbo", ".cache", "vendor", ".git"]
    cmd = ["semgrep", "--json", "--quiet", "--config", config,
           "--timeout", "20", "--timeout-threshold", "3"]
    for e in _EXC:
        cmd += ["--exclude", e]
    cmd.append(str(path))
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    preexec = None if os.name == "nt" else os.setsid
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace",
                                creationflags=flags, preexec_fn=preexec)
    except Exception as e:  # noqa: BLE001
        return [], [f"falha ao executar semgrep: {e}"]
    try:
        out, err = proc.communicate(timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        _terminate_tree(proc)                      # mata semgrep-core (neto)
        try:
            out, err = proc.communicate(timeout=15)
        except Exception:  # noqa: BLE001
            out, err = "", ""
        return (parse_semgrep(out or "", target=target),
                [f"semgrep excedeu {timeout}s e foi interrompido (inconclusivo)"])
    except Exception as e:  # noqa: BLE001
        _terminate_tree(proc)
        return [], [f"falha ao executar semgrep: {e}"]
    findings = parse_semgrep(out or "", target=target)
    limits: list[str] = []
    if rc not in (0, 1) and not findings:          # 1 = achou algo
        limits.append(f"semgrep retornou código {rc} (stderr: {(err or '')[:160]})")
    return findings, limits
