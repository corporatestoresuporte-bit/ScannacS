"""Persistência de sessão: tarefas, achados, evidências, suspeitas e limites.

Tudo em JSON sob reports/sessions/<id>/ (git-ignorado — pode conter dados dos
alvos). Escrita atômica. Uma retomada relê esse estado e revalida o escopo.

Layout de uma sessão:
  reports/sessions/<id>/
    session.json     metadados (ambiente, hashes de escopo/prompts, status)
    tasks.json       tarefas dos agentes (objetivo/alvo/ferramentas/prazo/...)
    findings.json    achados (confirmados e não)
    evidence.json    evidências (metadados; artefatos ficam em artifacts/)
    suspicions.json  suspeitas, descartes e lacunas (separados dos achados)
    limits.json      baldes de rate-limit compartilhados por alvo
    artifacts/       saídas brutas preservadas (redigidas)
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import config

SESSIONS_DIR = config.REPORTS_DIR / "sessions"
ACTIVE_POINTER = SESSIONS_DIR / ".active"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_session_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def write_json(path: Path, obj) -> None:
    _atomic_write(path, json.dumps(obj, ensure_ascii=False, indent=2))


def read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def _tool_version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:  # noqa: BLE001
        return "?"


def _git_commit() -> str:
    """Commit curto do checkout (best-effort; vazio se instalado/sem git)."""
    import subprocess
    try:
        out = subprocess.run(["git", "-C", str(config.ROOT), "rev-parse",
                              "--short", "HEAD"], capture_output=True, text=True,
                             timeout=8)
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:  # noqa: BLE001
        return ""


class Session:
    """Handle de uma sessão de auditoria no disco."""

    def __init__(self, sid: str):
        self.id = sid
        self.dir = SESSIONS_DIR / sid
        self.artifacts = self.dir / "artifacts"

    # -- ciclo de vida -------------------------------------------------------
    @classmethod
    def create(cls, environment: str = "", scope_hash: str = "",
               prompts_hash: str = "") -> "Session":
        sid = new_session_id()
        s = cls(sid)
        s.dir.mkdir(parents=True, exist_ok=True)
        s.artifacts.mkdir(parents=True, exist_ok=True)
        s.save_meta({
            "id": sid,
            "created_at": _now(),
            "status": "configurando",
            "environment": environment,
            "scope_hash": scope_hash,
            "prompts_hash": prompts_hash,
            # manifesto: identifica a VERSÃO/execução (spec §10 / revisão #1)
            "version": _tool_version(),
            "commit": _git_commit(),
            "install_mode": "checkout" if config._IS_CHECKOUT else "instalado",
            "hash_convention": "sha256-bytes",   # artefatos: hash sobre bytes
            "engines": [],                        # preenchido por quem executa
        })
        for name in ("tasks", "findings", "evidence", "suspicions"):
            write_json(s.dir / f"{name}.json", [])
        write_json(s.dir / "limits.json", {})
        s.set_active()
        return s

    @classmethod
    def active(cls) -> "Session | None":
        if not ACTIVE_POINTER.exists():
            return None
        sid = ACTIVE_POINTER.read_text(encoding="utf-8").strip()
        if not sid:
            return None
        s = cls(sid)
        return s if s.dir.exists() else None

    @classmethod
    def list_ids(cls) -> list[str]:
        if not SESSIONS_DIR.exists():
            return []
        return sorted(p.name for p in SESSIONS_DIR.iterdir() if p.is_dir())

    def set_active(self) -> None:
        _atomic_write(ACTIVE_POINTER, self.id)

    # -- metadados -----------------------------------------------------------
    def meta(self) -> dict:
        return read_json(self.dir / "session.json", {})

    def save_meta(self, meta: dict) -> None:
        write_json(self.dir / "session.json", meta)

    def update_meta(self, **kw) -> dict:
        m = self.meta()
        m.update(kw)
        m["updated_at"] = _now()
        self.save_meta(m)
        return m

    # -- coleções ------------------------------------------------------------
    def _load(self, name: str) -> list:
        return read_json(self.dir / f"{name}.json", [])

    def _append(self, name: str, item: dict) -> dict:
        items = self._load(name)
        if "id" not in item or not item["id"]:
            item["id"] = f"{name[:3]}-{len(items)+1:04d}"
        items.append(item)
        write_json(self.dir / f"{name}.json", items)
        return item

    def tasks(self) -> list:
        return self._load("tasks")

    def add_task(self, task: dict) -> dict:
        return self._append("tasks", task)

    def update_task(self, task_id: str, **kw) -> bool:
        items = self._load("tasks")
        hit = False
        for t in items:
            if t.get("id") == task_id:
                t.update(kw)
                t["updated_at"] = _now()
                hit = True
        if hit:
            write_json(self.dir / "tasks.json", items)
        return hit

    def findings(self) -> list:
        return self._load("findings")

    def add_finding(self, finding: dict) -> dict:
        # BOUNDARY: não publicar "confirmado" sem evidência/validação suficientes.
        if finding.get("status") == "confirmado":
            from . import findings as _F
            ok, missing = _F.validate_confirmation(finding, self.evidence())
            if not ok:
                finding = dict(finding)
                finding["status"] = "suspeita"
                finding["nota_validacao"] = (
                    "confirmação rejeitada (evidência insuficiente): "
                    + "; ".join(missing))
        return self._append("findings", finding)

    def update_finding(self, finding_id: str, status: str, validated_by: str,
                       reason: str = "", alternatives: list[str] | None = None,
                       confirmation_type: str | None = None) -> tuple[bool, str]:
        """Persiste a DECISÃO do validador num achado (rastreável).

        Grava status + registro de validação (quem/quando/motivo/alternativas).
        Para 'confirmado', aplica o portão can_confirm; se falhar, mantém como
        'suspeita' com a nota do motivo. Devolve (ok, mensagem)."""
        items = self._load("findings")
        hit = None
        for f in items:
            if f.get("id") == finding_id:
                hit = f
                break
        if hit is None:
            return (False, f"achado {finding_id} não encontrado")
        val = hit.get("validation") or {}
        val.update({"validated_by": validated_by, "validated_at": _now(),
                    "method": reason, "alternative_explanations":
                    alternatives if alternatives is not None else val.get(
                        "alternative_explanations", [])})
        hit["validation"] = val
        if confirmation_type:
            hit["confirmation_type"] = confirmation_type
        if status == "confirmado":
            from . import findings as _F
            # o validador precisa afirmar is_true_positive=True p/ confirmar
            val["is_true_positive"] = True
            ok, missing = _F.validate_confirmation(hit, self.evidence())
            if not ok:
                hit["status"] = "suspeita"
                hit["nota_validacao"] = "confirmação rejeitada: " + "; ".join(missing)
                write_json(self.dir / "findings.json", items)
                return (False, "não confirmado: " + "; ".join(missing))
        hit["status"] = status
        hit["nota_validacao"] = f"validado por {validated_by}: {reason}"[:300]
        write_json(self.dir / "findings.json", items)
        return (True, f"{finding_id} -> {status}")

    def close(self, status: str = "concluida") -> dict:
        """Encerra a sessão de forma coerente, com um retrato de cobertura."""
        fnd = self.findings()
        by = {}
        for f in fnd:
            by[f.get("status", "?")] = by.get(f.get("status", "?"), 0) + 1
        nao_revisados = sum(1 for f in fnd
                            if not (f.get("validation") or {}).get("validated_by"))
        return self.update_meta(status=status, closed_at=_now(),
                                cobertura={"achados_por_estado": by,
                                           "nao_revisados": nao_revisados,
                                           "evidencias": len(self.evidence())})

    def evidence(self) -> list:
        return self._load("evidence")

    def add_evidence(self, ev: dict) -> dict:
        return self._append("evidence", ev)

    def suspicions(self) -> list:
        return self._load("suspicions")

    def add_suspicion(self, item: dict) -> dict:
        return self._append("suspicions", item)

    # -- rate limits (compartilhados por alvo) -------------------------------
    def limits(self) -> dict:
        return read_json(self.dir / "limits.json", {})

    def save_limits(self, data: dict) -> None:
        write_json(self.dir / "limits.json", data)
