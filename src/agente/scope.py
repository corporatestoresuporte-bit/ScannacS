"""Modelo de escopo e o portão de autorização (gate).

Regras centrais (ver AGENTS.md):
  - A execução de auditoria fica BLOQUEADA enquanto faltar escopo válido
    e a autorização explícita do dono.
  - Só valem os ativos EXATOS listados. Subdomínios, redirecionamentos,
    IPs compartilhados e serviços de terceiros NÃO ampliam o escopo.
  - A máquina de desenvolvimento (loopback/localhost) nunca é alvo implícito.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import config

# Tipos de ativo aceitos no cadastro de alvos.
VALID_TARGET_TYPES = {"domain", "url", "ip", "vps"}

# Valores que apontam para a própria máquina — sempre recusados como alvo.
LOOPBACK_VALUES = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "loopback",
}


@dataclass
class Target:
    """Um ativo exato dentro do escopo."""

    name: str
    type: str
    value: str
    allowed_tests: list[str] = field(default_factory=list)
    limits: str = ""
    exclusions: list[str] = field(default_factory=list)
    notes: str = ""

    def problems(self) -> list[str]:
        """Lista de motivos que impedem este alvo de ser auditado."""
        issues: list[str] = []
        if not self.value.strip():
            issues.append("alvo sem 'value' (domínio/URL/IP)")
        if self.type not in VALID_TARGET_TYPES:
            issues.append(
                f"tipo '{self.type}' inválido (use um de {sorted(VALID_TARGET_TYPES)})"
            )
        if not self.allowed_tests:
            issues.append("nenhum teste permitido em 'allowed_tests'")
        if self._points_to_dev_machine():
            issues.append(
                "aponta para a máquina de desenvolvimento (loopback/localhost) "
                "— não é alvo implícito"
            )
        return issues

    def _points_to_dev_machine(self) -> bool:
        v = self.value.strip().lower()
        # normaliza URL -> host
        for prefix in ("http://", "https://"):
            if v.startswith(prefix):
                v = v[len(prefix):]
        host = v.split("/")[0].split(":")[0]
        return host in LOOPBACK_VALUES


@dataclass
class Scope:
    """Escopo completo: autorização + lista de alvos exatos."""

    authorized: bool = False
    authorized_by: str = ""
    authorized_at: str = ""
    environment: str = ""
    targets: list[Target] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        raw_targets = data.get("targets", []) or []
        targets = [
            Target(
                name=str(t.get("name", "")),
                type=str(t.get("type", "")),
                value=str(t.get("value", "")),
                allowed_tests=list(t.get("allowed_tests", []) or []),
                limits=str(t.get("limits", "")),
                exclusions=list(t.get("exclusions", []) or []),
                notes=str(t.get("notes", "")),
            )
            for t in raw_targets
        ]
        return cls(
            authorized=bool(data.get("authorized", False)),
            authorized_by=str(data.get("authorized_by", "")),
            authorized_at=str(data.get("authorized_at", "")),
            environment=str(data.get("environment", "")),
            targets=targets,
        )


def _toml_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_list(items: list[str]) -> str:
    return "[" + ", ".join(_toml_str(x) for x in items) + "]"


def to_toml(scope: "Scope") -> str:
    """Serializa o escopo para TOML (schema conhecido do projeto)."""
    lines = [
        f"authorized = {'true' if scope.authorized else 'false'}",
        f"authorized_by = {_toml_str(scope.authorized_by)}",
        f"authorized_at = {_toml_str(scope.authorized_at)}",
        f"environment = {_toml_str(scope.environment)}",
    ]
    for t in scope.targets:
        lines += [
            "",
            "[[targets]]",
            f"name = {_toml_str(t.name)}",
            f"type = {_toml_str(t.type)}",
            f"value = {_toml_str(t.value)}",
            f"allowed_tests = {_toml_list(t.allowed_tests)}",
            f"limits = {_toml_str(t.limits)}",
            f"exclusions = {_toml_list(t.exclusions)}",
            f"notes = {_toml_str(t.notes)}",
        ]
    return "\n".join(lines) + "\n"


def save_scope(scope: "Scope", path: Path | None = None) -> Path:
    path = path or config.SCOPE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_toml(scope), encoding="utf-8")
    return path


def scope_hash(scope: "Scope | None") -> str:
    import hashlib
    if scope is None:
        return ""
    return hashlib.sha256(to_toml(scope).encode("utf-8")).hexdigest()


@dataclass
class GateResult:
    """Resultado do portão de autorização."""

    allowed: bool
    reasons: list[str] = field(default_factory=list)
    scope: Scope | None = None

    def __bool__(self) -> bool:  # permite `if gate:`
        return self.allowed


def load_scope(path: Path | None = None) -> Scope | None:
    """Carrega o escopo do TOML. Devolve None se o arquivo não existir."""
    path = path or config.SCOPE_FILE
    if not path.exists():
        return None
    return Scope.from_dict(config.load_toml(path))


def evaluate_gate(scope: Scope | None) -> GateResult:
    """Decide se a auditoria pode rodar. Falha fechado (nega por padrão).

    NÃO checa a confirmação interativa/`--confirm` — isso é responsabilidade
    da CLI. Aqui validamos apenas escopo + autorização + alvos.
    """
    reasons: list[str] = []

    if scope is None:
        return GateResult(
            allowed=False,
            reasons=[
                "escopo não definido — crie config/scope.toml "
                "(use `agente scope init`)"
            ],
        )

    if not scope.authorized:
        reasons.append(
            "escopo não autorizado — defina authorized = true em config/scope.toml"
        )

    active = [t for t in scope.targets if t.value.strip()]
    if not active:
        reasons.append("nenhum alvo cadastrado com 'value'")

    for t in scope.targets:
        for problem in t.problems():
            label = t.name or t.value or "<alvo sem nome>"
            reasons.append(f"alvo '{label}': {problem}")

    return GateResult(allowed=not reasons, reasons=reasons, scope=scope)
