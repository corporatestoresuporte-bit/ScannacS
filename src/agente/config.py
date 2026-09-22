"""Localização de arquivos e carregamento de configuração.

Config em TOML, lido com `tomllib` (stdlib no Python 3.11+). Nenhuma
dependência externa é necessária para a base funcionar.

Segredos NÃO ficam aqui: são lidos de variáveis de ambiente (.env),
nunca versionados nem gravados em relatórios/logs.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

# Raiz do repositório = três níveis acima deste arquivo
# (src/agente/config.py -> src/agente -> src -> raiz).
ROOT = Path(__file__).resolve().parents[2]

CONFIG_DIR = ROOT / "config"
PROMPTS_DIR = ROOT / "prompts"
MASTERS_DIR = PROMPTS_DIR / "masters"
REPORTS_DIR = ROOT / "reports"
LOGS_DIR = ROOT / "logs"

SCOPE_FILE = CONFIG_DIR / "scope.toml"
SCOPE_EXAMPLE = CONFIG_DIR / "scope.example.toml"
SETTINGS_FILE = CONFIG_DIR / "settings.toml"
SETTINGS_EXAMPLE = CONFIG_DIR / "settings.example.toml"
ENV_FILE = ROOT / ".env"


class ConfigError(Exception):
    """Erro de configuração legível (arquivo ausente, TOML inválido, etc.)."""


def load_toml(path: Path) -> dict:
    """Lê um TOML e devolve um dict. Erros viram ConfigError legível."""
    if not path.exists():
        raise ConfigError(f"Arquivo não encontrado: {path}")
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:  # pragma: no cover - mensagem
        raise ConfigError(f"TOML inválido em {path}: {exc}") from exc


def load_settings() -> dict:
    """Carrega settings.toml se existir; senão devolve padrões vazios."""
    if SETTINGS_FILE.exists():
        return load_toml(SETTINGS_FILE)
    return {}


def load_dotenv(path: Path = ENV_FILE) -> dict[str, str]:
    """Parser mínimo de .env (KEY=VALUE). Não sobrescreve o ambiente real.

    Devolve o que foi lido do arquivo, mas quem tem prioridade é
    `os.environ`. Mantido simples de propósito — sem dependência.
    """
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            values[key] = val
    return values


def get_secret(name: str) -> str | None:
    """Lê um segredo do ambiente, com o .env como fallback.

    Prioridade: os.environ > .env. Nunca loga o valor.
    """
    if name in os.environ:
        return os.environ[name]
    return load_dotenv().get(name)


@dataclass(frozen=True)
class Paths:
    """Atalho imutável para os caminhos do projeto (útil em testes/CLI)."""

    root: Path = ROOT
    config: Path = CONFIG_DIR
    prompts: Path = PROMPTS_DIR
    masters: Path = MASTERS_DIR
    reports: Path = REPORTS_DIR
    logs: Path = LOGS_DIR
    scope: Path = SCOPE_FILE
    settings: Path = SETTINGS_FILE
