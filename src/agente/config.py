"""Localização de arquivos e carregamento de configuração.

Config em TOML, lido com `tomllib` (stdlib no Python 3.11+). Nenhuma
dependência externa é necessária para a base funcionar.

Segredos NÃO ficam aqui: são lidos de variáveis de ambiente (.env),
nunca versionados nem gravados em relatórios/logs.
"""

from __future__ import annotations

import importlib.resources
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

# --- Recursos EMPACOTADOS (viajam dentro do pacote: wordlist, exemplos) ------
def _package_data() -> Path:
    """Diretório `data/` DENTRO do pacote (funciona no checkout e instalado)."""
    try:
        return Path(str(importlib.resources.files("agente"))) / "data"
    except Exception:  # noqa: BLE001
        return Path(__file__).resolve().parent / "data"


PKG_DATA = _package_data()

# Raiz do checkout (quando rodando de src/). Só existe em desenvolvimento.
ROOT = Path(__file__).resolve().parents[2]
_IS_CHECKOUT = (ROOT / "pyproject.toml").exists()


def _user_home() -> Path:
    """Diretório de dados do usuário (NÃO escreve em site-packages)."""
    env = os.environ.get("AGENTE_HOME") or os.environ.get("SCANNACS_HOME")
    if env:
        return Path(env)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "ScannacS"
    xdg = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(xdg) / "ScannacS"


# Dados graváveis: no checkout usa a própria pasta; instalado, o dir do usuário.
DATA_HOME = ROOT if _IS_CHECKOUT else _user_home()

CONFIG_DIR = DATA_HOME / "config"
PROMPTS_DIR = DATA_HOME / "prompts"
MASTERS_DIR = PROMPTS_DIR / "masters"
REPORTS_DIR = DATA_HOME / "reports"
LOGS_DIR = DATA_HOME / "logs"

SCOPE_FILE = CONFIG_DIR / "scope.toml"
SETTINGS_FILE = CONFIG_DIR / "settings.toml"
ENV_FILE = DATA_HOME / ".env"

# Exemplos vêm do pacote (para `scope init` funcionar instalado).
SCOPE_EXAMPLE = PKG_DATA / "config" / "scope.example.toml"
SETTINGS_EXAMPLE = PKG_DATA / "config" / "settings.example.toml"

# Wordlist empacotada (resolvida via pacote, não via cwd).
WORDLIST = PKG_DATA / "wordlists" / "comum.txt"


def ensure_dirs() -> None:
    """Cria os diretórios de dados graváveis (idempotente)."""
    for d in (CONFIG_DIR, MASTERS_DIR, PROMPTS_DIR / "inbox", REPORTS_DIR, LOGS_DIR):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass


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
