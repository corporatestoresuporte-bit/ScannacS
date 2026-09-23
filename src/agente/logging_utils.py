"""Logging útil e seguro: registra o suficiente, sem vazar segredos.

Um filtro redige padrões sensíveis (tokens, chaves, senhas, Authorization)
antes de qualquer coisa chegar ao arquivo ou ao console.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from . import config

_REDACTED = "***REDACTED***"

# (0) prefixo+segredo: preserva só o prefixo (g1) e redige o resto (o token).
# Ex.: "Authorization: Bearer xxx" -> "Authorization: Bearer ***REDACTED***".
_PREFIX_PATTERNS = [
    re.compile(r"(?i)((?:authorization\s*[:=]\s*)?"
               r"(?:bearer|basic|token|negotiate)\s+)([A-Za-z0-9._\-+/=]+)"),
]

# (1) chave=valor: preserva o nome da chave + separador, redige só o valor.
# O nome pode estar em camelCase/underscore (apiSecret, SUPABASE_SERVICE_ROLE_KEY)
# — por isso aceitamos caracteres em volta do miolo sensível.
_KV_PATTERNS = [
    re.compile(
        r"(?i)([A-Za-z0-9_]*"
        r"(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
        r"service[_-]?role[_-]?key|password|passwd|senha|apikey|"
        r"authorization|auth)"
        r"[A-Za-z0-9_]*)"          # miolo + sufixo do nome da chave
        r"(\s*[:=]\s*['\"]?)"      # separador (com aspa opcional)
        r"([^\s'\";,]+)"           # o valor propriamente dito
    ),
]

# (2) formatos de segredo reconhecíveis pelo VALOR — redige o match inteiro,
# mesmo sem um nome de chave amigável (JWT, Stripe, AWS, GitHub, Slack, PEM).
_VALUE_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{2,}"),  # JWT
    re.compile(r"(?i)\b[srp]k_(?:live|test)_[A-Za-z0-9]{6,}"),   # Stripe
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                          # AWS access key id
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),                        # GitHub PAT
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),                # Slack
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),            # bloco PEM
]


def _apply(text: str) -> str:
    for pat in _PREFIX_PATTERNS:
        text = pat.sub(lambda m: f"{m.group(1)}{_REDACTED}", text)
    for pat in _KV_PATTERNS:
        text = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", text)
    for pat in _VALUE_PATTERNS:
        text = pat.sub(_REDACTED, text)
    return text


class SecretRedactionFilter(logging.Filter):
    """Substitui segredos na mensagem final do log."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _apply(record.getMessage())
        record.args = ()
        return True


def redact(text: str) -> str:
    """Redige segredos de uma string avulsa (uso fora do logger)."""
    return _apply(text)


def get_logger(name: str = "agente", logfile: Path | None = None) -> logging.Logger:
    """Logger com console + arquivo em logs/, já com redação de segredos."""
    logger = logging.getLogger(name)
    if logger.handlers:  # evita handlers duplicados em reuso
        return logger

    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    redactor = SecretRedactionFilter()

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    console.addFilter(redactor)
    logger.addHandler(console)

    try:
        config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        path = logfile or (config.LOGS_DIR / "agente.log")
        fileh = logging.FileHandler(path, encoding="utf-8")
        fileh.setFormatter(fmt)
        fileh.addFilter(redactor)
        logger.addHandler(fileh)
    except OSError:  # pragma: no cover - ambiente sem escrita
        pass

    return logger
