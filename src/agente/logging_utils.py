"""Logging útil e seguro: registra o suficiente, sem vazar segredos.

Um filtro redige padrões sensíveis (tokens, chaves, senhas, Authorization)
antes de qualquer coisa chegar ao arquivo ou ao console.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from . import config

# Padrões redigidos em qualquer mensagem de log.
# Ordem importa: o padrão "bearer <token>" vem antes do genérico chave=valor,
# senão o genérico consumiria só a palavra "Bearer" e deixaria o token.
_REDACTION_PATTERNS = [
    # header Authorization: Bearer xxx
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-]+)"),
    # chave=valor (ou chave: valor) com nomes sensíveis
    re.compile(
        r"(?i)\b(token|secret|password|passwd|senha|api[_-]?key|apikey|"
        r"access[_-]?key|private[_-]?key|authorization|auth|bearer)\b"
        r"(\s*[:=]\s*)(\S+)"
    ),
]

_REDACTED = "***REDACTED***"


class SecretRedactionFilter(logging.Filter):
    """Substitui segredos na mensagem final do log."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pat in _REDACTION_PATTERNS:
            if pat.groups >= 3:
                msg = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", msg)
            else:
                msg = pat.sub(lambda m: f"{m.group(1)}{_REDACTED}", msg)
        record.msg = msg
        record.args = ()
        return True


def redact(text: str) -> str:
    """Redige segredos de uma string avulsa (uso fora do logger)."""
    for pat in _REDACTION_PATTERNS:
        if pat.groups >= 3:
            text = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", text)
        else:
            text = pat.sub(lambda m: f"{m.group(1)}{_REDACTED}", text)
    return text


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
