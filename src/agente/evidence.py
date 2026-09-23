"""Evidência e artefatos.

Um achado só pode ser confirmado quando ancorado em EVIDÊNCIA coletada por
ferramenta, com o artefato bruto preservado. Cada evidência registra
(spec §7): origem, horário, ferramenta, parâmetros, resultado, referência ao
artefato, e o estado da coleta (ok / timeout / erro / sem-acesso / inconclusivo).

Os artefatos preservam a saída ORIGINAL da ferramenta, com segredos redigidos.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from .logging_utils import redact
from .verdict import EvidenceTier


class CollectionStatus(str, Enum):
    """Como terminou a coleta da evidência."""

    OK = "ok"
    TIMEOUT = "timeout"
    ERROR = "erro"
    NO_ACCESS = "sem_acesso"
    INCONCLUSIVE = "inconclusivo"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


@dataclass
class Evidence:
    """Uma unidade de evidência ligada a um alvo e a uma ferramenta.

    A saída bruta vai para um artefato preservado (redigido); aqui ficam os
    metadados rastreáveis.
    """

    target: str                 # alvo exato (origem do teste)
    tool: str                   # ferramenta usada (ex.: curl, openssl)
    params: str = ""            # parâmetros relevantes / comando executado
    source: str = ""            # origem observada (host/URL/arquivo)
    result_summary: str = ""    # resultado resumido (sem segredos)
    status: CollectionStatus = CollectionStatus.OK
    tier: EvidenceTier = EvidenceTier.HEURISTIC  # graduação (ver verdict.py)
    exit_code: int | None = None
    artifact_path: str = ""     # referência ao artefato preservado
    artifact_sha256: str = ""   # hash do artefato bruto
    collected_at: str = field(default_factory=_now)
    id: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["tier"] = self.tier.value
        return d

    @property
    def is_usable(self) -> bool:
        """Evidência serve para confirmar? Precisa ter terminado OK e ter
        artefato preservado com hash."""
        return (
            self.status == CollectionStatus.OK
            and bool(self.artifact_path)
            and bool(self.artifact_sha256)
            and bool(self.tool)
        )


def artifact_matches(artifact_path: str, expected_sha: str) -> bool:
    """O arquivo de artefato EXISTE e seu conteúdo bate com o hash gravado?

    É o que separa "campos preenchidos" de "prova real preservada": um caminho
    inexistente ou um hash forjado NÃO passam aqui.
    """
    if not artifact_path or not expected_sha:
        return False
    p = Path(artifact_path)
    if not p.is_file():
        return False
    try:
        # hash sobre BYTES (evita tradução de \r\n do Windows no round-trip)
        return hashlib.sha256(p.read_bytes()).hexdigest() == expected_sha
    except OSError:
        return False


def preserve_artifact(dir_path: Path, evidence_id: str, raw_output: str) -> tuple[str, str]:
    """Salva a saída bruta (redigida) como artefato e devolve (caminho, sha256).

    O hash é calculado sobre o conteúdo já redigido — é o que fica preservado.
    """
    dir_path.mkdir(parents=True, exist_ok=True)
    safe = redact(raw_output)
    data = safe.encode("utf-8", "replace")
    path = dir_path / f"{evidence_id}.txt"
    path.write_bytes(data)   # bytes: hash bate no round-trip (sem \r\n do Windows)
    return (str(path), hashlib.sha256(data).hexdigest())
