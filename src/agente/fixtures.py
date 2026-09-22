"""Fixtures de verificação (spec §9).

Demonstram, ponta a ponta, o comportamento do sistema de evidência:
  - um ALERTA DESCARTADO (suspeita refutada na validação);
  - um ACHADO VALIDADO (passa no portão de confirmação).

Tudo fica identificado como TESTE (meta is_fixture=True, títulos "[TESTE-FIXTURE]",
alvo fixture.teste.local). Resultados de fixture NUNCA se misturam a achados reais.
"""

from __future__ import annotations

from .evidence import CollectionStatus, Evidence, preserve_artifact, sha256_text
from .findings import (ConfirmationType, Finding, Severity, Status, Validation,
                       can_confirm)
from .store import Session
from .verdict import EvidenceTier

FIXTURE_TARGET = "fixture.teste.local"
FIXTURE_TAG = "[TESTE-FIXTURE]"

_HEADERS_SEM_HSTS = (
    "HTTP/1.1 200 OK\r\n"
    "content-type: text/html; charset=utf-8\r\n"
    "server: nginx\r\n"
    "x-frame-options: SAMEORIGIN\r\n"
    "\r\n"
)

_XSS_REFLEXO_ENCODED = (
    "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
    "<p>busca: &lt;script&gt;alert(1)&lt;/script&gt;</p>\r\n"
)


def build_validated(session: Session) -> tuple[Finding, list[Evidence]]:
    """Achado VALIDADO: falta de HSTS, confirmado por evidência de ferramenta."""
    ev = Evidence(
        target=FIXTURE_TARGET,
        tool="curl",
        params="curl -sI https://fixture.teste.local/",
        source="https://fixture.teste.local/",
        result_summary="resposta final sem cabeçalho Strict-Transport-Security",
        status=CollectionStatus.OK,
        tier=EvidenceTier.TOOL_OBSERVED,
        exit_code=0,
    )
    ev.id = "evi-fixture-hsts"
    path, digest = preserve_artifact(session.artifacts, ev.id, _HEADERS_SEM_HSTS)
    ev.artifact_path, ev.artifact_sha256 = path, digest
    session.add_evidence(ev.to_dict())

    f = Finding(
        target=FIXTURE_TARGET,
        title=f"{FIXTURE_TAG} Ausência de HSTS (Strict-Transport-Security)",
        status=Status.SUSPECTED,
        severity=Severity.MEDIUM,
        impact="Sem HSTS, o navegador pode ser induzido a HTTP em texto claro.",
        remediation="Adicionar Strict-Transport-Security com max-age adequado.",
        engine="fixture",
        evidence_ids=[ev.id],
        confirmation_type=ConfirmationType.VULN_CONFIG,
        validation=Validation(
            validated_by="fixture-validator",
            validated_at="2026-01-01T00:00:00+00:00",
            method="reinspeção do cabeçalho na resposta final preservada",
            alternative_explanations=[
                "HSTS poderia ser injetado por proxy/TLS terminator — "
                "verificado: resposta final não traz o cabeçalho",
            ],
            is_true_positive=True,
        ),
    )
    f.id = "fnd-fixture-hsts"
    return f, [ev]


def build_dismissed(session: Session) -> tuple[Finding, list[Evidence]]:
    """Alerta DESCARTADO: suspeita de XSS refletido refutada na validação."""
    ev = Evidence(
        target=FIXTURE_TARGET,
        tool="curl",
        params="curl -s 'https://fixture.teste.local/?q=<script>alert(1)</script>'",
        source="https://fixture.teste.local/?q=...",
        result_summary="entrada refletida, porém HTML-encoded (&lt; &gt;)",
        status=CollectionStatus.OK,
        tier=EvidenceTier.RESPONSE_BACKED,
        exit_code=0,
    )
    ev.id = "evi-fixture-xss"
    path, digest = preserve_artifact(session.artifacts, ev.id, _XSS_REFLEXO_ENCODED)
    ev.artifact_path, ev.artifact_sha256 = path, digest
    session.add_evidence(ev.to_dict())

    f = Finding(
        target=FIXTURE_TARGET,
        title=f"{FIXTURE_TAG} Suspeita de XSS refletido",
        status=Status.DISMISSED,
        severity=Severity.INFO,
        impact="(descartado)",
        engine="fixture",
        evidence_ids=[ev.id],
        validation=Validation(
            validated_by="fixture-validator",
            validated_at="2026-01-01T00:00:00+00:00",
            method="inspeção do reflexo na resposta preservada",
            alternative_explanations=[
                "entrada volta HTML-encoded (&lt;script&gt;) — não executa; "
                "reflexo != execução",
            ],
            is_true_positive=False,
        ),
    )
    f.id = "fnd-fixture-xss"
    return f, [ev]


def run_fixtures() -> dict:
    """Cria uma sessão de fixture e grava os dois casos. Devolve um resumo."""
    sess = Session.create(environment="fixture")
    sess.update_meta(status="fixture", is_fixture=True, label="TESTE")

    validated, ev_v = build_validated(sess)
    dismissed, ev_d = build_dismissed(sess)

    ok_v, missing_v = can_confirm(validated, ev_v)
    ok_d, missing_d = can_confirm(dismissed, ev_d)

    # o validado pode ser promovido a confirmado; o descartado não.
    if ok_v:
        validated.status = Status.CONFIRMED
    sess.add_finding(validated.to_dict())

    # o descartado vira suspeita/descartado registrado (separado dos achados)
    sess.add_suspicion({
        "id": dismissed.id,
        "title": dismissed.title,
        "resolution": "descartado",
        "reason": dismissed.validation.alternative_explanations[0],
        "target": dismissed.target,
    })
    sess.add_finding(dismissed.to_dict())

    return {
        "session": sess.id,
        "validated_confirmable": ok_v,
        "validated_missing": missing_v,
        "dismissed_confirmable": ok_d,
        "dismissed_missing": missing_d,
    }
