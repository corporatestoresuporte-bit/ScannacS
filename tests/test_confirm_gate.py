"""Portão de confirmação de achados (spec §7)."""

import tempfile
import unittest
from pathlib import Path

import _pathshim  # noqa: F401

from agente.evidence import (CollectionStatus, Evidence, preserve_artifact)
from agente.findings import (ConfirmationType, Finding, Status, Validation,
                             can_confirm)
from agente.verdict import EvidenceTier


def _good_evidence(tier=EvidenceTier.TOOL_OBSERVED, target="meusite.com"):
    # artefato REAL preservado (arquivo existe + hash bate) via a função real
    path, digest = preserve_artifact(
        Path(tempfile.mkdtemp()), "e", "HTTP/1.1 200 OK\nraw preservado\n")
    e = Evidence(target=target, tool="curl", params="curl -sI ...",
                 status=CollectionStatus.OK, tier=tier)
    e.artifact_path = path
    e.artifact_sha256 = digest
    return e


def _base_finding(**kw):
    f = Finding(target="meusite.com", title="teste",
                confirmation_type=ConfirmationType.VULN_CONFIG,
                validation=Validation(validated_by="v", validated_at="t",
                                      alternative_explanations=["x"],
                                      is_true_positive=True))
    for k, v in kw.items():
        setattr(f, k, v)
    return f


class TestConfirmGate(unittest.TestCase):
    def test_confirmavel_com_tudo(self):
        ok, missing = can_confirm(_base_finding(), [_good_evidence()])
        self.assertTrue(ok, msg=str(missing))

    def test_sem_evidencia_bloqueia(self):
        ok, missing = can_confirm(_base_finding(), [])
        self.assertFalse(ok)
        self.assertTrue(any("evidência" in m for m in missing))

    def test_artefato_inexistente_nao_confirma(self):
        # campos preenchidos mas arquivo não existe / hash forjado
        e = _good_evidence()
        e.artifact_path = "nao/existe/e.txt"
        e.artifact_sha256 = "f" * 64
        ok, _ = can_confirm(_base_finding(), [e])
        self.assertFalse(ok)

    def test_evidencia_de_outro_alvo_nao_confirma(self):
        # evidência real, mas de OUTRO alvo
        e = _good_evidence(target="outro-site.com")
        ok, _ = can_confirm(_base_finding(), [e])  # finding é meusite.com
        self.assertFalse(ok)

    def test_abstencao_nao_confirma(self):
        f = _base_finding()
        f.validation.is_true_positive = None  # abstenção
        ok, missing = can_confirm(f, [_good_evidence()])
        self.assertFalse(ok)
        self.assertTrue(any("is_true_positive" in m for m in missing))

    def test_sem_alternativas_bloqueia(self):
        f = _base_finding()
        f.validation.alternative_explanations = []
        ok, missing = can_confirm(f, [_good_evidence()])
        self.assertFalse(ok)

    def test_sem_confirmation_type_bloqueia(self):
        f = _base_finding(confirmation_type=None)
        ok, _ = can_confirm(f, [_good_evidence()])
        self.assertFalse(ok)

    def test_explorabilidade_exige_reproduzido(self):
        f = _base_finding(exploitability="RCE remoto")
        # evidência só observada por ferramenta, não reproduzida
        ok, missing = can_confirm(f, [_good_evidence(EvidenceTier.TOOL_OBSERVED)])
        self.assertFalse(ok)
        self.assertTrue(any("reproduzida" in m for m in missing))
        # com evidência reproduzida, passa
        ok2, _ = can_confirm(f, [_good_evidence(EvidenceTier.REPRODUCED)])
        self.assertTrue(ok2)

    def test_cve_exige_fonte_e_aplicabilidade(self):
        f = _base_finding(cve="CVE-2024-0001")
        ok, missing = can_confirm(f, [_good_evidence()])
        self.assertFalse(ok)
        self.assertTrue(any("fonte" in m for m in missing))
        f.cve_source = "nvd.nist.gov"
        f.cve_applicability = "componente X v1.2 confirmado"
        ok2, _ = can_confirm(f, [_good_evidence()])
        self.assertTrue(ok2)


if __name__ == "__main__":
    unittest.main()
