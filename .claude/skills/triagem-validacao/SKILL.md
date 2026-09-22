---
name: triagem-validacao
description: Use ao triar e VALIDAR qualquer achado de segurança antes de marcá-lo como confirmado. Aplica o portão suspeita→confirmado com evidência mecânica, reduz falso-positivo e afirma explorabilidade só no nível comprovado. Palavras-chave, achado, validação, triagem, falso positivo, confirmar, evidência, CVE. Não use para coletar dados brutos — use as skills de teste específicas.
---

> **ADAPTADO DE RAPTOR (MIT), projeto comunitário.** Origem:
> `.claude/skills/audit/SKILL.md` e `.claude/skills/exploitability-validation/`
> (gates G2/G3/G7, pipeline estágios letra=LLM/número=mecânico, veredito
> tri-estado, GATE POC-EVIDENCE, NO-HEDGING). Repositório
> https://github.com/gadievron/raptor (commit a1996f8),
> © 2025-2026 Evron, Cuthbert, Dullien, Bargury, Cartwright. Ver docs/integracoes.md.

# Triagem e validação de achados

Tese central (RAPTOR): **o LLM só levanta HIPÓTESE; quem dá o veredito é a
evidência mecânica.** Concordância entre agentes NÃO é evidência.

## Ciclo obrigatório

1. **Toda hipótese entra como SUSPEITA.** Registre em suspeitas, não em achados.
2. **Ground-truth por ferramenta (G2).** Um achado só sai de suspeita com ≥1
   evidência coletada por ferramenta, com artefato preservado (origem, horário,
   ferramenta, parâmetros, resultado, hash). Sem isso, permanece suspeita.
3. **Sem laço de auto-crítica (G3).** Não "reanalise" sem uma NOVA chamada de
   ferramenta. Reflexão sozinha infla falso-positivo.
4. **Alcançabilidade / aplicabilidade (G7).** Confirme que o alvo/versão/rota é
   realmente afetado. Se não há caminho observável, é suspeita/dormant.
5. **Explique o contrário.** Liste explicações alternativas e tente refutar o
   achado (revisor adversarial). Se refutado → DESCARTADO, com o motivo.

## Veredito tri-estado (não rebaixe abstenção)

`is_true_positive` / `is_exploitable` ∈ {True, False, None}. `None` = abstenção
(análise falhou/malformada), **não** é negativo. Só confirme com `True` explícito.

## Graduação de evidência (mais forte → mais fraca)

reproduzido > observado_por_ferramenta > config_comprovada > resposta_http >
heurística(LLM/padrão). **Explorabilidade só pode ser afirmada com evidência
reproduzida.** "Rodou sem erro" NÃO é evidência (GATE POC-EVIDENCE).

## CVE

Só cite CVE com fonte consultada (ex.: nvd.nist.gov) E verificação de que se
aplica ao componente/versão encontrados. Sem os dois → não afirme a CVE.

## Como aplicar no projeto

- Grave evidência com o executor: `agente exec --target <alvo> -- <comando>`
  (o artefato bruto é preservado e redigido automaticamente).
- Antes de publicar como confirmado, verifique o portão:
  `python -c "from agente.findings import ..."` — ou use a CLI de finding.
  O sistema RECUSA confirmar sem os campos, artefatos e validação exigidos.
- Erros/timeouts/sem-acesso viram LIMITAÇÃO (verificação inconclusiva), nunca
  achado. Relatório sem achados informa cobertura e limitações — não prova
  ausência de vulnerabilidade.
