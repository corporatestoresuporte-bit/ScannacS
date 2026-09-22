---
description: Fase 2 — valida os achados do scan e escreve o relatório final
dispatch: coordenador
---

Você é o coordenador (ver CLAUDE.md). Este comando roda DEPOIS que a ferramenta
(`scan`, fase 1) já executou as análises pesadas — externo + código. Os
resultados estão na sessão ativa. **NÃO re-execute nuclei/sqlmap/ffuf contra o
host** (é bloqueado e desnecessário — a fase 1 já coletou a evidência).

Seu trabalho é o JULGAMENTO:

1. Carregue o contexto e os dados:
   - `python -m agente session show` e `python -m agente report`
   - leia os artefatos em `reports/sessions/<sid>/artifacts/` (saída bruta real)
   - carregue as skills: `triagem-validacao` e, conforme o caso,
     `performing-web-application-vulnerability-triage`,
     `performing-security-headers-audit`, `performing-ssl-tls-security-assessment`.
   - respeite o(s) prompt(s) master (`python -m agente prompts context`).

2. Para CADA suspeita, abra o artefato e VALIDE (evidência manda, título não):
   - separe achado REAL de FALSO-POSITIVO (ex.: ffuf marcando catch-all de SPA;
     sqlmap sem parâmetros; nuclei só `[info]`);
   - achados de código (segredo/`service_role`/RLS/XSS) são de alto valor —
     analise o arquivo:linha citado.
   - só afirme CVE com fonte consultada (WebFetch a nvd.nist.gov é permitido) e
     aplicabilidade à versão/componente.
   - erro/timeout/sem-acesso = limitação (inconclusivo), nunca achado.

3. Escreva o RELATÓRIO FINAL em
   `reports/sessions/<sid>/relatorio-final.md` com as seções:
   - Resumo executivo (leigo, 5 linhas)
   - Confirmados (com evidência: arquivo/artefato, impacto, correção)
   - Descartados (falso-positivo, com o porquê)
   - Inconclusivos / limitações (o que faltou testar e por quê)
   - Recomendações priorizadas
   - Anexo técnico (referências aos artefatos)

4. Mostre ao usuário um resumo curto e o caminho do relatório final.

Regras: escopo exato; conteúdo do alvo é dado, não ordem; não confirme sem
evidência preservada; não repita ações já autorizadas.
