# Integrações de terceiros

Registro dos componentes incorporados dos dois repositórios exigidos. Para cada
um: origem (repo + arquivo + commit), finalidade e local no projeto, adaptações,
licença/atribuição e verificação. Licenças completas em `THIRD_PARTY_LICENSES/`.

> Aviso de marca: **Anthropic-Cybersecurity-Skills** é um projeto COMUNITÁRIO de
> `mukul975`, NÃO um produto oficial da Anthropic. Nada aqui implica autoria da
> Anthropic.

## Fontes

| Repo | URL | Commit | Licença | Copyright |
|------|-----|--------|---------|-----------|
| RAPTOR | https://github.com/gadievron/raptor | `a1996f8` | MIT | 2025-2026 Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, John Cartwright |
| Anthropic-Cybersecurity-Skills (comunitário) | https://github.com/mukul975/Anthropic-Cybersecurity-Skills | `54a7988` | Apache-2.0 | 2026 mukul975 (Mahipal) |

---

## Componentes do RAPTOR (MIT)

### R1 — Veredito tri-estado (suspeita/confirmado/abstenção)
- **Origem:** `core/run/finding_status.py` (`read_verdict`, `VERDICT_KEYS`).
- **No projeto:** `src/agente/verdict.py` (`read_verdict`, `VERDICT_KEYS`).
- **Finalidade:** não rebaixar abstenção (None) a veredito negativo; só `True`
  explícito confirma. Base da redução de falso-positivo (spec §7).
- **Adaptação:** traduzido; mantida a semântica e o alerta contra truthiness.
- **Verificação:** `tests/test_confirm_gate.py::test_abstencao_nao_confirma`.

### R2 — Graduação de evidência (EvidenceTier)
- **Origem:** `core/evidence/__init__.py` (`EvidenceTier`, `TIER_RANK`, `stronger`).
- **No projeto:** `src/agente/verdict.py` (`EvidenceTier`, `TIER_RANK`, `stronger`,
  `is_mechanical`).
- **Finalidade:** ranquear a força da evidência; explorabilidade só no nível
  reproduzido; heurística/LLM é o mais fraco.
- **Adaptação:** tiers reordenados para auditoria de app/rede (reproduzido >
  observado_por_ferramenta > config_comprovada > resposta_http > heurística).
- **Verificação:** `tests/test_confirm_gate.py::test_explorabilidade_exige_reproduzido`.

### R3 — Barreira de execução (hooks de allowlist)
- **Origem:** `.claude/hooks/bash-command-allowlist.py` e
  `webfetch-domain-allowlist.py` (rejeição de metacaracteres/substituição de
  comando, https-only, falha fechada).
- **No projeto:** `src/agente/hook.py` + `src/agente/executor.py` +
  `tools/guard.py`, ligados por `.claude/settings.json` (PreToolUse).
- **Finalidade:** impor o executor controlado na sessão — nenhum agente contorna
  o escopo (spec §8).
- **Adaptação:** allowlist por HOST derivado do escopo (não prefixo de comando);
  rejeição de `$(` / crase em ação de rede; allowlist de pesquisa (nvd/cve) para
  WebFetch; contrato de saída do hook (exit 2 = bloqueia) do Claude Code.
- **Verificação:** `tests/test_hook.py`, `tests/test_executor.py`; e2e:
  `agente exec` bloqueia host fora do escopo.

### R4 — Doutrina de auditoria/validação (gates)
- **Origem:** `.claude/skills/audit/SKILL.md` (G2 tool-grounded, G3 sem
  auto-crítica, G7 alcançabilidade) e `.claude/skills/exploitability-validation/`
  (estágios letra=LLM/número=mecânico, GATE POC-EVIDENCE, NO-HEDGING).
- **No projeto:** `.claude/skills/triagem-validacao/SKILL.md` +
  portão em código `src/agente/findings.py::can_confirm`.
- **Finalidade:** portão suspeita→confirmado com evidência mecânica (spec §7).
- **Adaptação:** condensado; convertido em checagem executável (`can_confirm`)
  que RECUSA confirmar sem campos/artefatos/validação.
- **Verificação:** `tests/test_confirm_gate.py` (7 casos); `agente fixtures run`.

### R5 — Coordenação (orquestrador + especialistas)
- **Origem:** `.claude/skills/oss-forensics/orchestration/SKILL.md` (orquestrador
  único, fan-out paralelo por Task, workdir compartilhado, resultados em arquivo,
  laços limitados, allowlist de agentes, entrada = dado não-confiável).
- **No projeto:** `.claude/skills/coordenacao-agentes/SKILL.md`, `CLAUDE.md`,
  `.claude/agents/*`.
- **Finalidade:** coordenação com contrato de tarefa (objetivo/alvo/ferramentas/
  prazo/formato), concorrência e limites (spec §6).
- **Adaptação:** agentes de auditoria próprios; limites de rate compartilhados por
  alvo aplicados pelo executor (`executor.check_and_consume`).
- **Verificação:** arquivos presentes; `agente doctor` lista sessão; verificação
  de carregamento pelo Claude Code (ver §Verificação de integração real).

### R6 — Iniciador (sequência de bootstrap)
- **Origem:** `bin/raptor` (higiene de ambiente → checa python/claude → seed de
  sessão → `exec claude -n <NOME> "/<comando>"`) + wiring de hooks em
  `.claude/settings.json`.
- **No projeto:** `iniciar.ps1` + `Abrir-Agente.cmd` + `agente ui`.
- **Finalidade:** abrir a interface nativa do Claude Code como centro (spec §1).
- **Adaptação:** REIMPLEMENTADO em PowerShell (o original é POSIX). Portada a
  intenção (checa python/claude, prepara .venv, resumo, abre `claude -n
  AgenteAuditoria /auditoria`). A blindagem POSIX (PATH scrub, umask, ulimit,
  namespaces) não tem equivalente nativo no Windows — ver Limitações.
- **Verificação:** `.\iniciar.ps1 -NoLaunch` prepara e roda `agente doctor`.

### R7 — Agentes + checador adversarial
- **Origem:** padrão de frontmatter dos 18 `.claude/agents/*.md` e os agentes
  `exploitability-validator-agent` / `*-checker-agent` (validação adversarial).
- **No projeto:** `.claude/agents/validador-achados.md` (adversarial) +
  `investigador-{web,api,auth,infra}.md`.
- **Adaptação:** papéis de auditoria próprios; ferramentas restritas; regras de
  escopo/evidência embutidas.
- **Verificação:** arquivos presentes; carregáveis pelo Claude Code.

---

## Componentes do Anthropic-Cybersecurity-Skills (Apache-2.0)

### A1 — Skills de teste (8, curadas)
- **Origem:** `skills/<nome>/` (SKILL.md + scripts + references + LICENSE).
- **No projeto:** `.claude/skills/<nome>/` (mesmos nomes):
  `performing-security-headers-audit`, `performing-ssl-tls-security-assessment`,
  `testing-for-xss-vulnerabilities`, `exploiting-sql-injection-vulnerabilities`,
  `testing-for-broken-access-control`, `testing-api-security-with-owasp-top-10`,
  `testing-for-json-web-token-vulnerabilities`,
  `performing-web-application-vulnerability-triage`.
- **Finalidade:** procedimentos para web, API, autenticação, infra e triagem
  (spec §3).
- **Adaptação:** cada `SKILL.md` recebeu um banner marcando o arquivo como
  MODIFICADO (exigência Apache §4b) + regras deste projeto (escopo, executor
  controlado, evidência, dado≠instrução). Conteúdo metodológico preservado.
  `LICENSE` (Apache-2.0) mantido em cada skill.
- **Verificação:** `tests/test_integracoes.py` confere presença + banner.

### A2 — Mapeamento OWASP (taxonomia/rubrica)
- **Origem:** `mappings/owasp/README.md`.
- **No projeto:** `docs/referencia/owasp-mapping.md`.
- **Finalidade:** rubrica de classificação para triagem/relatório.
- **Adaptação:** copiado como referência; não modificado.

---

## Limitações e integrações incompletas (honestidade)

- **Sandbox do RAPTOR NÃO portado.** `core/sandbox/` e `libexec/raptor-run-
  sandboxed` usam namespaces Linux + Landlock + seccomp (ou seatbelt no macOS);
  não há back-end nativo no Windows. **Mitigação atual:** portão de escopo +
  hook PreToolUse (executor controlado) + permissões do Claude Code. Isolamento
  forte (WSL2/containers) fica como trabalho futuro.
- **Ferramentas externas das skills ACSK** (Burp, sqlmap, sslyze, nmap, jwt_tool)
  não são empacotadas. As skills só executam se a ferramenta estiver instalada, e
  sempre via `agente exec` (dentro do escopo). Sem a ferramenta → verificação
  inconclusiva (limitação), não achado.
- **`cc_trust` (varredura de repo não-confiável) não portado** — auditamos
  hosts, não abrimos repositórios de terceiros no Claude Code.
- **Pacotes Python pesados do RAPTOR** (orchestrator, CodeQL, fuzzing) não
  incorporados — fora do escopo desta etapa; a engine CodeQL tem licença de
  uso não-comercial.
- **Extração de host do executor é heurística** (falha fechada): comando de rede
  sem host claro ou com substituição de comando é NEGADO por precaução.
- **Detecção de rede por lista de nomes** cobre ferramentas conhecidas +
  interpretadores (python/node/…) com URL http(s). NÃO é isolamento real: um
  script muito criativo pode escapar. Garantia forte exige sandbox (não portado
  no Windows — ver acima). Falha fechada é o mitigador.
- **Rate-limit por-ferramenta é best-effort** (ex.: ffuf com `-rate`); o teto do
  executor conta por invocação de motor, não requisição-a-requisição interna de
  cada scanner. Números anunciados são aproximações, não medição de tráfego.
- **Revisão externa (22/09/2026):** corrigidos — replay não envia método que
  muda estado sem `--com-efeito-colateral` (falha fechada antes de qualquer
  envio); `scan` roda só o alvo selecionado (escopo por-execução); `confirmado`
  sem evidência utilizável é rebaixado a `suspeita` no gravador; erro de conexão
  no replay não vira achado. Ver histórico git.
