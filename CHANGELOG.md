# Changelog

Formato baseado em Keep a Changelog. Datas em AAAA-MM-DD.

## [Não lançado]

### Adicionado (comprovação com Claude REAL 2026-09-23)
- **Laboratório executável** (`test_lab_confirma`): app loopback + 2 contas de
  teste, versão vulnerável e corrigida. Comprova o motor: CONFIRMA IDOR com
  evidência reproduzida, RECONHECE a correção (probe → 403) e RECUSA confirmação
  forjada (sem evidência ligada).
- **Trilha de auditoria dos hooks** (`logs/hook-audit.log`): registra cada
  chamada do PreToolUse (prova de disparo). Teste em `test_hook`.
- **`docs/limite-execucao-ia.md`**: documenta o bloqueio do classificador ao
  disparo de scan ofensivo pela IA e classifica o produto como semiautomático.

### Corrigido (comprovação com Claude REAL 2026-09-23)
- Relatório mostrava `0/0/0` escondendo achados `inconclusivo`; agora há seção
  **INCONCLUSIVOS** no corpo (`test_report`).
- Exportação de trechos dizia "segredos redigidos" mas vazava `sk_live`/JWT;
  redação corrigida (nomes camelCase/underscore + formatos JWT/Stripe/AWS/
  GitHub/Slack/PEM) — `test_redaction`, `test_codeexport`.
- Versão unificada (fonte única via `importlib.metadata`); fim da divergência
  `__version__` 0.1.0 vs `pyproject` 0.2.0.
- Workspace instalado não leva mais `PYTHONPATH=src` (era só do checkout).

### Corrigido (revisão de sessão 2026-09-23)
- Sessão agora grava MANIFESTO (versão, commit, install_mode, hash_convention).
- Decisões de validação PERSISTIDAS por achado (`finding set-status`: status +
  quem/quando/motivo/alternativas; 'confirmado' passa pelo portão can_confirm).
- `session close` encerra com retrato de cobertura; relatório separa REVISADOS
  de NÃO-REVISADOS (amostragem não vira conclusão ampla).
- Correção honesta: Claude Code É automatizável em CI (`claude -p`); bloqueio é
  auth/orçamento no runner, não impossibilidade.


### Corrigido (revisão externa 2026-09-22)
- **Confirmação exige prova real:** `Evidence`/`can_confirm`/`validate_confirmation`
  agora checam que o **artefato existe** e o **hash bate** (sobre bytes — evita
  tradução de `\r\n` no Windows) e que a **evidência é do mesmo alvo** do achado.
  Campo preenchido com caminho inexistente/hash forjado/alvo divergente **não**
  confirma mais.
- `replay`: método que altera estado não envia nada (nem baseline) sem
  `--com-efeito-colateral`; erro de conexão vira inconclusivo, não achado.
- `scan`: escopo por-execução (só o alvo selecionado); relatório usa o alvo real
  da sessão; `store.add_finding` rebaixa "confirmado" sem prova para "suspeita".
- `executor`: interpretador (python/node) com URL http(s) conta como rede.
- `codereview`: pula projetos aninhados (worktrees/.claude) — corrige 72% de
  ruído de outros projetos; detecta rota sem auth, mass assignment, preço do
  cliente, dado sensível retornado, `select *`, sem rate-limit.

### Adicionado
- **Workspace distribuível:** `agente init-workspace <pasta>` materializa
  CLAUDE.md/.claude(agentes/skills/hooks/commands)/prompts do pacote instalado
  (idempotente, preserva edições). `scan`/`ui` preparam o workspace sozinhos na
  1ª utilização e abrem o Claude na pasta do usuário. Validado no CI (Win+Linux).
- **CI Windows + Linux:** matriz `unittest` em ubuntu e windows (3.11/3.12/3.13)
  + job `instalacao` que faz `pip install` do artefato e roda `agente doctor` em
  caminho com espaço/acento (ambos SO) — verde nos runners reais.
- **Semgrep (SAST real):** `agente sast <pasta>` (roda se instalado); validado no
  CI Linux (job `semgrep-lab`: detecta `eval`, ignora código seguro).
- **KEV/EPSS:** `deps` prioriza os CVEs com CISA KEV (explorado ativamente) e
  FIRST EPSS (probabilidade) — verificado ao vivo e por mock.
- **Importação de HAR:** `replay --har <arquivo>` importa requisições do DevTools.
- **Empacotamento (Bloco 1):** recursos (wordlist, exemplos) viajam no pacote
  (`src/agente/data/`, via importlib.resources); dados graváveis vão para o dir
  do usuário quando instalado (nunca site-packages). Instalação a partir de
  artefato limpo (git archive) em venv novo verificada: `agente doctor` roda
  fora do checkout, sem PYTHONPATH, com wordlist/exemplos resolvidos.
- **Motor de dependências (Bloco 2):** `agente deps <pasta>` consulta a base
  **OSV** (osv.dev) a partir de requirements.txt / package-lock.json. Verificado
  com dados reais (ex.: django 2.2.0 → CVEs reais) e com mock (base indisponível
  = limitação, não "seguro").
- `docs/matriz-capacidades.md`: estado honesto por área (implementado/parcial/não).
- `agente replay` (teste ativo autorizado: IDOR/mass/no-auth/rate).
- `agente review-code` / `scan --code` (SAST-leve local).
- `scan` ponta a ponta + fase 2 no Claude (`/finalizar`), com prova de posse
  obrigatória por alvo.

### Pendências conhecidas (não implementado — ver matriz)
- Integração ZAP/Semgrep/Trivy/OSV; priorização KEV/EPSS.
- Empacotamento testado a partir de release/ZIP; matriz de SO/arch verificada em CI.
- Acesso a banco ao vivo (Supabase `pg_policies`); SSRF ativo; captura HAR/proxy.
- Isolamento forte (sandbox) no Windows.

## [0.1.0] — base
- CLI, escopo, executor controlado, motores de scan, sessões, evidência,
  incorporação de RAPTOR (MIT) e skills ACSK (Apache-2.0).
