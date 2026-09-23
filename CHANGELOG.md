# Changelog

Formato baseado em Keep a Changelog. Datas em AAAA-MM-DD.

## [Não lançado]

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
