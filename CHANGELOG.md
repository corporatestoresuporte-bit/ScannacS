# Changelog

Formato baseado em Keep a Changelog. Datas em AAAA-MM-DD.

## [Não lançado]

### Adicionado (2026-09-23)
- **Sessão autenticada vale pro scan inteiro:** o cURL colado aplica cookie/token
  a TODOS os motores (headers/fingerprint/bundle/graphql-ws), não só ao replay —
  passa WAF/challenge (Cloudflare/Vercel) e login, alcançando a app real.
  `engines.set_session_headers`. test_session_headers.

### Corrigido — Semgrep travando por horas (2026-09-24)
- semgrep gera `semgrep-core`/`osemgrep` como NETO; matar só o pai deixava o
  neto vivo segurando o pipe -> subprocess.run pendurava (7-17h "running").
  Agora run_semgrep usa Popen + teto real (300s) e MATA A ÁRVORE (taskkill /T /
  killpg) no timeout. Provado: retorna no teto e não deixa semgrep-core vivo.

### Corrigido — desempenho em repos grandes (2026-09-23)
- Semgrep agora exclui node_modules/dist/build/out/.next/coverage/vendor + teto
  de tempo por regra (antes varria node_modules e levava ~1h). codereview também
  pula dist/build/out/.turbo/.cache/vendor/bower_components/.output/.vercel.

### Corrigido (2026-09-23)
- Cada "Iniciar" no app cria uma **sessão NOVA** (não acumula achados de scans
  anteriores na mesma sessão — antes o relatório inflava com duplicatas).
- `Session.create` garante id ÚNICO mesmo com 2 scans no mesmo segundo (sufixo).

## [0.2.0-beta.3] - 2026-09-23

Pré-release beta. Fecha os gaps de cobertura: segredo no bundle (SPA/Supabase),
força-bruta defensiva do login, captura de sessão autenticada (rota logada/IDOR),
SSRF ativo, GraphQL introspection + WebSocket handshake, e 403 de WAF. Sandbox
forte segue como limitação documentada (contenção lógica: escopo+posse+hook+
limites). Preserva beta.1 e beta.2. 154 testes; CI Ubuntu+Windows.

### Adicionado — GraphQL + WebSocket (2026-09-23)
- Motor builtin `api-graphql-ws` (roda p/ site): **GraphQL** descobre o endpoint
  (caminhos comuns) e checa se a **introspection** está exposta (schema inteiro
  = info disclosure, normalmente off em prod); **WebSocket** acha `ws://|wss://`
  no HTML/JS e faz o **handshake** sem credencial (101 = aceita anônimo). Só
  leitura; sem mutation. `apiprobe.graphql_introspection/discover_graphql/
  find_ws_urls/ws_handshake`. test_apiprobe (loopback on/off). 154 testes.

### Adicionado — SSRF ativo autorizado (2026-09-23)
- `ssrf.run_ssrf` + `agente ssrf` + campo "SSRF no parâmetro" na captura
  autenticada: testa se um parâmetro que recebe URL faz o SERVIDOR buscar
  endereço proibido. Usa **canário em loopback** (detecta o fetch server-side,
  mesmo cego, quando o alvo o alcança) + sondas de **metadados de nuvem**
  (AWS/GCP, detecção in-band). Guardrails: escopo+posse; método seguro (ou
  opt-in); payloads limitados; canário só em loopback. SSRF cego sem canário
  alcançável é reportado como LIMITAÇÃO (precisa coletor externo/OOB).
  `find_url_params` acha parâmetros candidatos. test_ssrf (loopback vuln/seguro).

### Adicionado — captura de sessão autenticada (2026-09-23)
- `authsession.parse_curl`: cola o "Copy as cURL (bash)" do DevTools (requisição
  logada) e extrai método/URL/headers (cookie/token)/corpo. Token fica REDIGIDO
  no relatório (`redacted_headers`).
- `agente replay --curl <arquivo>` + opção **"Sessão autenticada"** na interface:
  testa a rota LOGADA (no-auth + IDOR com o id de outro usuário). Só leitura
  (GET/HEAD); método que muda estado é pulado; segue gated por escopo+posse.
  Abre caminho pro IDOR/BOLA real (ver a página como usuário logado).
- Testes: `test_authsession` (6) + smoke da UI. 144 testes verdes.

### Adicionado — teste de resistência do login (força-bruta DEFENSIVA) (2026-09-23)
- Novo módulo `authbf` + `agente authbf` + opção na interface: verifica se o
  **seu** login barra força-bruta (rate-limit/bloqueio). É defensivo — usa
  **contas de TESTE** que você fornece e **para** ao detectar 429/403/lockout ou
  sucesso. Guardrails DUROS: só host no escopo com posse comprovada; POST exige
  opt-in; tetos 25 tentativas / ≥0,5s / ≤120s. Achados: "login sem proteção
  anti-força-bruta" (médio), "credencial de teste aceita" (alto), ou registra
  "proteção presente" (descartado) quando o login bloqueia. Nunca grava senha no
  artefato. Distinto da descoberta de conteúdo (caminhos). test_authbf (loopback).

### Adicionado/Corrigido — cobertura de SPA + WAF (2026-09-23)
- **Segredo no bundle (novo motor `bundle-audit`)**: baixa o HTML + os scripts
  MESMO-ORIGEM (leitura) e acha segredo servido ao cliente — Supabase
  **service_role** (JWT decodificado), Stripe `sk_live`, AWS `AKIA`, GitHub
  `ghp_`, Google API key, chave PEM. É o risco real de SPA/Supabase que scan
  externo comum não pega; a amostra no artefato é **redigida** (não vaza o
  segredo). Anon key do Supabase (pública por design) NÃO vira achado.
- **403 de WAF corrigido**: os motores embutidos (cabeçalhos/fingerprint) usam
  cabeçalhos de navegador real + fallback HEAD→GET, então Cloudflare/Vercel não
  devolvem mais "sem-acesso".
- Testes: `test_bundle` (loopback). 132 testes verdes.

### Adicionado — "Preparar ambiente" pela interface (2026-09-23)
- Botão **Preparar ambiente** no app: detecta, instala e valida as ferramentas do
  perfil (alvos escolhidos), com progresso e erros em português. `src/agente/
  toolprep.py` + endpoints `/api/diagnose`, `/api/prepare`, `/api/prepare_state`.
- **Diagnóstico rico** distingue: `funcional` (verde = versão executa), `nao_instalada`,
  `instalada_nao_localizada` (fora do PATH do executor), `incompativel`,
  `precisa_config`. Classifica cada ferramenta por alvo: **necessária / complementar
  / não aplicável** (essencial nunca aparece como "opcional"). Inclui Semgrep, Trivy
  e ZAP no diagnóstico.
- **Instalação de fontes oficiais**, sem sudo/admin: pip (semgrep/sslyze/wafw00f),
  binário oficial (trivy/nuclei/ffuf via release do GitHub → `DATA_HOME/bin`), git
  (sqlmap + wrapper). `config.BIN_DIR` + `augment_path()` deixam o **executor
  consistente** (acha o que a interface instalou). nmap e ZAP: conduzidos como
  **intervenção** (sistema/admin ou Docker), com texto claro e **Tentar de novo**
  sem reinstalar tudo.
- Correções cross-OS: wrapper `.cmd` do sqlmap usa **caminho 8.3** (evita bug de
  acento em `Lázaro`); `_run` executa wrappers `.cmd` via `cmd /c`.
- Força bruta de **autenticação** continua **desabilitada** e marcada como pendente.
- CI: `test_toolprep` (hermético) + job `toolprep-lab` (Ubuntu) que instala e
  **valida semgrep+trivy funcionais** de verdade.

## [0.2.0-beta.2] - 2026-09-23

Pré-release beta semiautomática com o **app web** (`scan` abre a interface).
Preserva a beta.1 (tag e artefatos). Força bruta de **autenticação** continua
**desabilitada** e marcada como pendente.

### Adicionado (app web — `scan` abre a interface 2026-09-23)
- **App web local (dark)**: `scan` (ou `agente web`/`agente ui`) sobe um servidor
  em 127.0.0.1 e abre o navegador com um assistente que conduz todo o fluxo:
  escolher alvos (código + site + servidor no mesmo projeto, escopo explícito),
  modo (Completa / Só ferramentas / Só Claude), provar posse pela interface,
  ver **progresso real** dos scanners, cancelar, e ver o relatório.
- **Executor próprio do app** reusa os motores existentes (engines/codereview/
  deps/sast/iac), respeitando escopo + posse + autorização; seleção automática
  dos motores aplicáveis; ferramentas ausentes aparecem como tal (não escondidas).
- **Cancelamento real** de processos externos (`engines.run_engine` ganhou
  `on_proc`/`should_cancel`; termina a árvore de processo no Windows/Linux).
- **Passagem automática pro Claude** (modo Completa): salva evidências + relatório
  preliminar, materializa o workspace da MESMA sessão, roda o Claude com os prompts
  master + RAPTOR/ACSK, persiste as decisões e gera o relatório final — sem copiar
  prompt nem trocar de terminal.
- Posse de **loopback** (127.0.0.1/localhost) é automática (é a sua máquina).
- CI: teste `test_webui` (matriz Win+Linux) + smoke do app a partir do wheel.

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
