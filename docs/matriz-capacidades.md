# Matriz de capacidades (v0.1) — o que ESTÁ e o que NÃO está implementado

Rastreável e honesta. `✅ implementado` = há motor + evidência + teste.
`🟡 parcial` = existe, com limite claro. `❌ não` = ainda não há (não prometa).

Referências de requisito: OWASP ASVS/WSTG e API Security 2023 (ver README/links).

| Área (Seção 7) | Estado | Motor/skill | Evidência | Limite honesto |
|---|---|---|---|---|
| Inventário e exposição | 🟡 | `http-fingerprint`, `nmap`, `ffuf` | headers/portas/paths | SPA responde 200 a tudo (catch-all) — `ffuf -ac` mitiga; sem descoberta de rota logada |
| CVEs e dependências | 🟡 | `deps-osv` (`agente deps`) + nuclei | advisory OSV + KEV/EPSS | Lê lockfiles, consulta osv.dev (real) e prioriza com CISA KEV + FIRST EPSS. **Sem** imagens de container. "Afetada" != exploração |
| Código e cadeia | 🟡 | `codereview` + `sast` (Semgrep) + `iac` (Trivy) + **`bundle-audit`** | arquivo:linha / artefato | codereview + Semgrep + Trivy; **bundle-audit** baixa o JS servido e acha segredo no cliente (service_role/sk_live/AWS/GitHub) — pega o risco de SPA que o scan externo não via. Sem fluxo interprocedural |
| Autenticação e sessão | 🟡 | `replay` (no-auth) + **captura autenticada (cURL)** + `authbf` | resposta preservada | Cola o "Copy as cURL" logado e testa rota LOGADA; `authbf` mede resistência do login a força-bruta (contas de teste + limites). Sem OAuth/OIDC completo nem teste de expiração/revogação |
| Autorização e privilégios | 🟡 | `replay` (IDOR/BOLA/mass) + sessão autenticada | resposta preservada + confirmação em lab | IDOR confirmada COM evidência em lab (`test_lab_confirma`) e **IDOR autenticado** via cURL capturado (id de outro usuário). Em alvo real ainda ajuda ter 2 contas de teste |
| Entrada e processamento | 🟡 | `sqlmap`, `codereview` (XSS) | saída sqlmap / arquivo:linha | Sem template injection / traversal / deserialização ativos |
| Navegador e transporte | 🟡 | `tls` (✅), `cabecalhos-seguranca` | handshake / headers | TLS forte ✅; CSP/CORS/CSRF/cache: só presença de header, sem teste ativo |
| APIs e consumo | 🟡 | `replay` + `dast` (ZAP) + **`api-graphql-ws`** | resposta preservada | ZAP baseline; **GraphQL** (introspection exposta) + **WebSocket** (handshake sem-auth). Sem fuzzing profundo de schema |
| Requisições e replay | ✅ | `replay` (+ `--har`) | resposta + baseline | Importa HAR; controle de efeito colateral. Proxy dedicado ainda não |
| Banco e Supabase | 🟡 | `codereview` (RLS em migrations) + `bundle-audit` | arquivo:linha / bundle | RLS por migrations + **service_role vazada no bundle** (externo). **Não acessa o banco ao vivo** (`pg_policies` real precisa de credencial) |
| Servidor, firewall, nuvem | 🟡 | `nmap` (externo) | saída nmap | Sem acesso SSH/IAM/K8s; scan externo só vê exposição observável |
| Integrações e lógica | 🟡 | `codereview` (preço/webhook) | arquivo:linha | Sem invariantes de negócio automatizadas |
| SSRF e fronteiras internas | 🟡 | `ssrf` (canário loopback + metadados nuvem) | canário/resposta | Ativo in-band: canário pega o fetch server-side; sondas AWS/GCP. **SSRF cego** sem canário alcançável precisa de coletor externo (OOB) — limitação |
| Operação e dados sensíveis | 🟡 | redação em log/artefato | — | Sem checagem de backup/recuperação |

## Motores reais hoje
Embutidos (stdlib): `cabecalhos-seguranca`, `tls`, `http-fingerprint`.
Externos (se instalados): `nmap`, `nuclei`, `sqlmap`, `ffuf` (+ wrappers de outros).
Análise local: `codereview` (SAST-leve). Ativo: `replay`.

## Integrados vs não integrados (Seção 9)
Integrados e exercitados em CI: **OSV** (`deps`), **CISA KEV + FIRST EPSS**
(priorização), **Semgrep** (`sast`), **Trivy** (`iac`) e **ZAP** (`dast`/
`zap-import`). Falta: proxy dedicado de captura e fluxos autenticados profundos.

## Limitações estruturais
- **Sandbox forte NÃO implementado (decisão consciente).** No Windows nativo não
  há isolamento real sem WSL/Docker/VM. A contenção é LÓGICA: escopo + posse
  comprovada + hook PreToolUse (executor) + rate-limit + tetos por módulo. Isso
  protege o ALVO (não deixa sair do escopo), mas não isola a execução do host.
  Quem quiser isolamento roda a ferramenta dentro de WSL/Docker/VM.
- SSRF cego (sem reflexo in-band) precisa de coletor externo (OOB) — não incluso.
- O Claude (IA) é barrado pela plataforma de disparar scan ofensivo contra host
  externo; quem executa é o usuário no terminal (semiautomático).
- Cobertura por amostragem em grupos grandes de achados estáticos.

## Estado de verificação (o que foi realmente testado, e onde)
- **154 testes unittest (stdlib)** — passam localmente (Windows) e em CI
  (Ubuntu+Windows, 3.11/3.12/3.13).
- **Novos motores com teste de laboratório (loopback):** `bundle-audit`
  (segredo servido no JS), `authbf` (resistência do login), captura autenticada
  (`parse_curl`), `ssrf` (canário + metadados), `api-graphql-ws` (introspection +
  handshake). Todos com casos vulnerável/seguro e guardrails testados.
- **Confirmação COM evidência + reconhecimento de correção** (`test_lab_confirma`):
  laboratório executável em loopback (app + 2 contas de teste, versão vulnerável e
  corrigida). O motor CONFIRMA a IDOR na versão vulnerável (resposta reproduzida,
  artefato+hash), RECONHECE a correção (mesmo probe → 403, sem reprodução) e
  o portão RECUSA confirmação forjada (sem evidência ligada). Sessão de exemplo:
  `20260923-120327`.
- **Fluxo completo com Claude REAL** (sessão `20260923-113935`): install →
  init-workspace → prompt master carregado → review-code → `claude -p` triando
  6 achados → reconcile/close → export. Hooks comprovados por `hook-audit.log`
  (14 disparos). Ver `docs/limite-execucao-ia.md` para o limite de execução da IA.
- **CI GitHub Actions VERDE** em **Ubuntu E Windows**, Python 3.11/3.12/3.13
  (job `unittest`) + job `instalacao` (Ubuntu e Windows): `pip install` do
  artefato e `agente doctor` num caminho com **espaço + acento**, confirmando
  modo instalado e recursos resolvidos.
- **Semgrep (SAST) validado em CI Linux** (job `semgrep-lab`): detecta o caso
  vulnerável (`eval`) e ignora o seguro.
- **OSV + KEV + EPSS**: verificados com dados reais (osv.dev / cisa.gov /
  first.org) e com mock (base indisponível = limitação).
- **Instalação a partir de artefato limpo** (git archive → venv → `pip install`)
  verificada localmente também. O `.claude/` da fase-2 vem do clone do repo, não
  do wheel — a CLI instalada roda scan/deps/sast/review-code/replay.
- **Workspace do Claude a partir do wheel:** `init-workspace` materializa
  CLAUDE.md/.claude/agentes/skills/hooks — verificado no CI (Win+Linux) e local.
- **Estado validado:** decisões do validador são persistidas por achado
  (`finding set-status`) e a sessão fecha com cobertura (`session close`); o
  relatório separa REVISADOS de NÃO-REVISADOS (amostra ≠ conclusão ampla).
- **Correção (revisão):** o fluxo Claude em CI **é** automatizável via `claude -p`
  (modo programático) — o bloqueio real é **auth/orçamento/config no runner**,
  não impossibilidade. Ainda NÃO montado em CI (bloqueio concreto: sem credencial
  de IA no runner).
- **ZAP (DAST) validado em CI lab** (job `zap-lab`): ZAP baseline real contra
  servidor local → alertas importados.
- **NÃO verificado / pendente:** release/ZIP publicado; E2E do fluxo Claude com
  Claude REAL em CI (falta auth no runner); acesso a banco ao vivo (RLS efetiva
  com contas de teste); proxy de captura autenticado.

*Versão da matriz acompanha o CHANGELOG. Uma linha aqui não vira "pronto" sem
motor + evidência + teste correspondentes.*
