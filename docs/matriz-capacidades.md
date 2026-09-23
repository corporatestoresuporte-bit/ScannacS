# Matriz de capacidades (v0.1) — o que ESTÁ e o que NÃO está implementado

Rastreável e honesta. `✅ implementado` = há motor + evidência + teste.
`🟡 parcial` = existe, com limite claro. `❌ não` = ainda não há (não prometa).

Referências de requisito: OWASP ASVS/WSTG e API Security 2023 (ver README/links).

| Área (Seção 7) | Estado | Motor/skill | Evidência | Limite honesto |
|---|---|---|---|---|
| Inventário e exposição | 🟡 | `http-fingerprint`, `nmap`, `ffuf` | headers/portas/paths | SPA responde 200 a tudo (catch-all) — `ffuf -ac` mitiga; sem descoberta de rota logada |
| CVEs e dependências | 🟡 | `deps-osv` (`agente deps`) + nuclei | advisory OSV + KEV/EPSS | Lê lockfiles, consulta osv.dev (real) e prioriza com CISA KEV + FIRST EPSS. **Sem** imagens de container. "Afetada" != exploração |
| Código e cadeia | 🟡 | `codereview` + `sast` (Semgrep) + **`iac` (Trivy)** | arquivo:linha | codereview (regex) + Semgrep (SAST) + Trivy (IaC/misconfig) — Semgrep e Trivy validados em CI Linux. Sem fluxo de dados interprocedural |
| Autenticação e sessão | 🟡 | `replay` (no-auth), `codereview` | resposta preservada | Sem fluxo OAuth/OIDC completo nem teste de expiração/revogação |
| Autorização e privilégios | 🟡 | `replay` (IDOR/BOLA/mass) | resposta preservada | Precisa de 2 contas de teste (manual); efeito no servidor não é auto-confirmado |
| Entrada e processamento | 🟡 | `sqlmap`, `codereview` (XSS) | saída sqlmap / arquivo:linha | Sem template injection / traversal / deserialização ativos |
| Navegador e transporte | 🟡 | `tls` (✅), `cabecalhos-seguranca` | handshake / headers | TLS forte ✅; CSP/CORS/CSRF/cache: só presença de header, sem teste ativo |
| APIs e consumo | 🟡 | `replay` | resposta preservada | Sem GraphQL/WebSocket; rate-limit é best-effort |
| Requisições e replay | ✅ | `replay` (+ `--har`) | resposta + baseline | Importa HAR; controle de efeito colateral. Proxy dedicado ainda não |
| Banco e Supabase | 🟡 | `codereview` (RLS em migrations) | arquivo:linha SQL | **Não acessa o banco ao vivo** — distingue migration histórica de baseline, mas não `pg_policies` real |
| Servidor, firewall, nuvem | 🟡 | `nmap` (externo) | saída nmap | Sem acesso SSH/IAM/K8s; scan externo só vê exposição observável |
| Integrações e lógica | 🟡 | `codereview` (preço/webhook) | arquivo:linha | Sem invariantes de negócio automatizadas |
| SSRF e fronteiras internas | ❌ | — | — | Não implementado como teste ativo |
| Operação e dados sensíveis | 🟡 | redação em log/artefato | — | Sem checagem de backup/recuperação |

## Motores reais hoje
Embutidos (stdlib): `cabecalhos-seguranca`, `tls`, `http-fingerprint`.
Externos (se instalados): `nmap`, `nuclei`, `sqlmap`, `ffuf` (+ wrappers de outros).
Análise local: `codereview` (SAST-leve). Ativo: `replay`.

## Integrados vs não integrados (Seção 9)
Integrados e exercitados: **OSV** (`deps`), **CISA KEV + FIRST EPSS** (priorização
em `deps`), **Semgrep** (`sast`) e **Trivy** (`iac`), validados em CI Linux. Não integrados ainda: `ZAP` (DAST/proxy). Próximo passo; **não** contado
como cobertura pronta.

## Limitações estruturais
- Sem sandbox de isolamento no Windows nativo (contenção é escopo + hook +
  permissões do Claude, não isolamento forte).
- O Claude (IA) é barrado pela plataforma de disparar scan ofensivo contra host
  externo; quem executa é o usuário no terminal.
- Cobertura por amostragem em grupos grandes de achados estáticos.

## Estado de verificação (o que foi realmente testado, e onde)
- **96 testes unittest (stdlib)** — passam localmente (Windows, Python 3.13).
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
- **NÃO verificado / pendente:** release/ZIP publicado; E2E do fluxo Claude com
  Claude REAL em CI (falta auth no runner); ZAP; acesso a banco ao vivo (RLS
  efetiva com contas de teste).

*Versão da matriz acompanha o CHANGELOG. Uma linha aqui não vira "pronto" sem
motor + evidência + teste correspondentes.*
