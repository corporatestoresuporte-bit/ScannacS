# Matriz de capacidades (v0.1) — o que ESTÁ e o que NÃO está implementado

Rastreável e honesta. `✅ implementado` = há motor + evidência + teste.
`🟡 parcial` = existe, com limite claro. `❌ não` = ainda não há (não prometa).

Referências de requisito: OWASP ASVS/WSTG e API Security 2023 (ver README/links).

| Área (Seção 7) | Estado | Motor/skill | Evidência | Limite honesto |
|---|---|---|---|---|
| Inventário e exposição | 🟡 | `http-fingerprint`, `nmap`, `ffuf` | headers/portas/paths | SPA responde 200 a tudo (catch-all) — `ffuf -ac` mitiga; sem descoberta de rota logada |
| CVEs e dependências | 🟡 | `deps-osv` (`agente deps`) + nuclei | advisory OSV (id/CVE/fonte/horário) | Lê requirements.txt/package-lock.json e consulta osv.dev (real). **Sem** imagens de container, KEV/EPSS. "Afetada" != exploração; base pode estar incompleta |
| Código e cadeia | 🟡 | `codereview` (SAST-leve regex) | arquivo:linha | Segredo/`service_role`/RLS/XSS/rota-sem-auth/mass/IDOR(`select *`). **Sem** Semgrep/Trivy/IaC/fluxo de dados |
| Autenticação e sessão | 🟡 | `replay` (no-auth), `codereview` | resposta preservada | Sem fluxo OAuth/OIDC completo nem teste de expiração/revogação |
| Autorização e privilégios | 🟡 | `replay` (IDOR/BOLA/mass) | resposta preservada | Precisa de 2 contas de teste (manual); efeito no servidor não é auto-confirmado |
| Entrada e processamento | 🟡 | `sqlmap`, `codereview` (XSS) | saída sqlmap / arquivo:linha | Sem template injection / traversal / deserialização ativos |
| Navegador e transporte | 🟡 | `tls` (✅), `cabecalhos-seguranca` | handshake / headers | TLS forte ✅; CSP/CORS/CSRF/cache: só presença de header, sem teste ativo |
| APIs e consumo | 🟡 | `replay` | resposta preservada | Sem GraphQL/WebSocket; rate-limit é best-effort |
| Requisições e replay | ✅ | `replay` | resposta + baseline | Controle de efeito colateral; captura HAR/proxy ainda não |
| Banco e Supabase | 🟡 | `codereview` (RLS em migrations) | arquivo:linha SQL | **Não acessa o banco ao vivo** — distingue migration histórica de baseline, mas não `pg_policies` real |
| Servidor, firewall, nuvem | 🟡 | `nmap` (externo) | saída nmap | Sem acesso SSH/IAM/K8s; scan externo só vê exposição observável |
| Integrações e lógica | 🟡 | `codereview` (preço/webhook) | arquivo:linha | Sem invariantes de negócio automatizadas |
| SSRF e fronteiras internas | ❌ | — | — | Não implementado como teste ativo |
| Operação e dados sensíveis | 🟡 | redação em log/artefato | — | Sem checagem de backup/recuperação |

## Motores reais hoje
Embutidos (stdlib): `cabecalhos-seguranca`, `tls`, `http-fingerprint`.
Externos (se instalados): `nmap`, `nuclei`, `sqlmap`, `ffuf` (+ wrappers de outros).
Análise local: `codereview` (SAST-leve). Ativo: `replay`.

## NÃO integrados (candidatos — Seção 9)
`ZAP` (DAST/proxy), `Semgrep` (SAST real), `Trivy`/`OSV` (deps/IaC/CVE),
`KEV`/`EPSS` (priorização). Documentados como próximos passos; **não** contados
como cobertura pronta.

## Limitações estruturais
- Sem sandbox de isolamento no Windows nativo (contenção é escopo + hook +
  permissões do Claude, não isolamento forte).
- O Claude (IA) é barrado pela plataforma de disparar scan ofensivo contra host
  externo; quem executa é o usuário no terminal.
- Cobertura por amostragem em grupos grandes de achados estáticos.

## Estado de verificação (o que foi realmente testado, e onde)
- **91 testes unittest (stdlib)** — passam localmente (Windows, Python 3.13).
- **CI GitHub Actions VERDE** em Ubuntu, Python **3.11 / 3.12 / 3.13** (workflow
  `testes`, verde no commit atual). **Windows NÃO está no CI** — só execução
  local nesta máquina.
- **Instalação a partir de artefato limpo** (git archive → venv novo → `pip
  install`): verificada — `agente doctor` roda instalado, fora do checkout, sem
  PYTHONPATH, com recursos resolvidos do pacote. (O `.claude/` da fase-2 vem do
  clone do repo, não do wheel — a CLI instalada roda scan/deps/review-code/replay.)
- **OSV**: verificado com dados reais (osv.dev) e com mock (base indisponível =
  limitação).
- **NÃO verificado / pendente:** empacotamento em release/ZIP publicado; CI em
  Windows; E2E com ZAP/Semgrep/Trivy reais em laboratório; acesso a banco ao vivo.

*Versão da matriz acompanha o CHANGELOG. Uma linha aqui não vira "pronto" sem
motor + evidência + teste correspondentes.*
