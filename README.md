# agente-vulnerabilidades

Agente de **auditoria de segurança dos meus próprios ativos** — sites, domínios
e VPS — com **interface interativa integrada ao Claude Code**. Uso estritamente
autorizado, contra alvos que eu mesmo defino.

> ⚠️ **Nada é auditado sem escopo definido + autorização explícita
> (`DISPARAR AUDITORIA`) + execução via executor controlado.** O portão nega por
> padrão (fail-closed). A máquina de desenvolvimento nunca é alvo implícito.

## Mais simples: `scan` (fluxo de 2 fases)

```bash
scan exemplo.com
```

- **Fase 1 (a ferramenta, sem Claude):** pergunta o alvo, **exige prova de posse**
  (token em arquivo ou DNS TXT — uma vez por alvo), oferece analisar o
  código-fonte, e roda **todas as análises pesadas** (externo + código),
  gerando evidência e relatório. É o "músculo" — sem bloqueios.
- **Fase 2 (abre o Claude Code sozinho no fim):** carrega prompt master + skills
  (RAPTOR/ACSK), **valida** os achados (tira falso-positivo), consulta CVE e
  **escreve o relatório final**. É o "cérebro". Não re-ataca o host.

Pra ficar só na fase 1: `scan exemplo.com --no-claude`. Instalação e ferramentas: veja **[INSTALL.md](INSTALL.md)**
(no Windows, `.\instalar.ps1` cria o atalho `scan` e checa tudo).

Com análise do código-fonte (o risco real de SPA+Supabase — segredo no bundle,
`service_role` no client, RLS, XSS):

```bash
scan exemplo.com --code C:\caminho\do\repo
# só o código, sem rede:
python -m agente review-code C:\caminho\do\repo
```

Sem instalar: `PYTHONPATH=src python -m agente scan exemplo.com`.

## Como abrir (modo conversa com Claude Code)

No PowerShell, dentro da pasta do projeto:

```powershell
.\iniciar.ps1
```

Ou dê duplo-clique em **`Abrir-Agente.cmd`**. Ou, de dentro do ambiente:

```powershell
agente ui          # (ou: python -m agente ui)
```

O iniciador tem **UI dark**, verifica Python e Claude Code, prepara o ambiente,
mostra um resumo e abre a **interface nativa do Claude Code**. Lá dentro, digite
**`/scan`** para configurar e/ou disparar a auditoria. Abordagem inspirada no
iniciador do RAPTOR, reimplementada em PowerShell (Windows/PowerShell; espaços e
acentos no caminho são suportados; `Ctrl+C` encerra sem deixar processo filho).

### Onde colocar o prompt mestre

Solte o arquivo (`.md`/`.txt`) em **`prompts/inbox/`** e rode
`agente prompts import-inbox` (ou, na interface, `/scan` oferece importar). Os
originais vão para `prompts/masters/`, versionados. Um prompt avulso por texto:
`agente prompts import - <slug> --title "..." --order 10`.

### Ferramentas de scan (ligadas)

Motores embutidos (sempre): cabeçalhos de segurança, TLS, fingerprint HTTP.
Externas (rodam se instaladas): nmap, nuclei, sqlmap, sslyze, nikto, whatweb,
dig, gobuster, ffuf, wpscan, testssl, wafw00f. Veja com `agente tools`. Sem a
ferramenta → verificação inconclusiva (limitação), nunca achado inventado.

> **1ª vez — confiança do workspace:** ao abrir `claude` aqui pela primeira vez,
> aceite o diálogo de *trust*. Sem isso o Claude Code ignora as permissões e o
> **hook** do projeto (o executor controlado só é IMPOSTO na sessão após o
> workspace ser confiável). A CLI `agente exec` aplica o escopo de qualquer forma.

## O que este projeto faz

- **Coordenador + agentes** (Claude Code): `investigador-web`, `investigador-api`,
  `investigador-auth`, `investigador-infra` e `validador-achados` (adversarial).
- **Executor controlado**: toda ação externa passa por `agente exec` e por um
  hook `PreToolUse` que bloqueia rede fora do escopo ou antes da autorização.
- **Evidência obrigatória**: hipótese começa como SUSPEITA; só confirma com
  evidência de ferramenta + artefato preservado + validação (portão em código).
- **Prompts master**: importados, versionados e montados em contexto rastreável.
- **Sessões**: tarefas, achados, evidências e limites persistidos; retomáveis.
- **Componentes de dois repositórios** incorporados (RAPTOR + coleção de skills
  de segurança) — registro completo em [docs/integracoes.md](docs/integracoes.md).

## Requisitos

- Python **3.11+** (base sem dependências externas; usa `tomllib`).
- **Claude Code** no PATH (testado com 2.1.280).
- Windows/PowerShell (preparado para Linux depois).

## Fluxo de uso

1. Abrir (`.\iniciar.ps1`). O coordenador consulta o estado e pergunta só o que
   falta, em português, uma pergunta por vez.
2. **Prompts master** → salvos em `prompts/masters/` (originais preservados).
3. **Alvos e escopo** → ativos EXATOS, ambiente, testes permitidos, limites,
   exclusões (gravados em `config/scope.toml`).
4. Resumo do escopo e do plano.
5. Digitar **`DISPARAR AUDITORIA`** → autoriza (autorização única) e inicia.
6. Conversar com o coordenador, ver progresso, interromper. Mudou alvo/permissão
   → escopo é atualizado e revalidado antes de novos testes.

## Comandos (CLI)

| Comando | Função |
|---|---|
| `agente doctor` | Ambiente: Python, Claude Code, config, sessão, gate. |
| `agente ui` | Abre a interface do Claude Code no projeto. |
| `agente session new/show/list/resume` | Sessões (persistência/retomada). |
| `agente prompts list/import/context` | Prompts master + contexto rastreável. |
| `agente scope init/show/validate/set-env/add-target/authorize` | Escopo. |
| `agente scan <alvo> [--code <pasta>]` | Auditoria ponta a ponta (posse → roda tudo → relatório). |
| `agente review-code <pasta>` | Análise de código local: segredo/service_role/RLS/XSS + rota sem auth, mass assignment, preço do cliente, IDOR. |
| `agente replay <req.json>` | Teste ATIVO autorizado de 1 requisição: IDOR/BOLA, mass assignment, endpoint sem auth, rate-limit. |
| `agente report` | Relatório da sessão ativa. |
| `agente tools` | Lista motores embutidos + ferramentas externas detectadas. |
| `agente prompts import-inbox` | Importa prompts de `prompts/inbox/`. |
| `agente audit plan/run/status` | Plano, execução (gated), progresso. |
| `agente exec --target T -- <cmd>` | Executor controlado + captura de evidência. |
| `agente evidence list` / `finding list` | Evidências e achados da sessão. |
| `agente fixtures run` | Fixtures de teste (1 descartado + 1 validado). |
| `agente integracoes` | Registro de componentes de terceiros. |

## Estrutura

```
agente-vulnerabilidades/
├─ iniciar.ps1  Abrir-Agente.cmd     # abertura
├─ CLAUDE.md  AGENTS.md              # instruções (coordenador / desenvolvimento)
├─ .claude/
│  ├─ settings.json                  # hook PreToolUse (executor controlado)
│  ├─ commands/auditoria.md          # /auditoria (fluxo de abertura)
│  ├─ agents/*.md                    # coordenador + investigadores + validador
│  └─ skills/                        # skills incorporadas + triagem/coordenação
├─ src/agente/                       # CLI + escopo + executor + evidência + ...
├─ prompts/masters/                  # prompts master (originais)
├─ config/                           # scope.example.toml / settings.example.toml
├─ docs/integracoes.md               # registro de integrações (2 repos)
├─ THIRD_PARTY_LICENSES/             # MIT (RAPTOR) + Apache-2.0 (skills)
├─ tests/                            # 55 testes (unittest, stdlib)
├─ reports/  logs/                   # saídas/sessões (git-ignorado)
```

## Testes

```powershell
$env:PYTHONPATH="src"; python -m unittest discover -s tests -v
```

## Segurança e escopo

Detalhes em [AGENTS.md](AGENTS.md) (regras de operação) e
[CLAUDE.md](CLAUDE.md) (coordenação). Créditos e licenças de terceiros em
[docs/integracoes.md](docs/integracoes.md) e `THIRD_PARTY_LICENSES/`.
