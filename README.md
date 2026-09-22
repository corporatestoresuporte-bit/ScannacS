# agente-vulnerabilidades

Agente de **auditoria de segurança dos meus próprios ativos** — sites, domínios
e VPS — com **interface interativa integrada ao Claude Code**. Uso estritamente
autorizado, contra alvos que eu mesmo defino.

> ⚠️ **Nada é auditado sem escopo definido + autorização explícita
> (`DISPARAR AUDITORIA`) + execução via executor controlado.** O portão nega por
> padrão (fail-closed). A máquina de desenvolvimento nunca é alvo implícito.

## Como abrir

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
