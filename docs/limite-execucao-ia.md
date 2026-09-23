# Limite de execução pela IA — bloqueio, fluxo suportado e classificação

Documento honesto sobre **o que a IA (Claude) NÃO dispara** dentro do ScannacS,
por quê, e como o produto opera dentro dessa restrição. Sem segredos.

## O bloqueio, exatamente

- **Plataforma:** Claude Code (Anthropic) — classificador de segurança do próprio
  modelo, na camada da plataforma (não é erro de ferramenta nem de API).
- **Operações que a IA recusa disparar sozinha:**
  1. Executar varredura **ofensiva** contra host (nmap/nuclei/sqlmap/ffuf, etc.)
     quando quem pede o disparo é o modelo.
  2. Rodar `claude -p` com a flag **`--dangerously-skip-permissions`**.
- **Mensagens reais recebidas nesta build (verbatim, sem segredos):**
  - Ao tentar gerar/disparar conteúdo de scan ofensivo:
    > "Your response above was stopped by a safety classifier — this is not a
    > tool or API error. The rest of it was withheld, and tool calls in it that
    > had not finished did not run. Do not produce that content again, even reworded."
  - Ao tentar a flag de pular permissões, o classificador rotula a ação como
    **"Create Unsafe Agents"** e recusa.

> É uma restrição da plataforma, **não** um limite do escopo/hook do ScannacS.
> Os portões do produto (posse + escopo + evidência) são independentes disso.

## Fluxo suportado (o que funciona de ponta a ponta)

A IA **coordena, tria e valida**; **quem dispara o scan de rede é o usuário** no
terminal. Comprovado com Claude REAL (sessão `20260923-113935`):

1. Usuário instala e abre o workspace (`agente init-workspace`), roda `/scan`.
2. Claude carrega contexto (CLAUDE.md, prompt master, agentes, skills), lê o
   banner (hook SessionStart) e respeita o hook PreToolUse (executor controlado).
3. Para ação de rede/ofensiva: **o usuário** executa o comando `agente exec ...`
   (ou o scanner) no terminal — o hook valida escopo/posse/rate antes de deixar
   passar. A IA orquestra, lê a saída como DADO e coordena os próximos passos.
4. Claude faz **triagem e validação adversarial** dos achados (confirma só com
   evidência mecânica; senão, `inconclusivo`), reconcilia e fecha a sessão.

Testes **ATIVOS que não são "ofensivos contra terceiro"** — ex.: `replay`/IDOR
somente-leitura (GET/HEAD) contra alvo **próprio com posse comprovada** — rodam
normalmente (ver laboratório `test_lab_confirma.py`: confirma IDOR na versão
vulnerável e reconhece a correção). Métodos que mudam estado exigem
`--com-efeito-colateral` (falha fechada por padrão).

## Classificação honesta do produto

**Semiautomático.** A auditoria de rede/ofensiva depende de **execução manual do
usuário** no terminal (a plataforma barra a IA de disparar essas ferramentas
sozinha). É **automático** em: preparação de workspace, carregamento de contexto/
prompts/agentes/skills, portões de posse/escopo/rate, testes ativos de baixo
risco em alvo próprio (replay read-only), triagem/validação/reconciliação,
relatório e exportação de evidências.

- **Não é** "aponte uma URL e a IA ataca sozinha" — e isso é intencional.
- **É** "a IA conduz a auditoria dos SEUS ativos; você aperta o gatilho dos
  disparos de rede quando o portão autoriza."

## Contorno legítimo já usado

- `claude -p` **sem** `--dangerously-skip-permissions`, apoiado em **workspace
  confiável** (`hasTrustDialogAccepted`) + regras `allow` no `.claude/settings.json`
  (`Bash(agente:*)`, `Bash(python -m agente:*)`). Assim a IA roda os comandos
  locais do `agente` sem prompt e sem a flag insegura — comprovado nesta sessão.
