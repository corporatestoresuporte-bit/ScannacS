# agente-vulnerabilidades

Agente de **auditoria de segurança dos meus próprios ativos** — sites, domínios
e VPS. Uso estritamente autorizado, contra alvos que eu mesmo defino.

Este repositório é a **fundação**: base modular em Python com CLI, portão de
autorização e cadastro de escopo. O **provedor de IA** e os **scanners reais**
são escolhidos depois, junto com os prompts master.

> ⚠️ **Nada é auditado sem escopo definido + autorização explícita + confirmação
> na execução.** O portão nega por padrão (fail-closed). A máquina de
> desenvolvimento nunca é alvo implícito.

---

## Objetivo

- Auditar apenas ativos **meus**, listados de forma **exata** no escopo.
- Produzir achados com **evidência, impacto, reprodução e correção**.
- Separar claramente **suspeita**, **confirmado** e **não verificado**.
- Manter **credenciais fora** do código, do Git e dos relatórios.

## Requisitos

- Python **3.11+** (usa `tomllib` da stdlib). A base **não tem dependências
  externas**.
- Windows/PowerShell hoje; preparado para Linux depois.

## Instalação

```powershell
cd "$env:USERPROFILE\Documents\agente-vulnerabilidades"
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Opcional (instala o comando `agente`):
pip install -e .
```

Sem instalar, dá para rodar apontando o `PYTHONPATH` para `src`:

```powershell
$env:PYTHONPATH="src"; python -m agente version
```

Configuração local (arquivos git-ignorados):

```powershell
copy .env.example .env
python -m agente scope init      # cria config/scope.toml a partir do modelo
```

## Comandos

| Comando                     | O que faz                                                        |
|-----------------------------|------------------------------------------------------------------|
| `agente version`            | Mostra a versão.                                                 |
| `agente doctor`             | Checa ambiente: Python, config, prompts, `.env`, estado do gate. |
| `agente scope init`         | Cria `config/scope.toml` a partir do exemplo.                    |
| `agente scope show`         | Mostra o escopo atual.                                           |
| `agente scope validate`     | Roda o portão e explica por que está liberado/bloqueado.        |
| `agente prompts list`       | Lista os prompts master registrados.                            |
| `agente audit plan`         | Descreve o que **seria** executado por alvo (não toca na rede).  |
| `agente audit run --confirm`| Executa a auditoria (bloqueada sem escopo + confirmação).       |

(Sem `pip install -e .`, troque `agente` por `python -m agente`.)

## Estrutura

```
agente-vulnerabilidades/
├─ README.md              # este arquivo
├─ AGENTS.md              # como o agente funciona e é desenvolvido
├─ pyproject.toml         # empacotamento + comando `agente`
├─ requirements.txt       # base sem deps; ferramentas/scanners depois
├─ .env.example           # modelo de segredos (copie p/ .env)
├─ .gitignore             # protege segredos e saídas
├─ prompts/
│  ├─ README.md           # índice dos prompts master (finalidade + ordem)
│  └─ masters/            # prompts master, um arquivo por original
├─ config/
│  ├─ scope.example.toml  # modelo de escopo (alvos vazios)
│  └─ settings.example.toml
├─ src/agente/            # código-base modular
│  ├─ cli.py  config.py  scope.py  audit.py  findings.py  logging_utils.py
├─ tests/                 # verificações da base (stdlib, unittest)
├─ reports/               # saídas de auditoria (git-ignorado)
└─ logs/                  # logs com redação de segredos (git-ignorado)
```

## Testes

```powershell
$env:PYTHONPATH="src"; python -m unittest discover -s tests -v
```

## Próximas etapas

1. **Receber os prompts master** → salvar cada original em `prompts/masters/`
   e registrar finalidade/ordem em `prompts/README.md`.
2. **Definir alvos e escopo** em `config/scope.toml` (ativos exatos, ambiente,
   testes permitidos, limites, exclusões) e `authorized = true`.
3. **Escolher provedor de IA e scanners** e registrá-los como motores.
4. **Executar auditorias** sob demanda, com `audit run --confirm`.

Segurança e escopo em detalhe: veja [AGENTS.md](AGENTS.md).
