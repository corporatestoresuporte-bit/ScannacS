# 🛡️ agente-vulnerabilidades

**Auditoria de segurança dos seus próprios ativos** — externo, código e testes
ativos — numa CLI simples que exige **prova de posse** do alvo antes de rodar.

![license](https://img.shields.io/badge/license-MIT-green)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![tests](https://img.shields.io/badge/tests-77%20passing-brightgreen)
![stdlib](https://img.shields.io/badge/deps-stdlib%20only-lightgrey)

> ⚠️ **Uso autorizado apenas.** Ferramenta para auditar ativos **seus** (ou com
> autorização escrita). Antes de qualquer teste, o alvo precisa ser **verificado
> como seu** (arquivo ou DNS TXT). Escanear terceiros sem autorização é crime.
> Ver [SECURITY.md](SECURITY.md).

---

## ✨ O que faz — 3 camadas

| Camada | Comando | Cobre |
|---|---|---|
| **Externo (DAST)** | `scan <alvo>` | cabeçalhos, TLS, fingerprint, descoberta de conteúdo (ffuf), nuclei, sqlmap, nmap… |
| **Código (SAST-leve)** | `scan --code <pasta>` / `review-code` | segredo no bundle, `service_role`, RLS do Supabase, XSS, **rota sem auth, mass assignment, preço do cliente, IDOR** |
| **Ativo (autorizado)** | `replay <req.json>` | **IDOR/BOLA, mass assignment, endpoint sem auth, rate-limit** a partir de 1 requisição capturada |

Achados nascem como **suspeita** e só viram **confirmado** com evidência
preservada (disciplina anti-falso-positivo herdada do RAPTOR).

## 🚀 Início rápido

```bash
# 1) instalar (cria o comando `scan`)
pip install .
# no Windows: .\instalar.ps1  (cria o atalho e checa ferramentas)

# 2) rodar
scan exemplo.com
# com análise do código-fonte junto:
scan exemplo.com --code /caminho/do/repo
```

Sem instalar: `PYTHONPATH=src python -m agente scan exemplo.com`.
Ferramentas externas opcionais e por SO: ver [INSTALL.md](INSTALL.md).

## 🔁 Fluxo de 2 fases

1. **Fase 1 — a ferramenta (sem IA):** pergunta o alvo, confirma posse, roda
   todas as análises pesadas e gera evidência + relatório. É o "músculo".
2. **Fase 2 — abre o Claude Code (opcional):** carrega prompt master + skills
   (RAPTOR / ACSK), **valida** os achados, consulta CVE e escreve o relatório
   final. É o "cérebro". Não re-ataca o host.

Só a fase 1: `scan alvo --no-claude`.

## 🧰 Comandos

| Comando | Função |
|---|---|
| `scan <alvo> [--code <p>]` | Auditoria ponta a ponta (posse → roda tudo → relatório). |
| `agente review-code <pasta>` | Análise de código local. |
| `agente deps <pasta>` | Dependências vulneráveis via OSV (lockfiles). |
| `agente replay <req.json>` | Teste ativo autorizado (IDOR/mass/no-auth/rate). |
| `agente scope verify --target <t>` | Prova de posse do alvo (token arquivo/DNS). |
| `agente report` | Relatório da sessão. |
| `agente tools` | Motores e ferramentas detectadas. |
| `agente doctor` | Estado do ambiente. |

## 🔒 Segurança & escopo

- **Prova de posse obrigatória** por alvo (`scope verify`).
- **Escopo estrito** — só hosts exatos; subdomínio/terceiro não ampliam.
- **Executor controlado** — hook bloqueia rede fora do escopo.
- **Sem ação destrutiva por padrão** no `replay`.
- Segredos só em `.env`; `reports/`, `logs/`, `config/scope.toml` fora do Git.

## 🧩 Componentes de terceiros

- **RAPTOR** (MIT) — veredito tri-estado, graduação de evidência, doutrina de
  validação/coordenação, iniciador. https://github.com/gadievron/raptor
- **Anthropic-Cybersecurity-Skills** (Apache-2.0, projeto **comunitário** de
  `mukul975`, não oficial da Anthropic) — skills de web/API/auth/infra/triagem.

Registro completo: [docs/integracoes.md](docs/integracoes.md) · licenças em
[THIRD_PARTY_LICENSES/](THIRD_PARTY_LICENSES/).

## 🏗️ Estrutura

```
src/agente/     CLI + escopo + executor + motores + código + replay + evidência
.claude/        CLAUDE.md, agents, skills, commands (fase 2 no Claude Code)
prompts/        prompts master (originais) + inbox
config/         modelos de escopo/settings
tests/          77 testes (unittest, stdlib)
docs/           integrações, referência OWASP, exemplos
```

## 🧪 Testes

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## 📄 Licença

MIT — ver [LICENSE](LICENSE). Componentes de terceiros sob suas próprias licenças.
