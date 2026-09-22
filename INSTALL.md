# Instalação

Objetivo: **instalar → digitar `scan <alvo>` → roda tudo e mostra o relatório.**

> Toda auditoria exige **prova de posse do alvo** (token em arquivo ou DNS TXT).
> Isso é o que torna a ferramenta segura para distribuir: não dá para escanear
> um host que você não controla.

## 1. Requisito base

- **Python 3.11+**.

Instalar a ferramenta (cria o comando `scan`):

```bash
# na pasta do projeto
pip install .
# a partir daí:
scan exemplo.com
```

Sem instalar (roda igual, direto do código):

```bash
# Windows PowerShell
$env:PYTHONPATH="src"; python -m agente scan exemplo.com
# Linux/macOS
PYTHONPATH=src python -m agente scan exemplo.com
```

No Windows você pode usar `.\instalar.ps1`, que prepara o ambiente, cria o
atalho `scan` e mostra o que falta instalar.

## 2. Ferramentas de scan (opcionais, mas recomendadas)

Os motores **embutidos** (cabeçalhos, TLS, fingerprint HTTP) sempre funcionam.
As externas ampliam a cobertura; sem elas, o teste vira "inconclusivo"
(limitação), nunca achado falso.

| Ferramenta | Para quê | Windows | Linux (apt) | macOS (brew) |
|-----------|----------|---------|-------------|--------------|
| nuclei | vulns conhecidas/CVEs | `winget install ProjectDiscovery.nuclei` | via releases/go | `brew install nuclei` |
| ffuf | força-bruta de caminhos | `go install github.com/ffuf/ffuf/v2@latest` | `apt install ffuf` | `brew install ffuf` |
| sqlmap | injeção SQL | `git clone https://github.com/sqlmapproject/sqlmap` | `apt install sqlmap` | `brew install sqlmap` |
| nmap | portas/serviços | `winget install Insecure.Nmap` | `apt install nmap` | `brew install nmap` |
| sslyze | TLS aprofundado | `pip install sslyze` | `pip install sslyze` | `pip install sslyze` |
| whatweb | fingerprint | (WSL) | `apt install whatweb` | `brew install whatweb` |
| dig | DNS | (WSL/BIND) | `apt install dnsutils` | incluso |

Confira o que está instalado:

```bash
scan --help          # ou: python -m agente tools
python -m agente tools
```

> **Windows + usuário com acento no nome** (ex.: `Lázaro`): alguns pacotes pip
> quebram lendo arquivos sob o seu diretório. Instale ferramentas em um caminho
> **sem acento** (ex.: `C:\tools\...`) ou use o **WSL**.

## 3. Uso

```bash
scan bybit.rzsolucoes.org
```

1. Se o alvo ainda não foi provado como seu, o comando mostra um **token** para
   você publicar (`https://<alvo>/rz-audit-verify.txt` **ou** DNS TXT).
2. Publique o token e rode `scan <alvo>` de novo → **posse confirmada** (não
   pede mais).
3. Ele autoriza uma vez, roda todos os motores instalados e imprime o relatório
   (confirmado / suspeita / inconclusivo / cobertura).

Relatório da última sessão a qualquer momento: `python -m agente report`.
