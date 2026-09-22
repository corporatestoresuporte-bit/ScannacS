# Contribuindo

Obrigado pelo interesse! Este projeto é uma base modular de auditoria de
segurança dos próprios ativos.

## Ambiente

- Python 3.11+ (a base usa só a stdlib — sem dependências externas).
- Rodar os testes:

```bash
# Windows PowerShell
$env:PYTHONPATH="src"; python -m unittest discover -s tests -v
# Linux/macOS
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Regras do projeto (não negociáveis)

- **Escopo e posse:** nenhuma ação de rede fora do escopo; alvo exige prova de
  posse. Não envie PRs que enfraqueçam esses controles.
- **Evidência:** todo achado nasce como SUSPEITA e só vira confirmado com
  evidência preservada. Não invente resultado de ferramenta/CVE.
- **Sem segredos:** nada de credenciais no código, no Git ou nos testes.
- **Testes:** todo módulo novo vem com teste (unittest, stdlib). Testes não
  podem tocar a rede nem depender do escopo real.

## Estilo

- Código e comentários no padrão do projeto (PT nos comentários).
- Motores de scan externos entram via `engines.py`; análise de código em
  `codereview.py`; teste ativo em `replay.py`.

## Componentes de terceiros

Ao adaptar algo de RAPTOR (MIT) ou da coleção de skills (Apache-2.0), registre
em `docs/integracoes.md` e preserve as licenças em `THIRD_PARTY_LICENSES/`.
