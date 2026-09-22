# Política de Segurança e Uso Autorizado

## ⚠️ Uso autorizado apenas

`agente-vulnerabilidades` é uma ferramenta de auditoria de segurança **dos seus
próprios ativos** (ou de ativos para os quais você tem **autorização escrita**).

Rodar testes ofensivos (varredura ativa, força-bruta, `replay`/IDOR, sqlmap,
nuclei) contra sistemas de terceiros **sem autorização é crime** na maioria dos
países (no Brasil, Lei 12.737/2012 e correlatas), independentemente da sua
intenção. **Você é o único responsável** pelo uso desta ferramenta.

## Como a ferramenta reforça isso

- **Prova de posse obrigatória:** antes de qualquer teste, o alvo precisa ser
  verificado como seu — via arquivo `rz-audit-verify.txt` publicado no host, ou
  registro DNS TXT (`agente scope verify`). Sem isso, o `scan` não roda.
- **Escopo estrito:** só age contra os hosts EXATOS autorizados; subdomínio,
  redirecionamento, IP compartilhado ou terceiro NÃO ampliam o escopo.
- **Executor controlado:** um hook bloqueia ações de rede fora do escopo.
- **Sem ação destrutiva por padrão:** o `replay` só usa métodos seguros
  (GET/HEAD) a menos que você passe `--com-efeito-colateral`.

Não remova essas travas para "escanear qualquer link". Elas existem para te
proteger juridicamente e para manter a ferramenta legítima.

## Reportar uma vulnerabilidade nesta ferramenta

Encontrou um problema de segurança no próprio código do projeto? Abra uma
*issue* privada (Security Advisory no GitHub) ou entre em contato com o
mantenedor. Por favor, **não** inclua dados reais de alvos nos relatos.
