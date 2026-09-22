# Onde colocar o prompt mestre

**Coloque o arquivo do seu prompt mestre AQUI** nesta pasta (`prompts/inbox/`),
como `.md` ou `.txt`. Pode arrastar/colar quantos quiser.

Depois, dentro do agente, o comando importa todos de uma vez, preservando o
original e registrando ordem/finalidade:

```
python -m agente prompts import-inbox
```

(ou, na interface, digite `/scan` — o coordenador oferece importar o que estiver
aqui). Os originais vão para `prompts/masters/` e este inbox fica limpo.

Alternativa direta (um prompt via texto):
```
python -m agente prompts import - meu-prompt --title "Metodologia" --order 10
```

Este arquivo (`LEIA-...`) é ignorado pela importação.
