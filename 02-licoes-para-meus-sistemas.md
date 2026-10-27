# Lições do caso CMSsmap → aplicadas aos seus sistemas

O site do Roberto caiu por uma combinação de causas-raiz, não por um "hack genial". Cada causa vira um princípio que dá pra levar direto pro Ynnovar (Laravel/Filament), Volurya (Go), DataHosp (React/Supabase) e os sistemas da fábrica. Abaixo, causa → princípio → o que fazer **no seu stack**.

---

## 1. "Backup = cofre" → gestão de segredos
**No caso:** o `.tar.gz` carregava chave TLS, DKIM, tokens, senha do banco. Um arquivo = o servidor inteiro.

**Princípio:** segredo nunca mora no código nem num artefato que circula; mora em variável de ambiente/secrets manager, com rotação e acesso mínimo.

| Seu sistema | Ação concreta |
|---|---|
| **Ynnovar (Laravel)** | `.env` **fora do git** (confirme no `.gitignore`); `APP_KEY` só no servidor; nunca commitar dumps de `storage/`. Em CI, segredos via secrets do runner, não no YAML. |
| **Volurya (Go)** | Config 100% por env var (`os.Getenv`), zero token hardcoded; `.env` no `.gitignore`; para produção, um secrets manager ou variáveis do orquestrador. |
| **DataHosp (Supabase)** | O pulo do gato: **`service_role` key JAMAIS no frontend** — só a `anon` key vai pro browser. A `service_role` fura toda a RLS. Se ela já vazou em algum build, **rotacione agora**. |
| **Todos** | Dump de banco é joia da coroa: criptografe em repouso, restrinja quem baixa, e trate qualquer backup antigo esquecido como potencialmente vazado. |

---

## 2. Admin fantasma → higiene de autenticação e autorização
**No caso:** `adminlin`, admin com data forjada de 2012, recriado pelo backdoor.

**Princípio:** menor privilégio, autorização **sempre no servidor**, e contas auditáveis.

| Seu sistema | Ação concreta |
|---|---|
| **Ynnovar (Filament)** | Proteja painéis com **Policies**/`canAccess()`; nem todo usuário é admin. Tenha uma tela/consulta de "usuários com papel privilegiado" e revise periodicamente. 2FA no admin. |
| **Volurya (Go)** | Nunca confie só na *presença* de um token — valide assinatura/expiração e **cheque o papel em cada endpoint** (middleware de authz). Negue por padrão. |
| **DataHosp (Supabase)** | A **RLS é a sua autorização**. Tabela sem policy = qualquer um com a `anon` key lê tudo. Audite: toda tabela com dado sensível tem `ENABLE ROW LEVEL SECURITY` + policies `select/insert/update` por `auth.uid()`. |
| **Todos** | Logue e, se der, alerte em evento de "novo usuário privilegiado" ou mudança de papel. Admin aparecendo sozinho é o IOC número um. |

---

## 3. File manager / Code Snippets → execução de código arbitrário
**No caso:** três gerenciadores de arquivo + Code Snippets = várias portas pra escrever/rodar PHP.

**Princípio:** não exista no sistema uma função que escreve/executa código em produção; upload é dado, nunca código.

| Seu sistema | Ação concreta |
|---|---|
| **DataHosp / qualquer upload** | Valide tipo real (magic bytes, não só extensão), **renomeie** o arquivo, guarde em **storage de objetos** (Supabase Storage), nunca numa pasta servida que possa executar. Sirva via URL assinada. |
| **Ynnovar (Laravel)** | Uploads no disco `private`, não em `public/`. Nada de endpoint tipo tinker/eval exposto. `disable_functions` no PHP de produção para `exec/system/...`. |
| **Volurya (Go)** | Se servir arquivos do usuário, trave `Content-Type`, bloqueie path traversal (`filepath.Clean` + prefixo), e nunca sirva o diretório de upload como executável. |
| **Todos** | Menos recurso = menos superfície. A pergunta de ouro: "esse sistema *precisa* poder escrever código em si mesmo?" Quase sempre a resposta é não. |

---

## 4. Plugins desatualizados → dependências são vetor de entrada
**No caso:** Elementor Pro 3.10.3, Easy WP SMTP 1.5.3 etc. — a porta de entrada provável.

**Princípio:** dependência é código de terceiro rodando com seu privilégio; mantenha atualizada, escaneada e mínima.

| Seu sistema | Ação concreta |
|---|---|
| **Ynnovar (Laravel)** | `composer audit` no CI; manter Laravel/Filament/pacotes em dia; remover pacote que não usa. |
| **Volurya (Go)** | `govulncheck ./...` no pipeline (ele cruza seu código com o banco de vulns do Go). A superfície pequena de deps do Go é uma vantagem — preserve, evite dependência à toa. |
| **DataHosp (React)** | `npm audit`/`pnpm audit`, versões travadas no lockfile, atenção a supply-chain (pacote pequeno e popular demais). |
| **Todos** | Dependabot/Renovate pra PR automático de atualização. Lição direta do caso: três plugins que fazem a mesma coisa = três vezes a chance de um ter CVE. |

---

## 5. Faltou `DISALLOW_FILE_EDIT` / sobrou `Info.php` → hardening e vazamento de config
**No caso:** o WP permitia editar arquivos pelo painel (foi assim que plantaram os shells), e um `phpinfo()` exposto entregava a config do servidor.

**Princípio:** menor privilégio em runtime e **zero vazamento de configuração** em produção.

| Seu sistema | Ação concreta |
|---|---|
| **Ynnovar (Laravel)** | `APP_DEBUG=false` em produção — stack trace do Laravel vazando é o seu "Info.php". Permissões de arquivo corretas, não rodar como root. |
| **Volurya (Go)** | Container com filesystem **read-only**, `cap_drop: ALL`, imagem distroless/scratch. Sem página de debug aberta. |
| **DataHosp (Supabase)** | Revise o que a API expõe (introspecção/`pg_catalog`), mensagens de erro que vazam schema, e políticas de CORS. |
| **Todos** | Erro em produção = mensagem genérica pro usuário + detalhe só no log interno. Nunca o inverso. |

---

## 6. "Não se limpa, reconstrói" → integridade, detecção e deploy imutável
**No caso:** com backdoor de persistência, limpar arquivo a arquivo não resolve — recria do zero + rotaciona segredos.

**Princípio — e aqui sua arquitetura tem vantagem estrutural sobre WordPress:**

- **Deploy imutável a partir do git.** O WP foi comprometido em parte por ser *mutável em runtime* (plugin escreve arquivo, painel edita código). Seus apps Go/Laravel conteinerizados podem ser **imutáveis**: build do artefato, filesystem read-only, deploy só a partir de um commit. Nesse modelo, **qualquer arquivo que não está no git é suspeito por definição** — o dropper não teria onde se esconder. Isso mata a classe inteira do ataque.
- **Monitoramento de integridade.** Como o deploy vem do git, um `git status`/checksum no container detecta injeção na hora.
- **Logs centralizados + plano de resposta.** Saiba o que logar (auth, criação de usuário, erro 500 anômalo) e tenha o passo-a-passo de "deu incidente": isolar, rotacionar segredos, redeploy do known-good, revisar backups (que precisam estar limpos e verificados).

| Seu sistema | Ação concreta |
|---|---|
| **Ynnovar / Volurya / DataHosp** | Deploy só via pipeline a partir de commit assinado; container read-only; nada de "editar no servidor". |
| **Fábrica (Counterparts, Discipline, fornecedores)** | São sistemas que vão lidar com ponto, folha, financeiro, fornecedores — dado sensível de verdade. Aplique 1–6 desde o começo; é muito mais barato nascer com isso do que remediar. |

---

## TL;DR — os 6 princípios em uma linha cada
1. Segredo fora do código; backup é cofre; rotacione.
2. Menor privilégio; autorização no servidor; audite admin.
3. Upload é dado, nunca código; nada que execute código em produção.
4. Dependência atualizada, escaneada e mínima.
5. Sem debug/config vazando em produção; runtime com menor privilégio.
6. Deploy imutável a partir do git → o que não está no git é suspeito.

A boa notícia: o stack que você já prefere (Go, Docker, deploy conteinerizado) te coloca naturalmente mais perto do item 6 do que o WordPress jamais esteve. Dá pra transformar cada um desses princípios numa checklist de PR.
