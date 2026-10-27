# wp-threat-kit

Kit defensivo montado a partir do estudo do caso **CMSsmap** (backdoor WordPress "fake plugin + include", encontrado num backup). Tudo aqui é **genérico e defensivo** — não contém o artefato malicioso real nem dados do site estudado.

## Conteúdo
- **`01-dissecacao-evasao.md`** — como o malware se esconde (4 camadas de evasão) e por que a detecção por comportamento/estrutura vence a ofuscação.
- **`02-licoes-para-meus-sistemas.md`** — os 6 princípios de causa-raiz aplicados a Laravel/Filament, Go, React/Supabase e aos sistemas da fábrica.
- **`rules/cmssmap_wp_shell.yar`** — regras YARA (validadas: 18 loaders, 6 payloads, 24 por hash).
- **`cmd/wphunter/` + `go.mod`** — scanner de IOC em Go. Só leitura.
- **`lab/`** — ambiente Docker isolado (rede sem saída) com demonstrador **benigno** da técnica.

## Scanner — uso rápido
```bash
go build -o wphunter ./cmd/wphunter
./wphunter -path /caminho/para/public_html        # relatório legível
./wphunter -path /caminho/para/public_html -json  # para pipeline/CI (exit 1 se achar CRITICAL)
```

## Regras YARA
```bash
yara -r rules/cmssmap_wp_shell.yar /caminho/para/public_html
```

## Lab
Veja `lab/README.md` — suba isolado, dispare o demonstrador, observe o admin fantasma aparecer.

---
*Origem: estudo de segurança defensiva. Mantido genérico de propósito; nenhum segredo ou dado de terceiro aqui dentro.*
