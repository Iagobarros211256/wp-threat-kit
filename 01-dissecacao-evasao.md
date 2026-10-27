# Opção 1 — Dissecação das técnicas de evasão (família "CMSsmap")

O interessante desse malware não é o que ele faz (criar admin), é **como ele se esconde**. São quatro camadas de evasão, cada uma mirando um tipo diferente de detector.

## Camada 1 — Camuflagem de localização: "fake plugin"
O código não é um arquivo solto perdido no servidor; ele vira um **diretório de plugin** dentro de `wp-content/plugins/`, com um `index.php` que tem cabeçalho de plugin de verdade:

```
Plugin Name: CMSsmap - WordPress Sh-ll
Author: C1MSmap1
```

**Contra quem funciona:** contra a inspeção visual humana ("é só mais um plugin") e contra ferramentas que confiam na estrutura do WordPress. Um `.php` solto no `uploads/` grita "suspeito"; um plugin a mais numa lista de 30 passa batido.

**O ponto fraco que exploramos:** plugin real tem `readme.txt`, versão, changelog, dezenas de arquivos. Esses têm **1 a 3 arquivos** e nome de **7 letras aleatórias**. Isso é detectável estruturalmente (é o que o scanner da Opção 2 faz).

## Camada 2 — Separação loader/payload com extensão falsa
O `index.php` (a parte que o WordPress/servidor vai mesmo executar) é quase vazio. Ele só faz:

```php
error_reporting(0);        // não deixa erro vazar pro log
ignore_user_abort(true);   // continua rodando se a conexão cair
include('log.db');         // <-- o perigo mora aqui
```

O código perigoso está em **`log.db`**. A extensão `.db` é a jogada central:

**Contra quem funciona:** contra todo scanner que lista "arquivos `.php` modificados" ou faz `grep` só em `*.php`. Lembra que no relatório original a varredura de assinatura nos `.php` veio **vazia**? Foi por isso — o payload não era `.php`. Um `include()` em PHP executa qualquer arquivo como PHP, independente da extensão.

**O ponto fraco:** o `include('log.db')` em si é a assinatura. PHP legítimo quase nunca inclui um `.db`. Procurar `include/require` de extensões estranhas (`.db`, `.ico`, `.jpg`, `.cache`) pega o elo.

## Camada 3 — Montagem de string em runtime (`build_str`)
Aqui está a parte mais sofisticada. Scanner ingênuo procura por strings literais: `eval`, `base64_decode`, `shell_exec`, `wp_insert_user`. O payload **não contém essas strings escritas**. Ele tem uma função `build_str()` que remonta os nomes em tempo de execução (ex.: concatenando pedaços, invertendo, somando char codes) e chama via variável: `$f = build_str(...); $f($args);`.

**Contra quem funciona:** contra AV por assinatura estática e contra o `grep` de capacidade. Foi por isso que o fingerprint do payload no relatório achou só `$_SERVER` e `Auth` — os verbos perigosos estavam montados, não escritos.

**O ponto fraco — e a lição de detecção mais importante:** você não consegue esconder o **comportamento**, só os literais. O malware ainda precisa de funções que *não dá* pra ofuscar sem quebrar, porque são da API do WordPress chamadas por nome fixo em certos pontos, e deixa no disco um conjunto de artefatos (loader + payload + a própria `build_str`). Então a detecção migra de "procurar a palavra `eval`" para **"procurar a combinação estrutural"**: `build_str` + `load_wp_core` + `WP_User` + `set_role` juntos, num arquivo pequeno, incluído por um loader. É exatamente a condição da regra `CMSsmap_Payload_RogueAdmin`.

## Camada 4 — Gatilho autenticado
O shell não dispara pra qualquer um: ele checa uma condição em `$_SERVER` (um header específico ou um segredo — nos samples aparece o literal `postpass`). Pra um crawler ou scanner que só faz GET na URL, a página parece inofensiva/vazia (`error_reporting(0)` ajuda).

**Contra quem funciona:** contra scanner dinâmico/externo (DAST) e contra análise que depende de "ver o shell responder".
**O ponto fraco:** análise **estática** do arquivo ignora o gatilho — o código está todo lá pra ler, basta olhar o disco em vez da resposta HTTP. Por isso análise de backup (como a que fizemos) é tão poderosa: você lê o payload sem precisar que ele "aceite" você.

---

## Síntese: por que a regra YARA funciona
A regra (`rules/cmssmap_wp_shell.yar`) não tenta vencer a ofuscação no jogo dela. Ela mira as camadas que o malware **não pode** remover sem se autodestruir:

| Regra | Mira a camada | Resultado no sample |
|---|---|---|
| `CMSsmap_Loader_FakePlugin` | 1+2 (cabeçalho falso + `include('log.db')` + silenciadores) | 18 loaders |
| `CMSsmap_Payload_RogueAdmin` | 3 (combinação de funções que sobra) | 6 payloads |
| `PHP_Hidden_In_NonPHP_Extension` | 2 (heurística ampla, ruidosa — filtrar `.php`) | caça |
| `WP_Known_IOC_Hashes` | artefato exato | 24 (18+6) |

**Validado** com `yara-python` contra os artefatos reais extraídos do backup — todas as regras casaram o esperado.

### A lição transferível (vale pra qualquer malware, não só WP)
Ofuscação esconde **strings**, não **comportamento** nem **artefatos**. Boa detecção para de perseguir o literal e passa a perguntar: *que combinação de coisas no disco/no sistema só existe se o ataque existe?* Assinatura por string é a camada mais fraca; estrutura, relação entre arquivos e comportamento são as fortes.
