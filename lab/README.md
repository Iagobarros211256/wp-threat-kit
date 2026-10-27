# Opção 3 — Lab isolado para reproduzir e observar o backdoor

Objetivo: **ver a técnica funcionando** (loader `.php` → `include` de `.db` → bootstrap do WP → admin fantasma com data forjada) sem risco. O que sobe por padrão é um **demonstrador benigno**, não o malware real.

## Regras de segurança (as mesmas de qualquer análise de malware)
1. **Rede sem saída.** A `labnet` é `internal: true`: os containers não alcançam a internet. Por isso puxe as imagens **antes** de isolar:
   ```bash
   docker compose pull         # precisa de internet (só esta etapa)
   docker compose up -d        # já roda isolado
   ```
2. **Só localhost.** O WP é publicado em `127.0.0.1:8080`. Nunca troque para `0.0.0.0` nem exponha na LAN.
3. **Descartável.** Nada é persistido. Ao terminar:
   ```bash
   docker compose down -v      # derruba e apaga o estado
   ```
4. **Máquina sua, não de produção.** Rode no seu PC (Nobara + Docker), nunca num servidor que hospeda coisa de verdade.

## Roteiro de observação (demonstrador benigno)
```bash
docker compose pull && docker compose up -d
# 1) instale o WP pelo navegador: http://127.0.0.1:8080  (crie o admin legítimo)
# 2) estado ANTES:
docker compose exec -T db sh /observe/users.sh
# 3) "dispare o shell" acessando o loader direto (como um atacante faria):
curl -s http://127.0.0.1:8080/wp-content/plugins/zz-demo-shell/index.php
# 4) estado DEPOIS — repare no 'demo_rogue_admin' com user_registered em 2013:
docker compose exec -T db sh /observe/users.sh
# 5) evidência de que um .db rodou como PHP:
docker compose exec -T wordpress cat /var/www/html/wp-content/EVIDENCE_shell_ran.txt
```
Você vai ver, na prática: um arquivo `.db` executando código, um admin que você não criou surgindo na tabela, e a **data de registro forjada** — o IOC que usamos pra achar o `adminlin` no caso real.

## Rodar o scanner contra o lab
```bash
# copie o binário wphunter para dentro, ou monte o diretório e:
docker compose exec -T wordpress sh -c 'ls wp-content/plugins'
# de fora, apontando para o volume do demo:
../wphunter -path ./demo-plugin
```
Esperado: `odd-extension-include`, `silencer-combo` e (se você renomear a pasta para 7 letras aleatórias e tirar nada de readme) `suspicious-plugin-dir`.

## E o artefato REAL?
Para o `index.php`/`log.db` reais do caso, a recomendação é **análise estática** — você já leu tudo que precisa a partir do backup, sem executar nada. Se mesmo assim quiser observar o real rodando:
- faça **somente** neste lab isolado (`internal: true`), em VM/descartável, por sua conta e risco;
- monte o artefato read-only numa pasta de plugin e trate a imagem como contaminada (`down -v` + `docker image prune` depois);
- nunca em máquina com dados sensíveis ou na mesma rede de algo importante.

Lembre: o payload real tem gatilho e pode fazer mais do que criar admin. O demonstrador benigno já te dá 95% do aprendizado sem nenhum desses riscos.
