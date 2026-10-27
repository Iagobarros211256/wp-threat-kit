#!/usr/bin/env bash
# Observa a tabela de usuários do WP no lab. Rode ANTES e DEPOIS de acessar o loader,
# para ver o "admin fantasma" aparecer.
#   docker compose exec -T db sh /observe/users.sh      (ou rode os comandos à mão)
set -eu
mysql -uwp -pwp wp -e "
  SELECT u.ID, u.user_login, u.user_registered,
         SUBSTRING_INDEX(SUBSTRING_INDEX(m.meta_value,'\"',2),'\"',-1) AS role
  FROM wp_users u
  LEFT JOIN wp_usermeta m ON m.user_id=u.ID AND m.meta_key='wp_capabilities'
  ORDER BY u.ID;" 2>/dev/null || \
  echo "dica: ajuste o prefixo da tabela (wp_) se o seu lab usar outro."
