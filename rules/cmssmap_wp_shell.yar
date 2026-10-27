/*
    cmssmap_wp_shell.yar
    Família: "CMSsmap" WordPress fake-plugin backdoor (loader + payload split)
    Uso: deteccao defensiva. Rode com:  yara -r rules/cmssmap_wp_shell.yar <caminho>
    Observado em: backup de WP 6.8.1, ~24 pastas de plugin com nome aleatorio,
                  index.php (loader) -> include('log.db') (payload).
    Requer: modulo "hash" do YARA para a regra de hashes (yara >= 3.x compilado com openssl).
*/

import "hash"

/*

    NOTA sobre evasao: o payload monta nomes de funcao/strings em runtime
    (build_str), entao assinaturas ingenuas por "eval"/"base64_decode" NAO pegam.
    Estas regras miram o que o malware NAO consegue esconder: a estrutura do
    loader, o cabecalho de plugin falso, e o conjunto de artefatos no disco.
*/

rule CMSsmap_Loader_FakePlugin
{
    meta:
        description = "Loader: plugin falso que inclui um payload com extensao nao-php"
        severity    = "critical"
        family      = "CMSsmap"
        reference   = "fake plugin header + include('log.db')"
    strings:
        $hdr1 = "CMSsmap" nocase
        $hdr2 = "WordPress Sh" nocase          // 'Shell' ofuscado nos samples
        $hdr3 = "C1MSmap1" nocase
        $inc  = /include\s*\(\s*['"]log\.db['"]\s*\)/
        $sil1 = "ignore_user_abort"
        $sil2 = "error_reporting(0)"
    condition:
        // php pequeno + ou cabecalho falso ou include do .db + silenciadores
        filesize < 4KB and
        (
            (any of ($hdr1, $hdr2, $hdr3) and $inc) or
            ($inc and all of ($sil1, $sil2))
        )
}

rule CMSsmap_Payload_RogueAdmin
{
    meta:
        description = "Payload: cria/garante admin oculto carregando o core do WP"
        severity    = "critical"
        family      = "CMSsmap"
    strings:
        $f1 = "create_admin_if_missing"
        $f2 = "load_wp_core"
        $f3 = "build_str"           // reconstrucao de string anti-assinatura
        $f4 = "set_role"
        $w  = "WP_User"
    condition:
        filesize < 16KB and 3 of ($f*) and $w
}

rule PHP_Hidden_In_NonPHP_Extension
{
    meta:
        description = "Heuristica: codigo PHP vivo escondido em arquivo nao-.php"
        severity    = "high"
        note        = "casar so onde a extensao NAO e .php (use -r e filtre fora .php)"
    strings:
        $open = "<?php"
        $d1   = "eval("
        $d2   = "assert("
        $d3   = "base64_decode"
        $d4   = "gzinflate"
        $d5   = "str_rot13"
        $d6   = "$_POST"
        $d7   = "$_REQUEST"
        $d8   = "$_COOKIE"
    condition:
        $open at 0 and any of ($d*)
}

rule WP_Known_IOC_Hashes
{
    meta:
        description = "Hashes exatos dos artefatos observados (ajuste conforme novas variantes)"
        severity    = "critical"
        family      = "CMSsmap"
    condition:
        hash.md5(0, filesize) == "6f2394f0f643a1395159eec20976dbc6" or   // index.php loader
        hash.md5(0, filesize) == "8423d04c87e7d93c0aba4bce25fd3131"      // log.db payload
}
