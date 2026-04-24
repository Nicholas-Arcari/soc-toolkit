/*
    PHP Webshell Detection

    Targets the most common obfuscation and execution patterns used in PHP
    webshells (eval on user input, assert+base64 chain, preg_replace /e flag).
    These patterns are rare in legitimate code - eval() of $_POST is almost
    universally malicious.

    Reference: MITRE ATT&CK T1505.003 - Server Software Component: Web Shell
*/

rule webshell_php_generic : webshell php
{
    meta:
        author      = "SOC Toolkit"
        description = "Generic PHP webshell patterns (eval, assert, preg_replace /e)"
        severity    = "critical"
        mitre       = "T1505.003"
        reference   = "https://attack.mitre.org/techniques/T1505/003/"

    strings:
        $php_tag         = "<?php"
        $eval_post       = "eval($_POST"
        $eval_get        = "eval($_GET"
        $eval_request    = "eval($_REQUEST"
        $eval_cookie     = "eval($_COOKIE"
        $system_user     = /system\s*\(\s*\$_(POST|GET|REQUEST)/
        $exec_user       = /(exec|shell_exec|passthru)\s*\(\s*\$_(POST|GET|REQUEST)/
        $assert_base64   = /assert\s*\(\s*base64_decode/
        $preg_replace_e  = /preg_replace\s*\([^)]*\/e[^)]*,/

    condition:
        $php_tag and any of ($eval_post, $eval_get, $eval_request, $eval_cookie,
                             $system_user, $exec_user, $assert_base64, $preg_replace_e)
}


rule webshell_php_c99_hints : webshell php
{
    meta:
        author      = "SOC Toolkit"
        description = "Artifacts commonly found in c99/r57 family webshells"
        severity    = "high"
        mitre       = "T1505.003"

    strings:
        $php_tag = "<?php"
        $c99_title = "c99shell" nocase
        $r57_title = "r57shell" nocase
        $fopo = "FOPO" nocase
        $safe_mode_bypass = "safe_mode" nocase
        $disabled_functions = "disable_functions" nocase

    condition:
        $php_tag and 2 of ($c99_title, $r57_title, $fopo, $safe_mode_bypass, $disabled_functions)
}
