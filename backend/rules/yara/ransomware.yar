/*
    Ransomware Indicators

    Detects ransom notes and encrypted-payload markers. Note text alone
    is rarely malicious (emails discuss ransomware too), so the rule combines
    multiple signals: ransom language PLUS payment infrastructure (onion
    addresses, Bitcoin/Monero wallets).

    Reference: MITRE ATT&CK T1486 - Data Encrypted for Impact
*/

rule ransomware_note_generic : ransomware
{
    meta:
        author      = "SOC Toolkit"
        description = "Ransom note language combined with payment infrastructure"
        severity    = "critical"
        mitre       = "T1486"
        reference   = "https://attack.mitre.org/techniques/T1486/"

    strings:
        // Ransom note language - stay conservative to reduce false positives.
        // Each phrase is rarely seen outside actual ransomware notes
        $note_encrypted   = "your files have been encrypted" nocase
        $note_pay_ransom  = "pay the ransom" nocase
        $note_decrypt_key = "decryption key" nocase
        $note_decryptor   = "decryptor" nocase
        $note_recover     = "recover your files" nocase
        $note_bitcoin     = "bitcoin" nocase
        $note_btc_address = "bitcoin address" nocase
        $note_contact_tor = "tor browser" nocase

        // Payment infrastructure patterns.
        // Legacy base58 Bitcoin addresses deliberately excluded - they alias
        // with normal text (too many false positives). bech32 and Monero
        // formats are distinctive enough to be low-FP
        $tor_onion_v3    = /[a-z2-7]{56}\.onion/
        $tor_onion_v2    = /[a-z2-7]{16}\.onion/
        $btc_bech32      = /bc1[a-z0-9]{39,59}/
        $monero_addr     = /4[0-9AB][0-9a-zA-Z]{93}/

    condition:
        // Multiple ransom phrases OR ransom language + payment infrastructure
        3 of ($note_*)
        or (
            2 of ($note_*)
            and any of ($tor_onion_v3, $tor_onion_v2, $btc_bech32, $monero_addr)
        )
}


rule ransomware_known_extensions : ransomware
{
    meta:
        author      = "SOC Toolkit"
        description = "References to file extensions used by well-known ransomware families"
        severity    = "high"
        mitre       = "T1486"

    strings:
        // Post-encryption extensions seen in major families
        $ext_lockbit   = ".lockbit" nocase
        $ext_conti     = ".conti" nocase
        $ext_revil     = ".sodinokibi" nocase
        $ext_wannacry  = ".wncry" nocase
        $ext_ryuk      = ".ryk" nocase
        $ext_blackcat  = ".bl4ck" nocase
        $ext_royal     = ".royal_w" nocase
        $ext_hive      = ".hive" nocase
        $ext_clop      = ".clop" nocase

    condition:
        any of them
}
