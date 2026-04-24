from core.phishing.header_analyzer import analyze_headers
from core.phishing.verdict_engine import generate_verdict


SAMPLE_EMAIL = """From: "PayPal Security" <security@paypa1.com>
To: victim@example.com
Subject: URGENT: Your account has been suspended
Date: Mon, 10 Apr 2026 12:00:00 +0000
Return-Path: <bounce@malicious-domain.xyz>
Reply-To: phisher@evil.com
Message-ID: <abc123@malicious-domain.xyz>
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Received: from mail.malicious-domain.xyz [203.0.113.50]
Content-Type: text/html

<html>
<body>
<p>Your PayPal account has been suspended. Click here to verify:
<a href="http://paypal-verify.malicious-site.tk/login">Verify Account</a></p>
</body>
</html>
"""

CLEAN_EMAIL = """From: John Doe <john@company.com>
To: jane@company.com
Subject: Meeting tomorrow
Date: Mon, 10 Apr 2026 12:00:00 +0000
Return-Path: <john@company.com>
Message-ID: <msg001@company.com>
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain

Hi Jane, can we meet tomorrow at 10am to discuss the project?
Thanks, John
"""


def test_analyze_phishing_headers():
    results = analyze_headers(SAMPLE_EMAIL)

    assert results["from"] == '"PayPal Security" <security@paypa1.com>'
    assert results["spf"]["status"] == "fail"
    assert results["dkim"]["status"] == "fail"
    assert results["dmarc"]["status"] == "fail"
    assert len(results["suspicious_indicators"]) > 0

    indicators_text = " ".join(results["suspicious_indicators"]).lower()
    assert "return-path mismatch" in indicators_text
    assert "reply-to mismatch" in indicators_text


def test_analyze_clean_headers():
    results = analyze_headers(CLEAN_EMAIL)

    assert results["spf"]["status"] == "pass"
    assert results["dkim"]["status"] == "pass"
    assert results["dmarc"]["status"] == "pass"

    # Should have no mismatch indicators
    mismatch_indicators = [
        i for i in results["suspicious_indicators"]
        if "mismatch" in i.lower()
    ]
    assert len(mismatch_indicators) == 0


def test_verdict_malicious():
    headers = {
        "spf": {"status": "fail"},
        "dkim": {"status": "fail"},
        "dmarc": {"status": "fail"},
        "suspicious_indicators": [
            "Return-Path mismatch",
            "Reply-To mismatch",
            "Urgency keywords in subject",
        ],
    }
    urls = [{"malicious": True, "url": "http://evil.tk/phish"}]
    attachments = []

    result = generate_verdict(headers, urls, attachments)

    assert result["verdict"] == "MALICIOUS"
    assert result["risk_score"] >= 70
    assert len(result["recommendations"]) > 0


def test_verdict_clean():
    headers = {
        "spf": {"status": "pass"},
        "dkim": {"status": "pass"},
        "dmarc": {"status": "pass"},
        "suspicious_indicators": [],
    }

    result = generate_verdict(headers, [], [])

    assert result["verdict"] == "CLEAN"
    assert result["risk_score"] < 15
