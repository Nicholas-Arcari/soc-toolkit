from core.logs.ssh_analyzer import analyze_ssh_logs
from core.logs.web_analyzer import analyze_web_logs


SAMPLE_SSH_LOG = """Apr 10 08:15:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Apr 10 08:15:03 server sshd[1235]: Failed password for root from 192.168.1.100 port 22 ssh2
Apr 10 08:15:05 server sshd[1236]: Failed password for root from 192.168.1.100 port 22 ssh2
Apr 10 08:15:07 server sshd[1237]: Failed password for admin from 192.168.1.100 port 22 ssh2
Apr 10 08:15:09 server sshd[1238]: Failed password for admin from 192.168.1.100 port 22 ssh2
Apr 10 08:15:11 server sshd[1239]: Failed password for root from 10.0.0.50 port 22 ssh2
Apr 10 08:16:00 server sshd[1240]: Accepted password for deploy from 10.0.0.1 port 22 ssh2
Apr 10 08:17:00 server sshd[1241]: Invalid user test from 192.168.1.100 port 22"""

SAMPLE_ACCESS_LOG = """192.168.1.50 - - [10/Apr/2026:08:00:01 +0000] "GET / HTTP/1.1" 200 1234
192.168.1.50 - - [10/Apr/2026:08:00:02 +0000] "GET /admin HTTP/1.1" 403 567
192.168.1.100 - - [10/Apr/2026:08:00:03 +0000] "GET /login?user=admin'%20OR%201=1-- HTTP/1.1" 200 890
192.168.1.100 - - [10/Apr/2026:08:00:04 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0
192.168.1.100 - - [10/Apr/2026:08:00:05 +0000] "GET /.env HTTP/1.1" 404 0
192.168.1.200 - - [10/Apr/2026:08:00:06 +0000] "GET /index.html HTTP/1.1" 200 5678"""


def test_ssh_brute_force_detection():
    result = analyze_ssh_logs(SAMPLE_SSH_LOG)

    assert result["total_lines"] == 8
    assert len(result["failed_attempts"]) == 6
    assert len(result["successful_logins"]) == 1
    assert len(result["invalid_users"]) == 1

    # 192.168.1.100 should be top IP with 5 failed attempts
    top_ip = result["top_ips"][0]
    assert top_ip["ip"] == "192.168.1.100"
    assert top_ip["attempts"] == 5

    # Should be flagged as brute force
    assert "192.168.1.100" in result["brute_force_ips"]


def test_ssh_timeline():
    result = analyze_ssh_logs(SAMPLE_SSH_LOG)
    assert len(result["timeline"]) > 0
    assert result["timeline"][0]["hour"] == "08"


def test_web_sqli_detection():
    result = analyze_web_logs(SAMPLE_ACCESS_LOG)

    assert result["total_lines"] == 6
    assert result["suspicious_entries"] > 0

    suspicious_paths = [r.get("path", "") for r in result.get("suspicious_requests", [])]
    assert any("1=1" in p for p in suspicious_paths)


def test_web_path_traversal_detection():
    result = analyze_web_logs(SAMPLE_ACCESS_LOG)

    suspicious_paths = [r.get("path", "") for r in result.get("suspicious_requests", [])]
    assert any(".." in p for p in suspicious_paths)


def test_web_sensitive_path_detection():
    result = analyze_web_logs(SAMPLE_ACCESS_LOG)

    suspicious_paths = [r.get("path", "") for r in result.get("suspicious_requests", [])]
    assert any(".env" in p for p in suspicious_paths)
    assert any("/admin" in p for p in suspicious_paths)
