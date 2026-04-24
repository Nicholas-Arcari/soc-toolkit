import re
from collections import Counter


def analyze_web_logs(raw_logs: str) -> dict:
    """Analyze Apache/Nginx access logs for suspicious activity."""
    lines = raw_logs.strip().split("\n")
    entries = []
    suspicious_entries = []

    for line in lines:
        entry = _parse_access_log(line)
        if entry:
            entries.append(entry)
            if _is_suspicious(entry):
                entry["suspicious_reasons"] = _get_suspicious_reasons(entry)
                suspicious_entries.append(entry)

    ip_counter = Counter(e["ip"] for e in entries if e.get("ip"))
    top_ips = [
        {"ip": ip, "requests": count}
        for ip, count in ip_counter.most_common(20)
    ]

    status_counter = Counter(e.get("status", 0) for e in entries)
    timeline = _build_timeline(entries)

    return {
        "total_lines": len(lines),
        "suspicious_entries": len(suspicious_entries),
        "top_ips": top_ips,
        "status_codes": dict(status_counter),
        "suspicious_requests": suspicious_entries[:100],
        "timeline": timeline,
        "summary": (
            f"Total requests: {len(entries)} | "
            f"Suspicious: {len(suspicious_entries)} | "
            f"Unique IPs: {len(ip_counter)} | "
            f"4xx errors: {status_counter.get(404, 0) + status_counter.get(403, 0)} | "
            f"5xx errors: {sum(v for k, v in status_counter.items() if 500 <= k < 600)}"
        ),
    }


def _parse_access_log(line: str) -> dict | None:
    """Parse a Combined Log Format line."""
    pattern = re.compile(
        r'(\S+)\s+'           # IP
        r'\S+\s+'             # ident
        r'\S+\s+'             # user
        r'\[([^\]]+)\]\s+'    # timestamp
        r'"(\S+)\s+'          # method
        r'(\S+)\s+'           # path
        r'\S+"\s+'            # protocol
        r'(\d{3})\s+'         # status
        r'(\d+|-)'            # size
    )
    match = pattern.match(line)
    if not match:
        return None

    return {
        "ip": match.group(1),
        "timestamp": match.group(2),
        "method": match.group(3),
        "path": match.group(4),
        "status": int(match.group(5)),
        "size": int(match.group(6)) if match.group(6) != "-" else 0,
    }


def _is_suspicious(entry: dict) -> bool:
    """Check if a request is suspicious."""
    path = entry.get("path", "").lower()
    method = entry.get("method", "")

    # SQL injection: single quotes, UNION SELECT, and tautologies (1=1)
    # are the most common SQLi payloads in automated scanners like SQLMap
    sqli_patterns = ["'", "union", "select", "drop", "--", "or%20", "1=1"]
    if any(p in path for p in sqli_patterns):
        return True

    # Path traversal (../) attempts to escape the web root and read
    # sensitive files like /etc/passwd or win.ini. %2f is the URL-encoded
    # slash used to bypass naive input filters
    if "../" in path or "..%2f" in path.lower():
        return True

    # Command injection via shell metacharacters - if these reach a
    # system() call or exec(), the attacker gets RCE
    if any(p in path for p in [";", "|", "`", "$("]):
        return True

    # Common paths probed by automated scanners (Nikto, Nuclei, WPScan).
    # Seeing multiple of these from one IP indicates reconnaissance
    scanner_paths = [
        "/admin", "/wp-admin", "/wp-login", "/.env", "/config",
        "/phpmyadmin", "/.git", "/backup", "/shell", "/cmd",
        "/actuator", "/.well-known", "/xmlrpc.php",
    ]
    if any(path.startswith(p) for p in scanner_paths):
        return True

    # Unusual HTTP methods
    if method not in ("GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"):
        return True

    return False


def _get_suspicious_reasons(entry: dict) -> list[str]:
    """Get specific reasons why a request is suspicious."""
    reasons = []
    path = entry.get("path", "").lower()

    if any(p in path for p in ["'", "union", "select", "1=1"]):
        reasons.append("Possible SQL injection")
    if "../" in path or "..%2f" in path:
        reasons.append("Path traversal attempt")
    if any(p in path for p in [";", "|", "`"]):
        reasons.append("Possible command injection")
    if any(path.startswith(p) for p in ["/admin", "/wp-admin", "/.env", "/.git"]):
        reasons.append("Sensitive path enumeration")

    return reasons


def _build_timeline(entries: list[dict]) -> list[dict]:
    """Build hourly request timeline."""
    hourly: Counter[str] = Counter()
    for entry in entries:
        ts = entry.get("timestamp", "")
        hour_match = re.search(r":(\d{2}):\d{2}:\d{2}", ts)
        if hour_match:
            hourly[hour_match.group(1)] += 1

    return [
        {"hour": hour, "count": count}
        for hour, count in sorted(hourly.items())
    ]
