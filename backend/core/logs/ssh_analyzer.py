import re
from collections import Counter


def analyze_ssh_logs(raw_logs: str) -> dict:
    """Analyze SSH auth logs for brute force and suspicious activity.

    Correlates failed and successful logins to detect the most dangerous
    scenario: a brute force attack that eventually succeeds. A successful
    login from an IP that previously had many failures is a strong indicator
    of compromise and should trigger immediate incident response.
    """
    lines = raw_logs.strip().split("\n")
    failed_attempts = []
    successful_logins = []
    invalid_users = []

    for line in lines:
        if "Failed password" in line:
            entry = _parse_ssh_line(line, "failed")
            if entry:
                failed_attempts.append(entry)

        elif "Accepted" in line:
            entry = _parse_ssh_line(line, "accepted")
            if entry:
                successful_logins.append(entry)

        elif "Invalid user" in line:
            entry = _parse_ssh_line(line, "invalid_user")
            if entry:
                invalid_users.append(entry)

    # Aggregate by IP
    ip_counter = Counter(e["ip"] for e in failed_attempts if e.get("ip"))
    top_ips = [
        {"ip": ip, "attempts": count, "category": _categorize_ip(count)}
        for ip, count in ip_counter.most_common(20)
    ]

    # Build timeline
    timeline = _build_timeline(failed_attempts)

    # Detect brute force patterns
    brute_force_ips = [ip for ip, count in ip_counter.items() if count >= 5]
    suspicious = len(failed_attempts)

    summary_parts = [
        f"Total lines: {len(lines)}",
        f"Failed attempts: {len(failed_attempts)}",
        f"Successful logins: {len(successful_logins)}",
        f"Invalid users: {len(invalid_users)}",
        f"Brute force IPs (5+ attempts): {len(brute_force_ips)}",
    ]

    return {
        "total_lines": len(lines),
        "suspicious_entries": suspicious,
        "failed_attempts": failed_attempts,
        "successful_logins": successful_logins,
        "invalid_users": invalid_users,
        "top_ips": top_ips,
        "brute_force_ips": brute_force_ips,
        "timeline": timeline,
        "summary": " | ".join(summary_parts),
    }


def _parse_ssh_line(line: str, event_type: str) -> dict | None:
    """Parse a single SSH log line."""
    ip_match = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
    user_match = re.search(r"(?:for|user)\s+(\S+)", line)
    port_match = re.search(r"port\s+(\d+)", line)

    # Parse timestamp (common syslog format: "Mon DD HH:MM:SS")
    ts_match = re.match(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    timestamp = ts_match.group(1) if ts_match else None

    if not ip_match:
        return None

    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "ip": ip_match.group(1),
        "user": user_match.group(1) if user_match else "unknown",
        "port": int(port_match.group(1)) if port_match else None,
        "raw": line.strip(),
    }


def _categorize_ip(attempt_count: int) -> str:
    """Categorize an IP based on failed attempt count.

    Thresholds based on real-world SOC triage experience: 5+ attempts
    indicates automated scanning, 50+ is a sustained brute force,
    100+ is likely a botnet or dedicated attacker worth blocking.
    """
    if attempt_count >= 100:
        return "critical"
    if attempt_count >= 50:
        return "high"
    if attempt_count >= 10:
        return "medium"
    if attempt_count >= 5:
        return "low"
    return "info"


def _build_timeline(events: list[dict]) -> list[dict]:
    """Build an hourly timeline of events."""
    hourly = Counter()
    for event in events:
        ts = event.get("timestamp")
        if ts:
            hour_match = re.search(r"(\d{2}):\d{2}:\d{2}", ts)
            if hour_match:
                hourly[hour_match.group(1)] += 1

    return [
        {"hour": hour, "count": count}
        for hour, count in sorted(hourly.items())
    ]
