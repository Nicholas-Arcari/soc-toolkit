import json
import re
from collections import Counter

# Critical Windows Security Event IDs mapped to severity levels.
# These are the events every SOC analyst should monitor - they cover
# the key stages of an attack: initial access (4625), persistence
# (4697, 4698, 7045), privilege escalation (4672, 4728), and
# lateral movement (4624 type 3, 4648). Event IDs come from the
# Windows Security Audit Log and are documented by Microsoft.
SECURITY_EVENTS = {
    4624: {"name": "Successful Logon", "severity": "info"},
    4625: {"name": "Failed Logon", "severity": "medium"},
    4634: {"name": "Logoff", "severity": "info"},
    4648: {"name": "Explicit Credential Logon", "severity": "medium"},
    4672: {"name": "Special Privileges Assigned", "severity": "low"},
    4688: {"name": "Process Created", "severity": "info"},
    4689: {"name": "Process Terminated", "severity": "info"},
    4697: {"name": "Service Installed", "severity": "high"},
    4698: {"name": "Scheduled Task Created", "severity": "high"},
    4720: {"name": "User Account Created", "severity": "high"},
    4722: {"name": "User Account Enabled", "severity": "medium"},
    4724: {"name": "Password Reset Attempt", "severity": "medium"},
    4728: {"name": "Member Added to Security Group", "severity": "high"},
    4732: {"name": "Member Added to Local Group", "severity": "high"},
    4738: {"name": "User Account Changed", "severity": "medium"},
    4756: {"name": "Member Added to Universal Group", "severity": "high"},
    4768: {"name": "Kerberos TGT Requested", "severity": "info"},
    4769: {"name": "Kerberos Service Ticket Requested", "severity": "info"},
    4771: {"name": "Kerberos Pre-Auth Failed", "severity": "medium"},
    4776: {"name": "NTLM Authentication", "severity": "low"},
    5140: {"name": "Network Share Accessed", "severity": "low"},
    5145: {"name": "Network Share Object Checked", "severity": "info"},
    7045: {"name": "New Service Installed", "severity": "high"},
}


def analyze_windows_logs(raw_logs: str) -> dict:
    """Analyze Windows Security event logs."""
    events = _parse_events(raw_logs)
    suspicious = [e for e in events if e.get("severity") in ("medium", "high", "critical")]

    event_id_counter = Counter(e.get("event_id") for e in events)
    ip_counter = Counter(
        e["source_ip"] for e in events if e.get("source_ip")
    )
    top_ips = [
        {"ip": ip, "events": count}
        for ip, count in ip_counter.most_common(20)
    ]

    # Detect attack patterns
    attack_patterns = _detect_attack_patterns(events)

    timeline = _build_timeline(events)

    return {
        "total_lines": len(events),
        "suspicious_entries": len(suspicious),
        "event_distribution": dict(event_id_counter.most_common(20)),
        "top_ips": top_ips,
        "attack_patterns": attack_patterns,
        "timeline": timeline,
        "summary": (
            f"Total events: {len(events)} | "
            f"Suspicious: {len(suspicious)} | "
            f"Failed logons (4625): {event_id_counter.get(4625, 0)} | "
            f"New services (7045): {event_id_counter.get(7045, 0)} | "
            f"Account changes: {event_id_counter.get(4720, 0) + event_id_counter.get(4738, 0)}"
        ),
    }


def _parse_events(raw_logs: str) -> list[dict]:
    """Parse Windows event log entries (supports JSON and text formats)."""
    events = []

    # Try JSON format first
    try:
        for line in raw_logs.strip().split("\n"):
            if line.strip():
                event = json.loads(line)
                event_id = event.get("EventID", event.get("event_id", 0))
                event_info = SECURITY_EVENTS.get(event_id, {})
                events.append({
                    "event_id": event_id,
                    "event_name": event_info.get("name", "Unknown"),
                    "severity": event_info.get("severity", "info"),
                    "timestamp": event.get("TimeCreated", event.get("timestamp", "")),
                    "source_ip": event.get("IpAddress", event.get("source_ip", "")),
                    "username": event.get("TargetUserName", event.get("username", "")),
                    "computer": event.get("Computer", event.get("computer", "")),
                })
        return events
    except (json.JSONDecodeError, ValueError):
        pass

    # Fall back to text format
    for line in raw_logs.strip().split("\n"):
        event_id_match = re.search(r"(?:EventID|Event\s*ID)[:\s]+(\d+)", line, re.IGNORECASE)
        if not event_id_match:
            continue

        event_id = int(event_id_match.group(1))
        event_info = SECURITY_EVENTS.get(event_id, {})

        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        user_match = re.search(r"(?:User|Account)[:\s]+(\S+)", line, re.IGNORECASE)

        events.append({
            "event_id": event_id,
            "event_name": event_info.get("name", "Unknown"),
            "severity": event_info.get("severity", "info"),
            "timestamp": "",
            "source_ip": ip_match.group(1) if ip_match else "",
            "username": user_match.group(1) if user_match else "",
            "computer": "",
        })

    return events


def _detect_attack_patterns(events: list[dict]) -> list[dict]:
    """Detect common attack patterns in Windows events.

    Maps detected patterns to MITRE ATT&CK techniques so analysts can
    quickly understand the attack stage and look up recommended mitigations
    in the ATT&CK knowledge base.
    """
    patterns = []

    # Brute force: many 4625 (failed logon) from the same source IP
    failed_by_ip = Counter(
        e["source_ip"] for e in events
        if e.get("event_id") == 4625 and e.get("source_ip")
    )
    for ip, count in failed_by_ip.items():
        if count >= 5:
            patterns.append({
                "pattern": "Brute Force",
                "description": f"IP {ip}: {count} failed logon attempts",
                "severity": "high" if count >= 20 else "medium",
                "mitre": "T1110 - Brute Force",
            })

    # Lateral movement: 4624 type 3 from multiple sources
    network_logons = [e for e in events if e.get("event_id") == 4624]
    if len(network_logons) > 10:
        patterns.append({
            "pattern": "Possible Lateral Movement",
            "description": f"{len(network_logons)} network logon events detected",
            "severity": "medium",
            "mitre": "T1021 - Remote Services",
        })

    # Persistence: new services (7045/4697) or scheduled tasks (4698) are
    # high-priority alerts because they indicate an attacker establishing
    # persistence - the malware will survive reboots
    persistence_events = [
        e for e in events if e.get("event_id") in (4697, 4698, 7045)
    ]
    for event in persistence_events:
        patterns.append({
            "pattern": "Persistence Mechanism",
            "description": f"{event['event_name']} detected",
            "severity": "high",
            "mitre": "T1543 - Create or Modify System Process",
        })

    return patterns


def _build_timeline(events: list[dict]) -> list[dict]:
    """Build event timeline."""
    hourly: Counter[str] = Counter()
    for event in events:
        ts = event.get("timestamp", "")
        hour_match = re.search(r"(\d{2}):\d{2}:\d{2}", str(ts))
        if hour_match:
            hourly[hour_match.group(1)] += 1

    return [
        {"hour": hour, "count": count}
        for hour, count in sorted(hourly.items())
    ]
