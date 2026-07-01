"""
THRAGG Module: logs
Version: 3.0.0

Contract (frozen, matches nmap.py v2.1 + findings extension):
    run(log_path: str) -> dict
        {
            "metadata": {...},
            "summary": {...},   # stats only, no raw evidence
            "details": {...},   # full event objects, separated by type
            "artifacts": {...},
            "errors": [...]
        }
"""

import os
import re
import time
import json
from datetime import datetime, timezone

MODULE_NAME = "logs"
MODULE_VERSION = "3.0.0"
OUTPUT_DIR = "thragg_results"

# threshold for flagging repeated failed logins from same IP as brute force
BRUTE_FORCE_THRESHOLD = 5

# Regex patterns for classifying auth.log lines
PATTERNS = {
    "invalid_user": re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"
    ),
    "failed_login": re.compile(
        r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
    ),
    "successful_login": re.compile(
        r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)"
    ),
    "auth_failure": re.compile(
        r"authentication failure;.*user=(?P<user>\S+)"
    ),
    "sudo_event": re.compile(
        r"sudo:\s*(?P<user>\S+)\s*:.*COMMAND="
    ),
    "session_open": re.compile(
        r"session opened for user (?P<user>\S+)"
    ),
    "session_close": re.compile(
        r"session closed for user (?P<user>\S+)"
    ),
    "cron_event": re.compile(
        r"CRON\[\d+\]:\s*\((?P<user>\S+)\)\s*CMD"
    ),
    "illegal_port": re.compile(
        r"(refused connect from|illegal port)\s*(?P<ip>\S+)?", re.IGNORECASE
    ),
    "protocol_mismatch": re.compile(
        r"(protocol|version) mismatch", re.IGNORECASE
    ),
}

# Severity / confidence / category / MITRE mapping per event type
EVENT_META = {
    "failed_login":       {"severity": "Medium", "confidence": "Medium", "category": "Authentication", "mitre": "T1110"},
    "invalid_user":       {"severity": "Medium", "confidence": "Medium", "category": "Authentication", "mitre": "T1110"},
    "successful_login":   {"severity": "Low",    "confidence": "High",   "category": "Authentication", "mitre": "T1078"},
    "auth_failure":       {"severity": "Medium", "confidence": "Medium", "category": "Authentication", "mitre": "T1110"},
    "sudo_event":         {"severity": "Low",    "confidence": "High",   "category": "Privilege Escalation", "mitre": "T1548"},
    "session_open":       {"severity": "Low",    "confidence": "High",   "category": "Authentication", "mitre": "T1078"},
    "session_close":      {"severity": "Low",    "confidence": "High",   "category": "Authentication", "mitre": "T1078"},
    "cron_event":         {"severity": "Low",    "confidence": "Medium", "category": "Persistence", "mitre": "T1053"},
    "illegal_port":       {"severity": "High",   "confidence": "Medium", "category": "Reconnaissance", "mitre": "T1595"},
    "protocol_mismatch":  {"severity": "Medium", "confidence": "Medium", "category": "Reconnaissance", "mitre": "T1595"},
    "too_many_login":     {"severity": "High",   "confidence": "High",   "category": "Authentication", "mitre": "T1110.001"},
}

DETAIL_KEYS = [
    "failed_login_events",
    "successful_login_events",
    "invalid_user_events",
    "authentication_failure_events",
    "sudo_events",
    "session_open_events",
    "session_close_events",
    "cron_events",
    "illegal_port_events",
    "protocol_mismatch_events",
    "too_many_login_events",
]

EVENT_TO_DETAIL_KEY = {
    "failed_login": "failed_login_events",
    "successful_login": "successful_login_events",
    "invalid_user": "invalid_user_events",
    "auth_failure": "authentication_failure_events",
    "sudo_event": "sudo_events",
    "session_open": "session_open_events",
    "session_close": "session_close_events",
    "cron_event": "cron_events",
    "illegal_port": "illegal_port_events",
    "protocol_mismatch": "protocol_mismatch_events",
    "too_many_login": "too_many_login_events",
}

# Drives dynamic finding generation. Each rule maps a details key -> how to
# build a finding if that key has >= min_count events.
FINDING_RULES = [
    {
        "detail_key": "failed_login_events",
        "min_count": 1,
        "title": "Repeated Failed Login Attempts",
        "severity": "Medium",
        "confidence": "Medium",
        "category": "Authentication",
        "mitre": "T1110",
        "description": "Multiple failed password attempts were observed, indicating possible credential guessing.",
        "recommendation": "Review source IPs for repeated failures and consider rate-limiting or lockout policies.",
    },
    {
        "detail_key": "invalid_user_events",
        "min_count": 1,
        "title": "Repeated Invalid User Attempts",
        "severity": "Medium",
        "confidence": "Medium",
        "category": "Authentication",
        "mitre": "T1110",
        "description": "Login attempts were made against usernames that do not exist on the system.",
        "recommendation": "Investigate source IPs; this pattern often precedes automated username enumeration.",
    },
    {
        "detail_key": "authentication_failure_events",
        "min_count": 1,
        "title": "Authentication Failures Detected",
        "severity": "Medium",
        "confidence": "Medium",
        "category": "Authentication",
        "mitre": "T1110",
        "description": "PAM-level authentication failures were recorded outside of normal login flow.",
        "recommendation": "Correlate with failed_login events from the same hosts/users.",
    },
    {
        "detail_key": "illegal_port_events",
        "min_count": 1,
        "title": "Multiple Illegal Port Connection Attempts",
        "severity": "High",
        "confidence": "Medium",
        "category": "Reconnaissance",
        "mitre": "T1595",
        "description": "Connections were refused or flagged on unexpected ports, consistent with port scanning.",
        "recommendation": "Cross-reference with Nmap findings for the same host to confirm active scanning.",
    },
    {
        "detail_key": "protocol_mismatch_events",
        "min_count": 1,
        "title": "Protocol Mismatch Indicating Possible Reconnaissance",
        "severity": "Medium",
        "confidence": "Medium",
        "category": "Reconnaissance",
        "mitre": "T1595",
        "description": "Protocol/version mismatches were logged, often caused by scanners or banner-grabbing tools.",
        "recommendation": "Investigate source IPs for scanning tool signatures (e.g. Nmap NSE probes).",
    },
    {
        "detail_key": "sudo_events",
        "min_count": 5,
        "title": "Excessive Sudo Usage",
        "severity": "Medium",
        "confidence": "Medium",
        "category": "Privilege Escalation",
        "mitre": "T1548",
        "description": "An unusually high number of sudo commands were executed, which may indicate privilege abuse.",
        "recommendation": "Review the specific commands run and confirm they match expected administrative activity.",
    },
    {
        "detail_key": "too_many_login_events",
        "min_count": 1,
        "title": "Possible Brute-Force Activity",
        "severity": "High",
        "confidence": "High",
        "category": "Authentication",
        "mitre": "T1110.001",
        "description": "One or more source IPs exceeded the failed-login threshold, consistent with brute-force password attacks.",
        "recommendation": "Block or throttle the offending source IPs and force password resets for targeted accounts.",
    },
]


def ensure_output_dir():
    """Create the thragg_results directory if it doesn't exist. Returns the path."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    return OUTPUT_DIR


def read_log_file(log_path):
    """Read the log file and return its lines."""
    errors = []

    if not log_path or not os.path.exists(log_path):
        errors.append(f"Log file not found: {log_path}")
        return {"lines": [], "status": "skipped", "errors": errors}

    try:
        with open(log_path, "r", errors="replace") as f:
            lines = f.readlines()
        return {"lines": lines, "status": "completed", "errors": errors}
    except Exception as e:
        errors.append(f"Failed to read log file: {e}")
        return {"lines": [], "status": "failed", "errors": errors}


def _make_event(event_type, line_number, timestamp, raw_line, log_source="auth.log", **fields):
    """Build a standardized event object with severity/category/mitre/confidence."""
    meta = EVENT_META.get(
        event_type,
        {"severity": "Low", "confidence": "Low", "category": "Unknown", "mitre": None},
    )
    event = {
        "event": event_type,
        "severity": meta["severity"],
        "category": meta["category"],
        "mitre": meta["mitre"],
        "confidence": meta["confidence"],
        "event_source": log_source,
        "timestamp": timestamp,
        "line_number": line_number,
        "raw_line": raw_line,
    }
    event.update(fields)
    return event


def parse_log_lines(lines, log_source="auth.log"):
    """
    Classify each line into an event object and group by type.
    Returns dict of detail lists + tracking sets, plus errors.
    """
    errors = []
    details = {key: [] for key in DETAIL_KEYS}
    usernames = set()
    source_ips = set()
    failed_ip_counts = {}

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split()
        timestamp = " ".join(parts[:3]) if len(parts) >= 3 else ""

        for event_type, pattern in PATTERNS.items():
            m = pattern.search(line)
            if not m:
                continue

            groups = m.groupdict()
            user = groups.get("user")
            ip = groups.get("ip")

            if user:
                usernames.add(user)
            if ip:
                source_ips.add(ip)

            fields = {}
            if user:
                fields["username"] = user
            if ip:
                fields["source_ip"] = ip

            event = _make_event(event_type, idx, timestamp, line, log_source=log_source, **fields)
            details[EVENT_TO_DETAIL_KEY[event_type]].append(event)

            if event_type in ("failed_login", "invalid_user") and ip:
                failed_ip_counts[ip] = failed_ip_counts.get(ip, 0) + 1

            break  # one event type per line

    # derive brute-force / too-many-login events from repeated failures per IP
    for ip, count in failed_ip_counts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            event = _make_event(
                "too_many_login",
                line_number=None,
                timestamp=None,
                raw_line=f"{count} failed login attempts from {ip}",
                log_source=log_source,
                source_ip=ip,
                attempt_count=count,
            )
            details["too_many_login_events"].append(event)

    return {
        "details": details,
        "usernames": usernames,
        "source_ips": source_ips,
        "errors": errors,
    }


def build_summary(parsed):
    """Build quick-stat summary dict — counts and severity rollups only."""
    details = parsed["details"]

    counts = {key: len(events) for key, events in details.items()}

    total_events = sum(counts.values())

    high_severity_events = sum(
        1 for events in details.values() for e in events if e["severity"] == "High"
    )

    return {
        "failed_logins": counts["failed_login_events"],
        "successful_logins": counts["successful_login_events"],
        "invalid_users": counts["invalid_user_events"],
        "authentication_failures": counts["authentication_failure_events"],
        "sudo_events": counts["sudo_events"],
        "session_open_events": counts["session_open_events"],
        "session_close_events": counts["session_close_events"],
        "cron_events": counts["cron_events"],
        "illegal_port_attempts": counts["illegal_port_events"],
        "protocol_mismatches": counts["protocol_mismatch_events"],
        "too_many_login_events": counts["too_many_login_events"],
        "unique_usernames": len(parsed["usernames"]),
        "unique_source_ips": len(parsed["source_ips"]),
        "high_severity_events": high_severity_events,
        "total_events": total_events,
    }


def build_findings(parsed):
    """
    Generate analyst-level findings dynamically from parsed detail events.
    No raw log lines here — only aggregated evidence (counts, ips, users, line numbers).
    """
    details = parsed["details"]
    findings = []
    counter = 1

    for rule in FINDING_RULES:
        events = details.get(rule["detail_key"], [])
        if len(events) < rule["min_count"]:
            continue

        source_ips = sorted({e["source_ip"] for e in events if e.get("source_ip")})
        usernames = sorted({e["username"] for e in events if e.get("username")})
        line_numbers = sorted({e["line_number"] for e in events if e.get("line_number") is not None})

        finding = {
            "id": f"LOG-{counter:03d}",
            "title": rule["title"],
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "category": rule["category"],
            "description": rule["description"],
            "evidence": {
                "event_count": len(events),
                "source_ips": source_ips,
                "usernames": usernames,
                "line_numbers": line_numbers,
            },
            "mitre": rule["mitre"],
            "recommendation": rule["recommendation"],
        }
        findings.append(finding)
        counter += 1

    return findings


def run(log_path):
    """Main module entry point. Conforms to THRAGG frozen module contract."""
    start_time = time.time()
    errors = []

    ensure_output_dir()

    read_result = read_log_file(log_path)
    errors.extend(read_result["errors"])

    parsed = parse_log_lines(read_result["lines"], log_source=os.path.basename(log_path) if log_path else "unknown")
    errors.extend(parsed["errors"])

    execution_time = round(time.time() - start_time, 3)

    metadata = {
        "module": MODULE_NAME,
        "module_version": MODULE_VERSION,
        "target": log_path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_time": execution_time,
        "status": read_result["status"],
        "returncode": 0 if read_result["status"] == "completed" else None,
    }

    summary = build_summary(parsed)
    details = parsed["details"]
    findings = build_findings(parsed)
    details["findings"] = findings

    artifacts = {
        "raw_log": log_path if read_result["status"] == "completed" else None,
    }

    return {
        "metadata": metadata,
        "summary": summary,
        "details": details,
        "artifacts": artifacts,
        "errors": errors,
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python logs.py <path_to_auth.log>")
        sys.exit(1)

    result = run(sys.argv[1])

    print(json.dumps(result, indent=2))
