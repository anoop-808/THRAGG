"""
modules/zap.py
THRAGG Web Application Security Analysis module - Phase 1: Report Ingestion
Version 1.1.0

Reads an existing OWASP ZAP JSON report (from a completed scan) and
converts it into THRAGG's standard intelligence contract. Does NOT run
a scan itself - it is an intelligence translator, not a scanner.

Public interface:
    run(report_path: str) -> dict
"""

import json
import os
import re
import time
from collections import defaultdict


MODULE_NAME = "zap"
MODULE_VERSION = "1.1.0"
PHASE = "Phase 1: Report Ingestion"

OUTPUT_DIR = "output/zap"

# --- Category classification ------------------------------------------------
# Prefer CWE-driven classification (stable) over keyword-driven (fragile).
# Keyword rules remain as fallback for alerts without a usable CWE.

CWE_CATEGORY_MAP = {
    "89": "Injection",
    "78": "Injection",
    "77": "Injection",
    "91": "Injection",
    "643": "Injection",
    "90": "Injection",
    "611": "Injection",
    "79": "Client Side",
    "352": "Session Management",
    "613": "Session Management",
    "287": "Authentication",
    "306": "Authentication",
    "521": "Authentication",
    "799": "Authentication",
    "16": "Configuration",
    "548": "Configuration",
    "215": "Information Disclosure",
    "200": "Information Disclosure",
    "209": "Information Disclosure",
    "319": "Sensitive Data",
    "311": "Sensitive Data",
    "693": "Security Headers",
    "1021": "Client Side",
    "918": "Server Side",
    "22": "Server Side",
}

CATEGORY_RULES = [
    ("Injection", ["sql injection", "command injection", "code injection",
                    "xpath injection", "ldap injection", "xxe", "injection"]),
    ("Authentication", ["authentication", "brute force", "credentials",
                         "password", "login"]),
    ("Session Management", ["session", "cookie", "csrf"]),
    ("Security Headers", ["header", "csp", "x-frame", "x-content-type",
                           "hsts", "strict-transport"]),
    ("Information Disclosure", ["information disclosure", "information leak",
                                 "version disclosure", "stack trace",
                                 "comment", "debug"]),
    ("Sensitive Data", ["sensitive", "private key", "credit card",
                         "pii", "exposed"]),
    ("Configuration", ["misconfiguration", "config", "default",
                        "directory listing", "backup file"]),
    ("Client Side", ["cross site scripting", "xss", "dom", "client side",
                      "clickjacking"]),
    ("Server Side", ["server side", "ssrf", "remote code", "path traversal"]),
]

# --- OWASP Top 10 (2021) mapping --------------------------------------------

CWE_OWASP_MAP = {
    "89": "A03:2021 - Injection",
    "78": "A03:2021 - Injection",
    "77": "A03:2021 - Injection",
    "91": "A03:2021 - Injection",
    "643": "A03:2021 - Injection",
    "90": "A03:2021 - Injection",
    "611": "A03:2021 - Injection",
    "79": "A03:2021 - Injection",
    "352": "A01:2021 - Broken Access Control",
    "22": "A01:2021 - Broken Access Control",
    "548": "A01:2021 - Broken Access Control",
    "319": "A02:2021 - Cryptographic Failures",
    "311": "A02:2021 - Cryptographic Failures",
    "16": "A05:2021 - Security Misconfiguration",
    "693": "A05:2021 - Security Misconfiguration",
    "215": "A05:2021 - Security Misconfiguration",
    "287": "A07:2021 - Identification and Authentication Failures",
    "306": "A07:2021 - Identification and Authentication Failures",
    "521": "A07:2021 - Identification and Authentication Failures",
    "799": "A07:2021 - Identification and Authentication Failures",
    "613": "A07:2021 - Identification and Authentication Failures",
    "918": "A10:2021 - Server-Side Request Forgery",
}

OWASP_TOP10_RULES = [
    ("A01:2021 - Broken Access Control", ["access control", "path traversal",
                                           "directory browsing", "forced browsing"]),
    ("A02:2021 - Cryptographic Failures", ["tls", "ssl", "cipher", "https",
                                            "weak encryption", "cleartext"]),
    ("A03:2021 - Injection", ["injection", "xss", "cross site scripting"]),
    ("A04:2021 - Insecure Design", ["insecure design"]),
    ("A05:2021 - Security Misconfiguration", ["misconfiguration", "header",
                                               "default credentials",
                                               "directory listing"]),
    ("A06:2021 - Vulnerable and Outdated Components", ["outdated", "vulnerable component",
                                                         "version disclosure"]),
    ("A07:2021 - Identification and Authentication Failures", ["authentication",
                                                                 "session", "credentials"]),
    ("A08:2021 - Software and Data Integrity Failures", ["integrity", "deserialization"]),
    ("A09:2021 - Security Logging and Monitoring Failures", ["logging", "monitoring"]),
    ("A10:2021 - Server-Side Request Forgery", ["ssrf", "server side request forgery"]),
]

# --- MITRE ATT&CK mapping (small starter set, expand later) ----------------

CWE_MITRE_MAP = {
    "89": "T1190",
    "78": "T1059",
    "77": "T1059",
    "79": "T1059",
    "611": "T1190",
    "352": "T1190",
    "287": "T1110",
    "799": "T1110",
    "521": "T1110",
    "22": "T1083",
    "918": "T1190",
    "319": "T1040",
}

KEYWORD_MITRE_RULES = [
    ("T1190", ["sql injection", "xxe", "ssrf", "remote code"]),
    ("T1059", ["xss", "cross site scripting", "command injection"]),
    ("T1110", ["brute force", "authentication", "weak password"]),
    ("T1083", ["path traversal", "directory listing"]),
    ("T1040", ["cleartext", "sniffing"]),
]

# --- THRAGG recommendations (independent of ZAP's own "solution" text) -----

RECOMMENDATIONS = {
    "Security Headers": "Configure the web server / application to send the missing "
                         "security headers (CSP, X-Frame-Options, X-Content-Type-Options, "
                         "HSTS) on every HTTP response.",
    "Injection": "Use parameterized queries / prepared statements and strict input "
                 "validation. Never build queries or commands via string concatenation "
                 "of user input.",
    "Client Side": "Apply context-aware output encoding and a strict Content-Security-Policy "
                    "to prevent injected scripts from executing in the browser.",
    "Authentication": "Enforce strong password policies, account lockout / rate limiting, "
                       "and multi-factor authentication on all authentication endpoints.",
    "Session Management": "Regenerate session identifiers on login, set Secure/HttpOnly/"
                           "SameSite cookie attributes, and enforce short session timeouts.",
    "Information Disclosure": "Disable verbose error messages and debug output in "
                               "production, and remove version banners from responses.",
    "Sensitive Data": "Encrypt sensitive data in transit and at rest, and ensure it is "
                       "never exposed in URLs, logs, or client-side code.",
    "Configuration": "Review server and application configuration against vendor hardening "
                      "guides; disable directory listing and remove default/backup files.",
    "Server Side": "Validate and allow-list any user-supplied URLs or file paths used in "
                    "server-side requests or file operations.",
    "Other": "Review the finding details and apply the vendor-recommended remediation.",
}


def ensure_output_dir():
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    except OSError:
        pass


def load_report(report_path: str):
    if not report_path or not os.path.isfile(report_path):
        return None, f"Report file not found: {report_path}"

    try:
        with open(report_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return None, f"Report is not valid JSON: {e}"
    except OSError as e:
        return None, f"Could not read report file: {e}"

    if not isinstance(data, dict):
        return None, "Report JSON root is not an object - unexpected ZAP format"

    return data, None


def parse_alerts(data: dict):
    """Extract every alert, tagging each with a stable alert_id for
    later correlation back from findings."""
    raw_alerts = []
    sites = data.get("site", [])

    if isinstance(sites, dict):
        sites = [sites]

    alert_id = 0
    for site in sites:
        site_name = site.get("@name", "unknown")
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            continue

        for alert in alerts:
            instances = alert.get("instances", [])
            if isinstance(instances, list) and instances:
                for inst in instances:
                    raw_alerts.append(_extract_alert_fields(alert, site_name, inst, alert_id))
                    alert_id += 1
            else:
                raw_alerts.append(_extract_alert_fields(alert, site_name, {}, alert_id))
                alert_id += 1

    return raw_alerts


def _extract_alert_fields(alert: dict, site_name: str, instance: dict, alert_id: int):
    return {
        "alert_id": alert_id,
        "title": alert.get("name", "Unknown Alert"),
        "risk": alert.get("riskdesc", alert.get("risk", "")),
        "confidence": alert.get("confidence", ""),
        "url": instance.get("uri", site_name),
        "parameter": instance.get("param", ""),
        "attack": instance.get("attack", ""),
        "description": alert.get("desc", ""),
        "solution": alert.get("solution", ""),
        "reference": alert.get("reference", ""),
        "cwe": alert.get("cweid", ""),
        "wasc": alert.get("wascid", ""),
        "sourceid": alert.get("sourceid", ""),
    }


_SEVERITY_RE = re.compile(r"(High|Medium|Low|Informational)", re.IGNORECASE)


def _normalize_severity(raw_risk: str) -> str:
    if not raw_risk:
        return "Unknown"
    match = _SEVERITY_RE.search(raw_risk)
    if match:
        return match.group(1).capitalize()
    return "Unknown"


def normalize_alerts(raw_alerts: list):
    normalized = []
    for a in raw_alerts:
        n = dict(a)
        n["severity"] = _normalize_severity(a.get("risk", ""))
        n["confidence"] = (a.get("confidence") or "").strip()
        n["title"] = (a.get("title") or "Unknown Alert").strip()
        n["url"] = (a.get("url") or "").strip()
        n["cwe"] = str(a.get("cwe") or "").strip()
        n["wasc"] = str(a.get("wasc") or "").strip()
        n["category"] = _classify(n["cwe"], n["title"], a.get("description", ""))
        n["owasp_top10"] = _map_owasp_top10(n["cwe"], n["title"], a.get("description", ""))
        n["mitre"] = _map_mitre(n["cwe"], n["title"], a.get("description", ""))
        normalized.append(n)
    return normalized


def _classify(cwe: str, title: str, description: str) -> str:
    if cwe and cwe in CWE_CATEGORY_MAP:
        return CWE_CATEGORY_MAP[cwe]
    text = f"{title} {description}".lower()
    for category, keywords in CATEGORY_RULES:
        if any(kw in text for kw in keywords):
            return category
    return "Other"


def _map_owasp_top10(cwe: str, title: str, description: str) -> str:
    if cwe and cwe in CWE_OWASP_MAP:
        return CWE_OWASP_MAP[cwe]
    text = f"{title} {description}".lower()
    for owasp_id, keywords in OWASP_TOP10_RULES:
        if any(kw in text for kw in keywords):
            return owasp_id
    return "Unmapped"


def _map_mitre(cwe: str, title: str, description: str) -> str:
    if cwe and cwe in CWE_MITRE_MAP:
        return CWE_MITRE_MAP[cwe]
    text = f"{title} {description}".lower()
    for technique_id, keywords in KEYWORD_MITRE_RULES:
        if any(kw in text for kw in keywords):
            return technique_id
    return "Unmapped"


_SEVERITY_RANK = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0, "Unknown": 0}
_SEVERITY_WEIGHT = {"High": 10, "Medium": 4, "Low": 1, "Informational": 0, "Unknown": 0}


def _calculate_risk_score(severity_counts: dict) -> int:
    """Weighted, capped 0-100 risk score so THRAGG can compare modules
    numerically instead of by string severity."""
    raw = (
        severity_counts.get("High", 0) * _SEVERITY_WEIGHT["High"]
        + severity_counts.get("Medium", 0) * _SEVERITY_WEIGHT["Medium"]
        + severity_counts.get("Low", 0) * _SEVERITY_WEIGHT["Low"]
    )
    return min(100, raw)


def build_summary(normalized_alerts: list):
    severity_counts = defaultdict(int)
    urls = set()
    categories = set()
    cwes = set()

    for a in normalized_alerts:
        severity_counts[a["severity"]] += 1
        if a["url"]:
            urls.add(a["url"])
        categories.add(a["category"])
        if a["cwe"]:
            cwes.add(a["cwe"])

    return {
        "total_alerts": len(normalized_alerts),
        "high": severity_counts.get("High", 0),
        "medium": severity_counts.get("Medium", 0),
        "low": severity_counts.get("Low", 0),
        "informational": severity_counts.get("Informational", 0),
        "unknown": severity_counts.get("Unknown", 0),
        "affected_urls": len(urls),
        "categories_found": len(categories),
        "cwe_count": len(cwes),
        "risk_score": _calculate_risk_score(severity_counts),
    }


def _finding_confidence(evidence_count: int, affected_urls: int, has_cwe: bool) -> str:
    """Confidence in the finding itself (not ZAP's per-alert confidence),
    derived from how much corroborating evidence backs it."""
    score = 0
    if evidence_count >= 5:
        score += 1
    if affected_urls >= 3:
        score += 1
    if has_cwe:
        score += 1

    if score >= 2:
        return "High"
    if score == 1:
        return "Medium"
    return "Low"


def build_findings(normalized_alerts: list):
    groups = defaultdict(list)
    for a in normalized_alerts:
        key = (a["title"], a["category"])
        groups[key].append(a)

    findings = []
    for (title, category), alerts in groups.items():
        urls = {a["url"] for a in alerts if a["url"]}
        cwes = sorted({a["cwe"] for a in alerts if a["cwe"]})
        mitre_ids = sorted({a["mitre"] for a in alerts if a["mitre"] != "Unmapped"})
        related_alerts = sorted({a["alert_id"] for a in alerts})

        severity = max(
            (a["severity"] for a in alerts),
            key=lambda s: _SEVERITY_RANK.get(s, 0),
        )
        owasp = next((a["owasp_top10"] for a in alerts if a["owasp_top10"] != "Unmapped"), "Unmapped")
        solution = next((a["solution"] for a in alerts if a["solution"]), "")
        recommendation = RECOMMENDATIONS.get(category, RECOMMENDATIONS["Other"])
        confidence = _finding_confidence(len(alerts), len(urls), bool(cwes))

        findings.append({
            "finding": title,
            "category": category,
            "risk": severity,
            "confidence": confidence,
            "owasp_top10": owasp,
            "mitre_attack": mitre_ids,
            "cwe": cwes,
            "evidence_count": len(alerts),
            "affected_urls": len(urls),
            "example_urls": sorted(urls)[:5],
            "solution": solution,
            "recommendation": recommendation,
            "related_alerts": related_alerts,
        })

    findings.sort(key=lambda f: _SEVERITY_RANK.get(f["risk"], 0), reverse=True)
    return findings


def build_artifacts(report_path: str):
    base, _ = os.path.splitext(report_path)
    html_guess = base + ".html"
    return {
        "json_report": report_path,
        "html_report": html_guess if os.path.isfile(html_guess) else None,
        "source": "OWASP ZAP Desktop",
    }


def build_metadata(report_path: str, status: str, start_time: float) -> dict:
    return {
        "module": MODULE_NAME,
        "module_version": MODULE_VERSION,
        "phase": PHASE,
        "status": status,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_time": round(time.time() - start_time, 4),
        "report_path": report_path,
    }


def run(report_path: str) -> dict:
    """THRAGG public interface. Always returns the standard contract:

    {
        "metadata": {...},
        "summary": {...},
        "details": {...},
        "artifacts": {...},
        "errors": [...]
    }

    Never raises - any failure is captured in "errors" with status "failed".
    """
    start_time = time.time()
    ensure_output_dir()
    errors = []

    data, load_error = load_report(report_path)
    if load_error:
        errors.append(load_error)
        return {
            "metadata": build_metadata(report_path, "failed", start_time),
            "summary": {},
            "details": {"findings": []},
            "artifacts": {},
            "errors": errors,
        }

    try:
        raw_alerts = parse_alerts(data)
        normalized_alerts = normalize_alerts(raw_alerts)
        summary = build_summary(normalized_alerts)
        findings = build_findings(normalized_alerts)
        artifacts = build_artifacts(report_path)
    except Exception as e:
        errors.append(f"Unexpected error while processing report: {e}")
        return {
            "metadata": build_metadata(report_path, "failed", start_time),
            "summary": {},
            "details": {"findings": []},
            "artifacts": {},
            "errors": errors,
        }

    return {
        "metadata": build_metadata(report_path, "completed", start_time),
        "summary": summary,
        "details": {
            "raw_alert_count": len(raw_alerts),
            "alerts": normalized_alerts,
            "findings": findings,
        },
        "artifacts": artifacts,
        "errors": errors,
    }


if __name__ == "__main__":
    import sys
    import pprint

    if len(sys.argv) < 2:
        print("Usage: python zap.py <zap_report.json>")
        sys.exit(1)

    result = run(sys.argv[1])
    pprint.pprint(result)
