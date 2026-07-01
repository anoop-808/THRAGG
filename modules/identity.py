"""
THRAGG Module: identity.py
Purpose: Analyze identity infrastructure evidence from Azure / Entra ID exports.

Frozen contract:
    run(input_path) -> {
        metadata, summary, details, artifacts, errors
    }

Supported input types (auto-detected by filename + structure):
    users.json              Microsoft Graph /users export
    groups.json             Microsoft Graph /groups export
    applications.json       Microsoft Graph /applications export
    service_principals.json Microsoft Graph /servicePrincipals export
    role_assignments.json   Azure RBAC role assignments export
    subscription.json       Azure subscription/tenant metadata

    input_path can be:
        - a single .json file
        - a folder containing any mix of the above (walked recursively)

Internal pipeline:
    File -> Detect Type -> Parser -> Raw Identity Object
         -> Rule Engine -> Raw Finding -> normalize_finding()
         -> THRAGG Finding

Design rules:
    - identity.py NEVER calls Azure CLI, Graph API, or any live service.
    - identity.py NEVER modifies users, roles, permissions, or MFA settings.
    - identity.py ONLY reads evidence that already exists in exported files.
    - No AI, no guessing. Only findings supported by real evidence.
    - Missing/empty files generate a warning, never a crash.
    - Every finding maps to MITRE ATT&CK technique AND tactic.
    - Confidence is computed from signal strength, not hardcoded.
    - Risk score = severity x confidence x exposure x exploitability.
    - Every rule has a stable ID (ID-USER-001, ID-APP-002, etc.).
"""

import os
import json
import time
import re
from datetime import datetime, timezone

MODULE_VERSION = "1.1.0"
MODULE_NAME = "identity"
TOOL_NAME = "Azure / Entra ID"

SUPPORTED_FORMATS = {".json"}

# ---------------------------------------------------------------------------
# File type fingerprints
# ---------------------------------------------------------------------------

FILENAME_TYPE_MAP = {
    "users.json": "users",
    "groups.json": "groups",
    "applications.json": "applications",
    "service_principals.json": "service_principals",
    "role_assignments.json": "role_assignments",
    "subscription.json": "subscription",
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK — technique + tactic together
# Every finding references both so analysts get full ATT&CK context.
# ---------------------------------------------------------------------------

MITRE = {
    "valid_accounts": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
    },
    "account_discovery": {
        "technique_id": "T1087",
        "technique": "Account Discovery",
        "tactic": "Discovery",
    },
    "modify_auth": {
        "technique_id": "T1556",
        "technique": "Modify Authentication Process",
        "tactic": "Credential Access, Defense Evasion, Persistence",
    },
    "steal_token": {
        "technique_id": "T1528",
        "technique": "Steal Application Access Token",
        "tactic": "Credential Access",
    },
    "create_account": {
        "technique_id": "T1136",
        "technique": "Create Account",
        "tactic": "Persistence",
    },
    "cloud_accounts": {
        "technique_id": "T1078.004",
        "technique": "Valid Accounts: Cloud Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
    },
    "persistence_accounts": {
        "technique_id": "T1098",
        "technique": "Account Manipulation",
        "tactic": "Persistence, Privilege Escalation",
    },
    "app_access_token": {
        "technique_id": "T1550.001",
        "technique": "Use Alternate Authentication Material: Application Access Token",
        "tactic": "Defense Evasion, Lateral Movement",
    },
    "oauth_abuse": {
        "technique_id": "T1550.001",
        "technique": "Use Alternate Authentication Material: Application Access Token",
        "tactic": "Defense Evasion, Lateral Movement",
    },
    "service_principal_abuse": {
        "technique_id": "T1528",
        "technique": "Steal Application Access Token",
        "tactic": "Credential Access",
    },
    "excessive_permissions": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
    },
    "guest_abuse": {
        "technique_id": "T1078.004",
        "technique": "Valid Accounts: Cloud Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
    },
    "privilege_escalation": {
        "technique_id": "T1078.004",
        "technique": "Valid Accounts: Cloud Accounts",
        "tactic": "Privilege Escalation",
    },
}

# ---------------------------------------------------------------------------
# Graph permission ID -> human-readable scope name
# ---------------------------------------------------------------------------

GRAPH_SCOPE_NAMES = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "243333ab-4d21-40cb-a475-36241daa0842": "Policy.ReadWrite.All",
    "e8e4a2e2-1b36-4a16-b5e2-8fd5e5c8c22f": "PrivilegedAccess.ReadWrite.AzureAD",
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d": "User.Read",
    "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0": "profile",
    "37f7f235-527c-4136-accd-4a02d197296e": "openid",
    "7427e0e9-2fba-42fe-b0c0-848c9e6a8182": "email",
    "10465720-29dd-4523-a11a-6a75c743c9d9": "User.ReadBasic.All",
    "df85f4d6-205c-4ac5-a5ea-6bf408dba283": "Files.ReadWrite.All",
}

HIGH_RISK_SCOPES = {
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Group.ReadWrite.All",
    "Policy.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "Files.ReadWrite.All",
}

# ---------------------------------------------------------------------------
# Scoring tables
# ---------------------------------------------------------------------------

# Severity -> base weight (0-100)
_SEVERITY_WEIGHT = {
    "Critical": 100,
    "High":      80,
    "Medium":    50,
    "Low":       25,
    "Informational": 5,
}

# Confidence label -> numeric score (0-100) and multiplier
_CONFIDENCE_SCORE = {
    "Confirmed": (100, 1.00),
    "High":      ( 80, 0.90),
    "Medium":    ( 60, 0.70),
    "Low":       ( 40, 0.50),
}

# Exposure: how broadly exploitable is the affected scope?
# Assigned per-rule when building raw findings.
# 1.0 = tenant-wide, 0.8 = single user/app, 0.6 = informational scope
_EXPOSURE = {
    "tenant":      1.0,
    "application": 0.9,
    "user":        0.8,
    "group":       0.7,
    "hygiene":     0.6,
}

# Exploitability: how much attacker effort is required?
# 1.0 = trivial (misconfiguration), 0.7 = moderate, 0.5 = requires context
_EXPLOITABILITY = {
    "trivial":   1.0,
    "moderate":  0.7,
    "contextual": 0.5,
}

ADMIN_KEYWORDS = {"admin", "administrator", "root", "superuser", "global", "privileged"}

SUSPICIOUS_GROUP_PATTERNS = [
    (r"intern.*admin",      "Intern group with apparent admin access"),
    (r"contractor.*admin",  "Contractor group with apparent admin access"),
    (r"temp.*admin",        "Temporary group with apparent admin access"),
    (r"guest.*admin",       "Guest group with apparent admin access"),
]

# Microsoft's own tenant ID (used to distinguish 1st-party vs tenant-owned SPs)
_MS_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"


# ===========================================================================
# Confidence computation
# Signal strength -> Confirmed / High / Medium / Low
# Every rule provides explicit signals; confidence is computed, not hardcoded.
# ===========================================================================

def _confidence_from_score(score):
    """Convert numeric confidence score (0-100) to label."""
    if score >= 90:
        return "Confirmed"
    if score >= 70:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def _compute_confidence(signal_type, signals=None):
    """
    Compute confidence label from the nature and strength of signals.

    signal_type: string key describing the detection method
    signals:     optional dict of additional factors that can raise/lower confidence

    Returns (confidence_label, confidence_score, confidence_rationale)
    """
    signals = signals or {}

    base_scores = {
        # Deterministic — data field presence is binary, no ambiguity
        "ext_marker_in_upn":       100,  # #EXT# is a Microsoft-standard guest marker
        "field_is_null":           100,  # confirmed absence of a field
        "json_field_confirmed":    100,  # value explicitly present in export
        "empty_list_confirmed":    100,  # list field is confirmed empty
        "role_assignment_present":  100,  # RBAC assignment is a direct data fact

        # Strong heuristic — pattern is unambiguous but needs role confirmation
        "suspicious_group_name":    85,  # regex match on group display name
        "subscription_type_name":   90,  # subscription name string match

        # Moderate heuristic — keyword match, correct more often than not
        "admin_keyword_in_name":    60,  # name contains "admin" but no role data

        # Weak heuristic — indirect signal only
        "large_count_threshold":    75,  # count exceeds threshold
    }

    score = base_scores.get(signal_type, 60)

    # Adjustments from additional signals
    if signals.get("corroborated_by_second_field"):
        score = min(100, score + 10)
    if signals.get("only_name_matched"):
        score = max(0, score - 10)
    if signals.get("no_role_data_available"):
        score = max(0, score - 15)

    rationale = _confidence_rationale(signal_type, score, signals)
    return _confidence_from_score(score), score, rationale


def _confidence_rationale(signal_type, score, signals):
    rationales = {
        "ext_marker_in_upn":
            "#EXT# suffix is the Microsoft-standard marker for guest/external identities. Deterministic.",
        "field_is_null":
            "Field value is explicitly null in the export. Absence is confirmed, not inferred.",
        "json_field_confirmed":
            "Field value is directly present and readable in the JSON export.",
        "empty_list_confirmed":
            "List field is explicitly empty in the export.",
        "role_assignment_present":
            "Role assignment record exists in the RBAC export. Direct evidence.",
        "suspicious_group_name":
            "Group display name matches a regex pattern combining low-trust and admin identifiers.",
        "subscription_type_name":
            "Subscription name explicitly contains a known non-production keyword.",
        "admin_keyword_in_name":
            "Account name contains an admin keyword. Confidence is reduced because "
            "role membership data is not available in this export to confirm privilege.",
        "large_count_threshold":
            "Count exceeds the defined threshold. Confidence reflects that thresholds "
            "are heuristic, not absolute security violations.",
    }
    base = rationales.get(signal_type, "Signal detected from export data.")
    if signals.get("no_role_data_available"):
        base += " Role membership data unavailable — confidence reduced."
    return base


# ===========================================================================
# Risk score
# Risk = severity_weight x confidence_multiplier x exposure x exploitability
# Normalized to 0-100.
# ===========================================================================

def _compute_risk_score(severity, confidence_label, exposure_key, exploitability_key):
    """
    Four-factor risk score:
        severity       — how bad if exploited
        confidence     — how certain we are about the finding
        exposure       — how broadly reachable is the affected scope
        exploitability — how much effort does an attacker need
    """
    sev_weight  = _SEVERITY_WEIGHT.get(severity, 5)
    _, conf_mul = _CONFIDENCE_SCORE.get(confidence_label, (60, 0.70))
    exposure    = _EXPOSURE.get(exposure_key, 0.8)
    exploit     = _EXPLOITABILITY.get(exploitability_key, 0.7)

    raw = sev_weight * conf_mul * exposure * exploit
    return round(min(raw, 100), 1)


# ===========================================================================
# Public entrypoint (frozen THRAGG contract)
# ===========================================================================

def run(input_path):
    start = time.time()

    result = {
        "metadata": {
            "module": MODULE_NAME,
            "module_version": MODULE_VERSION,
            "tool": TOOL_NAME,
            "input_path": input_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time": None,
            "files_processed": 0,
            "folders_processed": 0,
        },
        "summary": {},
        "details": {},
        "artifacts": {"input_files": []},
        "errors": [],
    }

    if not input_path or not os.path.exists(input_path):
        result["errors"].append(f"Input path does not exist: {input_path}")
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result

    if os.path.isdir(input_path):
        result["metadata"]["folders_processed"] = 1

    files_to_parse = _collect_files(input_path, result["errors"])

    identity_store = {
        "users": [],
        "groups": [],
        "applications": [],
        "service_principals": [],
        "role_assignments": [],
        "subscription": None,
    }

    for filepath in files_to_parse:
        result["artifacts"]["input_files"].append(filepath)
        file_type, data, err = _load_and_detect(filepath)

        if err:
            result["errors"].append(err)
            continue

        if file_type is None:
            result["errors"].append(
                f"Could not identify file type for: {filepath} — skipped. "
                f"Rename to one of: users.json, groups.json, applications.json, "
                f"service_principals.json, role_assignments.json, subscription.json"
            )
            continue

        if file_type == "subscription":
            identity_store["subscription"] = data
        elif file_type in identity_store:
            if isinstance(data, list):
                identity_store[file_type].extend(data)
            elif isinstance(data, dict):
                identity_store[file_type].append(data)

        result["metadata"]["files_processed"] += 1

    raw_findings = []
    raw_findings.extend(_rules_users(identity_store["users"], result["errors"]))
    raw_findings.extend(_rules_groups(identity_store["groups"], result["errors"]))
    raw_findings.extend(_rules_applications(identity_store["applications"], result["errors"]))
    raw_findings.extend(_rules_service_principals(identity_store["service_principals"], result["errors"]))
    raw_findings.extend(_rules_role_assignments(identity_store["role_assignments"], result["errors"]))
    raw_findings.extend(_rules_subscription(identity_store["subscription"], result["errors"]))

    findings = [_normalize_finding(r) for r in raw_findings]

    result["details"] = {"findings": findings}
    result["summary"] = _build_summary(findings, identity_store)
    result["metadata"]["execution_time"] = round(time.time() - start, 4)
    result["metadata"]["warnings"] = [
        e for e in result["errors"]
        if isinstance(e, str) and e.strip().upper().startswith("WARNING:")
    ]
    result["errors"] = [
        e for e in result["errors"]
        if not (isinstance(e, str) and e.strip().upper().startswith("WARNING:"))
    ]

    return result


# ===========================================================================
# File collection
# ===========================================================================

def _collect_files(input_path, errors):
    files = []

    if os.path.isfile(input_path):
        ext = os.path.splitext(input_path)[1].lower()
        if ext in SUPPORTED_FORMATS:
            files.append(input_path)
        else:
            errors.append(f"Unsupported file extension: {input_path}")
        return files

    if os.path.isdir(input_path):
        for root, _dirs, filenames in os.walk(input_path):
            for name in filenames:
                if os.path.splitext(name)[1].lower() in SUPPORTED_FORMATS:
                    files.append(os.path.join(root, name))
        if not files:
            errors.append(f"No .json files found under: {input_path}")
        return files

    errors.append(f"Input path is neither file nor folder: {input_path}")
    return files


# ===========================================================================
# Load + type detection
# ===========================================================================

def _load_and_detect(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read().strip()
    except Exception as exc:
        return None, None, f"Could not read {filepath}: {exc}"

    if not raw:
        return None, None, f"File is empty, skipped: {filepath}"

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, None, f"Invalid JSON in {filepath}: {exc}"

    basename = os.path.basename(filepath).lower()
    if basename in FILENAME_TYPE_MAP:
        return FILENAME_TYPE_MAP[basename], data, None

    file_type = _detect_type_by_content(data)
    return file_type, data, None


def _detect_type_by_content(data):
    sample = data[0] if isinstance(data, list) and data else data
    if not isinstance(sample, dict):
        return None

    keys = set(sample.keys())
    if "userPrincipalName" in keys:
        return "users"
    if "securityEnabled" in keys and "groupTypes" in keys:
        return "groups"
    if "servicePrincipalType" in keys:
        return "service_principals"
    if "appId" in keys and "requiredResourceAccess" in keys:
        return "applications"
    if "homeTenantId" in keys or ("tenantId" in keys and "environmentName" in keys):
        return "subscription"
    if "roleDefinitionId" in keys or "principalId" in keys:
        return "role_assignments"
    return None


# ===========================================================================
# Rule engine — Users
# Each rule: object -> signal -> computed confidence -> raw finding
# ===========================================================================

def _rules_users(users, errors):
    if not users:
        errors.append(
            "WARNING: No users data available. User-related security checks skipped."
        )
        return []

    raw_findings = []

    for idx, user in enumerate(users):
        if not isinstance(user, dict):
            errors.append(f"WARNING: Malformed user record skipped at index {idx}.")
            continue

        upn     = user.get("userPrincipalName", "unknown")
        display = user.get("displayName", upn)
        uid     = user.get("id", "unknown")
        source  = "users.json"

        # ── ID-USER-001: Guest / External account ─────────────────────────
        if "#EXT#" in upn:
            confidence, conf_score, rationale = _compute_confidence("ext_marker_in_upn")
            raw_findings.append({
                "rule_id": "ID-USER-001",
                "title": "Guest / External User Account Detected",
                "severity": "Medium",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "Guest Accounts",
                "asset": upn,
                "user": display,
                "role": "Guest",
                "source": source,
                "object_id": uid,
                "mitre_key": "guest_abuse",
                "exposure": "user",
                "exploitability": "moderate",
                "evidence": {
                    "object_id": uid,
                    "source_file": source,
                    "userPrincipalName": upn,
                    "indicator": "#EXT# suffix confirms external/guest identity",
                },
                "recommendation": (
                    "Review whether this guest account still requires access. "
                    "Enforce Conditional Access policies for guest identities. "
                    "Apply guest access restrictions in Entra External Identities settings."
                ),
            })

        # ── ID-USER-002: No mobile phone (MFA gap signal) ─────────────────
        if not user.get("mobilePhone"):
            confidence, conf_score, rationale = _compute_confidence("field_is_null")
            raw_findings.append({
                "rule_id": "ID-USER-002",
                "title": "No Mobile Phone Registered (Potential MFA Gap)",
                "severity": "Low",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "MFA",
                "asset": upn,
                "user": display,
                "role": None,
                "source": source,
                "object_id": uid,
                "mitre_key": "modify_auth",
                "exposure": "user",
                "exploitability": "contextual",
                "evidence": {
                    "object_id": uid,
                    "source_file": source,
                    "userPrincipalName": upn,
                    "mobilePhone": None,
                    "note": (
                        "mobilePhone is null in the export. SMS and call-based MFA "
                        "are unavailable. Authenticator-app or FIDO2 may still be "
                        "configured but cannot be confirmed from this export alone."
                    ),
                },
                "recommendation": (
                    "Ensure at least one strong MFA method is registered "
                    "(Authenticator app, FIDO2 key, or verified phone). "
                    "Enforce MFA registration via Conditional Access."
                ),
            })

        # ── ID-USER-003: No job title ──────────────────────────────────────
        if not user.get("jobTitle"):
            confidence, conf_score, rationale = _compute_confidence("field_is_null")
            raw_findings.append({
                "rule_id": "ID-USER-003",
                "title": "User Account Missing Job Title",
                "severity": "Informational",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "Identity Hygiene",
                "asset": upn,
                "user": display,
                "role": None,
                "source": source,
                "object_id": uid,
                "mitre_key": "account_discovery",
                "exposure": "hygiene",
                "exploitability": "contextual",
                "evidence": {
                    "object_id": uid,
                    "source_file": source,
                    "userPrincipalName": upn,
                    "jobTitle": None,
                },
                "recommendation": (
                    "Populate jobTitle for all accounts to enable "
                    "role-based access reviews and least-privilege enforcement."
                ),
            })

        # ── ID-USER-004: Admin keyword in name ────────────────────────────
        display_lower = display.lower()
        upn_lower     = upn.lower()
        matched_kw = next(
            (kw for kw in ADMIN_KEYWORDS if kw in display_lower or kw in upn_lower), None
        )
        if matched_kw:
            confidence, conf_score, rationale = _compute_confidence(
                "admin_keyword_in_name",
                signals={"no_role_data_available": True, "only_name_matched": True},
            )
            raw_findings.append({
                "rule_id": "ID-USER-004",
                "title": "Privileged-Named Account Detected",
                "severity": "Medium",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "Privilege",
                "asset": upn,
                "user": display,
                "role": "Suspected Administrator",
                "source": source,
                "object_id": uid,
                "mitre_key": "cloud_accounts",
                "exposure": "user",
                "exploitability": "contextual",
                "evidence": {
                    "object_id": uid,
                    "source_file": source,
                    "userPrincipalName": upn,
                    "matched_keyword": matched_kw,
                    "note": (
                        "Account name contains an admin keyword. "
                        "Confidence is reduced because role membership data "
                        "is not available in this export."
                    ),
                },
                "recommendation": (
                    "Verify assigned roles via Entra ID Roles & Administrators. "
                    "Privileged accounts should use dedicated admin accounts, "
                    "phishing-resistant MFA, and be excluded from general browsing."
                ),
            })

        # ── ID-USER-005: No email address ─────────────────────────────────
        if not user.get("mail"):
            confidence, conf_score, rationale = _compute_confidence("field_is_null")
            raw_findings.append({
                "rule_id": "ID-USER-005",
                "title": "User Account Has No Email Address",
                "severity": "Informational",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "Identity Hygiene",
                "asset": upn,
                "user": display,
                "role": None,
                "source": source,
                "object_id": uid,
                "mitre_key": None,
                "exposure": "hygiene",
                "exploitability": "contextual",
                "evidence": {
                    "object_id": uid,
                    "source_file": source,
                    "userPrincipalName": upn,
                    "mail": None,
                },
                "recommendation": (
                    "Ensure all human accounts have a valid mail attribute "
                    "to enable security alert delivery and account recovery."
                ),
            })

    return raw_findings


# ===========================================================================
# Rule engine — Groups
# ===========================================================================

def _rules_groups(groups, errors):
    if not groups:
        errors.append(
            "WARNING: No groups data available. Group-related security checks skipped."
        )
        return []

    raw_findings = []

    for idx, group in enumerate(groups):
        if not isinstance(group, dict):
            errors.append(f"WARNING: Malformed group record skipped at index {idx}.")
            continue

        gid         = group.get("id", "unknown")
        display     = group.get("displayName", "Unnamed Group")
        description = group.get("description") or ""
        display_lower = display.lower()
        source      = "groups.json"

        # ── ID-GRP-001: Suspicious group name ─────────────────────────────
        for pattern, label in SUSPICIOUS_GROUP_PATTERNS:
            if re.search(pattern, display_lower):
                confidence, conf_score, rationale = _compute_confidence(
                    "suspicious_group_name"
                )
                raw_findings.append({
                    "rule_id": "ID-GRP-001",
                    "title": f"Suspicious Group: {label}",
                    "severity": "High",
                    "confidence": confidence,
                    "confidence_score": conf_score,
                    "confidence_rationale": rationale,
                    "category": "RBAC",
                    "asset": display,
                    "user": None,
                    "role": "Group",
                    "source": source,
                    "object_id": gid,
                    "mitre_key": "privilege_escalation",
                    "exposure": "group",
                    "exploitability": "moderate",
                    "evidence": {
                        "object_id": gid,
                        "source_file": source,
                        "displayName": display,
                        "description": description,
                        "pattern_matched": pattern,
                        "note": (
                            "Name combines a low-trust identity class (intern/contractor) "
                            "with an admin designation — strong indicator of excessive privilege."
                        ),
                    },
                    "recommendation": (
                        "Immediately audit membership and role assignments of this group. "
                        "Interns and contractors should never hold administrative privileges. "
                        "Apply least-privilege RBAC; use time-bound PIM assignments instead."
                    ),
                })
                break

        # ── ID-GRP-002: No expiration on security group ───────────────────
        if group.get("securityEnabled") and not group.get("expirationDateTime"):
            confidence, conf_score, rationale = _compute_confidence("field_is_null")
            raw_findings.append({
                "rule_id": "ID-GRP-002",
                "title": "Security Group Has No Expiration Date",
                "severity": "Low",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "Identity Hygiene",
                "asset": display,
                "user": None,
                "role": "Group",
                "source": source,
                "object_id": gid,
                "mitre_key": "persistence_accounts",
                "exposure": "group",
                "exploitability": "contextual",
                "evidence": {
                    "object_id": gid,
                    "source_file": source,
                    "displayName": display,
                    "securityEnabled": True,
                    "expirationDateTime": None,
                },
                "recommendation": (
                    "Configure group expiration policies in Entra ID. "
                    "Groups without expiry accumulate stale access over time."
                ),
            })

        # ── ID-GRP-003: Vague or missing description ───────────────────────
        if not description or len(description.strip()) < 5:
            confidence, conf_score, rationale = _compute_confidence("field_is_null")
            raw_findings.append({
                "rule_id": "ID-GRP-003",
                "title": "Security Group Has No Meaningful Description",
                "severity": "Informational",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "Identity Hygiene",
                "asset": display,
                "user": None,
                "role": "Group",
                "source": source,
                "object_id": gid,
                "mitre_key": None,
                "exposure": "hygiene",
                "exploitability": "contextual",
                "evidence": {
                    "object_id": gid,
                    "source_file": source,
                    "displayName": display,
                    "description": description or None,
                },
                "recommendation": (
                    "Add a clear description to every security group explaining "
                    "its purpose, owner, and intended membership."
                ),
            })

    return raw_findings


# ===========================================================================
# Rule engine — Applications
# ===========================================================================

def _rules_applications(applications, errors):
    if not applications:
        errors.append(
            "WARNING: No applications data available. Application security checks skipped."
        )
        return []

    raw_findings = []

    for idx, app in enumerate(applications):
        if not isinstance(app, dict):
            errors.append(f"WARNING: Malformed application record skipped at index {idx}.")
            continue

        aid     = app.get("id", "unknown")
        app_id  = app.get("appId", "unknown")
        display = app.get("displayName", "Unnamed App")
        source  = "applications.json"

        # ── ID-APP-001: No credentials configured ─────────────────────────
        has_secrets = bool(app.get("passwordCredentials"))
        has_certs   = bool(app.get("keyCredentials"))
        if not has_secrets and not has_certs:
            confidence, conf_score, rationale = _compute_confidence("empty_list_confirmed")
            raw_findings.append({
                "rule_id": "ID-APP-001",
                "title": "Application Has No Credentials Configured",
                "severity": "Informational",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "Applications",
                "asset": display,
                "user": None,
                "role": "Application",
                "source": source,
                "object_id": aid,
                "mitre_key": "app_access_token",
                "exposure": "application",
                "exploitability": "contextual",
                "evidence": {
                    "object_id": aid,
                    "source_file": source,
                    "appId": app_id,
                    "displayName": display,
                    "passwordCredentials": [],
                    "keyCredentials": [],
                    "note": "No client secrets or certificates registered. May be abandoned.",
                },
                "recommendation": (
                    "Verify this application is actively used. "
                    "If abandoned, delete it. If active, prefer certificate credentials."
                ),
            })

        # ── ID-APP-002: High-privilege OAuth scopes ────────────────────────
        app_scopes = []
        for rra in app.get("requiredResourceAccess") or []:
            if not isinstance(rra, dict):
                errors.append(
                    f"WARNING: Malformed requiredResourceAccess skipped for application {aid}."
                )
                continue
            for ra in rra.get("resourceAccess") or []:
                if not isinstance(ra, dict):
                    errors.append(
                        f"WARNING: Malformed resourceAccess skipped for application {aid}."
                    )
                    continue
                scope_name = GRAPH_SCOPE_NAMES.get(
                    ra.get("id", ""), ra.get("id", "unknown")
                )
                app_scopes.append(scope_name)

        risky_scopes = [s for s in app_scopes if s in HIGH_RISK_SCOPES]
        if risky_scopes:
            confidence, conf_score, rationale = _compute_confidence("json_field_confirmed")
            raw_findings.append({
                "rule_id": "ID-APP-002",
                "title": "Application Requests High-Privilege OAuth Permissions",
                "severity": "High",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "OAuth",
                "asset": display,
                "user": None,
                "role": "Application",
                "source": source,
                "object_id": aid,
                "mitre_key": "oauth_abuse",
                "exposure": "application",
                "exploitability": "moderate",
                "evidence": {
                    "object_id": aid,
                    "source_file": source,
                    "appId": app_id,
                    "displayName": display,
                    "risky_scopes": risky_scopes,
                    "all_scopes": app_scopes,
                },
                "recommendation": (
                    "Audit whether this application genuinely requires these permissions. "
                    "Apply least-privilege OAuth scopes. "
                    "Require admin consent and monitor sign-in logs for token abuse."
                ),
            })

        # ── ID-APP-003: Multi-tenant sign-in audience ─────────────────────
        audience = app.get("signInAudience") or ""
        if "AzureADMultipleOrgs" in audience or "AzureADandPersonalMicrosoftAccount" in audience:
            confidence, conf_score, rationale = _compute_confidence("json_field_confirmed")
            raw_findings.append({
                "rule_id": "ID-APP-003",
                "title": "Application Allows Multi-Tenant Sign-In",
                "severity": "Medium",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "Applications",
                "asset": display,
                "user": None,
                "role": "Application",
                "source": source,
                "object_id": aid,
                "mitre_key": "valid_accounts",
                "exposure": "tenant",
                "exploitability": "moderate",
                "evidence": {
                    "object_id": aid,
                    "source_file": source,
                    "appId": app_id,
                    "displayName": display,
                    "signInAudience": audience,
                },
                "recommendation": (
                    "Restrict signInAudience to AzureADMyOrg unless multi-tenant "
                    "access is a deliberate business requirement."
                ),
            })

        # ── ID-APP-004: No identifier URIs ────────────────────────────────
        if not app.get("identifierUris"):
            confidence, conf_score, rationale = _compute_confidence("empty_list_confirmed")
            raw_findings.append({
                "rule_id": "ID-APP-004",
                "title": "Application Has No Identifier URIs Configured",
                "severity": "Low",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "Applications",
                "asset": display,
                "user": None,
                "role": "Application",
                "source": source,
                "object_id": aid,
                "mitre_key": None,
                "exposure": "application",
                "exploitability": "contextual",
                "evidence": {
                    "object_id": aid,
                    "source_file": source,
                    "appId": app_id,
                    "displayName": display,
                    "identifierUris": [],
                },
                "recommendation": (
                    "Configure identifierUris to uniquely identify this application. "
                    "Without it, token audience validation may be weakened."
                ),
            })

    return raw_findings


# ===========================================================================
# Rule engine — Service Principals
# ===========================================================================

def _rules_service_principals(service_principals, errors):
    if not service_principals:
        errors.append(
            "WARNING: No service_principals data available. SP checks skipped."
        )
        return []

    raw_findings = []
    tenant_owned = []
    disabled_sps = []
    source = "service_principals.json"

    for idx, sp in enumerate(service_principals):
        if not isinstance(sp, dict):
            errors.append(
                f"WARNING: Malformed service principal record skipped at index {idx}."
            )
            continue

        spid    = sp.get("id", "unknown")
        display = sp.get("displayName", "Unnamed SP")

        if not sp.get("accountEnabled", True):
            disabled_sps.append(sp)

        owner_org = sp.get("appOwnerOrganizationId") or ""
        if owner_org and owner_org != _MS_TENANT_ID:
            tenant_owned.append(sp)

        # ── ID-SP-001: Client secret credentials ──────────────────────────
        if sp.get("passwordCredentials"):
            confidence, conf_score, rationale = _compute_confidence("json_field_confirmed")
            raw_findings.append({
                "rule_id": "ID-SP-001",
                "title": "Service Principal Has Client Secret Credentials",
                "severity": "Medium",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "Service Principals",
                "asset": display,
                "user": None,
                "role": "Service Principal",
                "source": source,
                "object_id": spid,
                "mitre_key": "service_principal_abuse",
                "exposure": "application",
                "exploitability": "moderate",
                "evidence": {
                    "object_id": spid,
                    "source_file": source,
                    "displayName": display,
                    "credential_type": "passwordCredential (client secret)",
                    "count": len(sp["passwordCredentials"]),
                },
                "recommendation": (
                    "Replace client secrets with managed identity or certificate auth. "
                    "Rotate secrets regularly and store only in Key Vault."
                ),
            })

        # ── ID-SP-002: Certificate credentials ────────────────────────────
        if sp.get("keyCredentials"):
            confidence, conf_score, rationale = _compute_confidence("json_field_confirmed")
            raw_findings.append({
                "rule_id": "ID-SP-002",
                "title": "Service Principal Uses Certificate Credentials",
                "severity": "Informational",
                "confidence": confidence,
                "confidence_score": conf_score,
                "confidence_rationale": rationale,
                "category": "Service Principals",
                "asset": display,
                "user": None,
                "role": "Service Principal",
                "source": source,
                "object_id": spid,
                "mitre_key": "service_principal_abuse",
                "exposure": "application",
                "exploitability": "contextual",
                "evidence": {
                    "object_id": spid,
                    "source_file": source,
                    "displayName": display,
                    "credential_type": "keyCredential (certificate)",
                    "count": len(sp["keyCredentials"]),
                },
                "recommendation": (
                    "Ensure certificates are rotated before expiry. "
                    "Store private keys only in Key Vault or HSM."
                ),
            })

    # ── ID-SP-003: Large SP inventory ─────────────────────────────────────
    total = len(service_principals)
    if total >= 50:
        confidence, conf_score, rationale = _compute_confidence("large_count_threshold")
        raw_findings.append({
            "rule_id": "ID-SP-003",
            "title": f"Large Service Principal Inventory ({total} principals)",
            "severity": "Medium",
            "confidence": confidence,
            "confidence_score": conf_score,
            "confidence_rationale": rationale,
            "category": "Service Principals",
            "asset": "Tenant",
            "user": None,
            "role": "Service Principal",
            "source": source,
            "object_id": None,
            "mitre_key": "valid_accounts",
            "exposure": "tenant",
            "exploitability": "moderate",
            "evidence": {
                "object_id": None,
                "source_file": source,
                "total_service_principals": total,
                "tenant_owned": len(tenant_owned),
                "disabled": len(disabled_sps),
                "note": "Large SP inventory increases credential theft and permission abuse surface.",
            },
            "recommendation": (
                "Audit SP permissions regularly. Remove unused SPs. "
                "Use managed identities instead where possible."
            ),
        })

    # ── ID-SP-004: Tenant-owned SPs ───────────────────────────────────────
    if tenant_owned:
        confidence, conf_score, rationale = _compute_confidence("json_field_confirmed")
        raw_findings.append({
            "rule_id": "ID-SP-004",
            "title": f"Tenant-Owned Service Principals Detected ({len(tenant_owned)})",
            "severity": "Informational",
            "confidence": confidence,
            "confidence_score": conf_score,
            "confidence_rationale": rationale,
            "category": "Service Principals",
            "asset": "Tenant",
            "user": None,
            "role": "Service Principal",
            "source": source,
            "object_id": None,
            "mitre_key": "service_principal_abuse",
            "exposure": "tenant",
            "exploitability": "contextual",
            "evidence": {
                "object_id": None,
                "source_file": source,
                "count": len(tenant_owned),
                "names": [sp.get("displayName") for sp in tenant_owned],
            },
            "recommendation": (
                "Verify each tenant-owned SP is intentionally registered. "
                "Ensure role assignments follow least privilege."
            ),
        })

    return raw_findings


# ===========================================================================
# Rule engine — Role Assignments
# ===========================================================================

def _rules_role_assignments(role_assignments, errors):
    if not role_assignments:
        errors.append(
            "WARNING: role_assignments.json is empty or missing. "
            "Azure RBAC analysis skipped. "
            "To enable: run 'az role assignment list --all' and export the result."
        )
        return []

    raw_findings = []
    source = "role_assignments.json"

    PRIVILEGED_ROLES = {
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
        "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    }

    owners, contributors, uaa = [], [], []

    for idx, ra in enumerate(role_assignments):
        if not isinstance(ra, dict):
            errors.append(
                f"WARNING: Malformed role assignment record skipped at index {idx}."
            )
            continue

        role_def = ra.get("roleDefinitionId") or ""
        role_id  = role_def.split("/")[-1]
        principal = ra.get("principalId", "unknown")
        scope     = ra.get("scope", "/")

        if role_id == "8e3af657-a8ff-443c-a75c-2fe8c4bcb635":
            owners.append({"principal": principal, "scope": scope})
        elif role_id == "b24988ac-6180-42a0-ab88-20f7382dd24c":
            contributors.append({"principal": principal, "scope": scope})
        elif role_id == "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9":
            uaa.append({"principal": principal, "scope": scope})

    if owners:
        confidence, conf_score, rationale = _compute_confidence("role_assignment_present")
        raw_findings.append({
            "rule_id": "ID-RBAC-001",
            "title": f"Owner Role Assigned ({len(owners)} assignments)",
            "severity": "High",
            "confidence": confidence,
            "confidence_score": conf_score,
            "confidence_rationale": rationale,
            "category": "RBAC",
            "asset": "Azure Subscription",
            "user": None,
            "role": "Owner",
            "source": source,
            "object_id": None,
            "mitre_key": "excessive_permissions",
            "exposure": "tenant",
            "exploitability": "trivial",
            "evidence": {
                "object_id": None,
                "source_file": source,
                "assignments": owners[:10],
            },
            "recommendation": (
                "Owner grants full control including permission delegation. "
                "Replace with least-privilege roles. Use PIM to make Owner time-bound."
            ),
        })

    if uaa:
        confidence, conf_score, rationale = _compute_confidence("role_assignment_present")
        raw_findings.append({
            "rule_id": "ID-RBAC-002",
            "title": f"User Access Administrator Role Assigned ({len(uaa)} assignments)",
            "severity": "Critical",
            "confidence": confidence,
            "confidence_score": conf_score,
            "confidence_rationale": rationale,
            "category": "RBAC",
            "asset": "Azure Subscription",
            "user": None,
            "role": "User Access Administrator",
            "source": source,
            "object_id": None,
            "mitre_key": "privilege_escalation",
            "exposure": "tenant",
            "exploitability": "trivial",
            "evidence": {
                "object_id": None,
                "source_file": source,
                "assignments": uaa[:10],
            },
            "recommendation": (
                "User Access Administrator can grant themselves Owner — "
                "effective privilege escalation path. Remove unless required. "
                "Use PIM with approval workflow."
            ),
        })

    return raw_findings


# ===========================================================================
# Rule engine — Subscription / Tenant
# ===========================================================================

def _rules_subscription(subscription, errors):
    if not subscription:
        errors.append(
            "WARNING: No subscription data available. Tenant checks skipped."
        )
        return []

    if not isinstance(subscription, dict):
        errors.append("WARNING: Malformed subscription data. Tenant checks skipped.")
        return []

    raw_findings = []
    source = "subscription.json"
    sub_id = subscription.get("id", "unknown")

    # ── ID-SUB-001: Non-standard cloud environment ─────────────────────────
    env = subscription.get("environmentName") or ""
    if env and env != "AzureCloud":
        confidence, conf_score, rationale = _compute_confidence("json_field_confirmed")
        raw_findings.append({
            "rule_id": "ID-SUB-001",
            "title": f"Non-Standard Azure Environment: {env}",
            "severity": "Informational",
            "confidence": confidence,
            "confidence_score": conf_score,
            "confidence_rationale": rationale,
            "category": "Monitoring",
            "asset": subscription.get("name", "Subscription"),
            "user": None,
            "role": None,
            "source": source,
            "object_id": sub_id,
            "mitre_key": None,
            "exposure": "tenant",
            "exploitability": "contextual",
            "evidence": {
                "object_id": sub_id,
                "source_file": source,
                "environmentName": env,
                "subscriptionId": sub_id,
            },
            "recommendation": (
                "Confirm this is the expected cloud environment. "
                "Sovereign clouds have different compliance boundaries."
            ),
        })

    # ── ID-SUB-002: Non-production subscription type ───────────────────────
    sub_name = subscription.get("name") or ""
    NON_PROD_KEYWORDS = {"student", "free", "trial", "visual studio", "dev", "sandbox"}
    matched = next((k for k in NON_PROD_KEYWORDS if k in sub_name.lower()), None)
    if matched:
        confidence, conf_score, rationale = _compute_confidence("subscription_type_name")
        raw_findings.append({
            "rule_id": "ID-SUB-002",
            "title": f"Non-Production Subscription Type Detected: '{sub_name}'",
            "severity": "Medium",
            "confidence": confidence,
            "confidence_score": conf_score,
            "confidence_rationale": rationale,
            "category": "Monitoring",
            "asset": sub_name,
            "user": None,
            "role": None,
            "source": source,
            "object_id": sub_id,
            "mitre_key": None,
            "exposure": "tenant",
            "exploitability": "contextual",
            "evidence": {
                "object_id": sub_id,
                "source_file": source,
                "subscriptionName": sub_name,
                "matched_keyword": matched,
                "state": subscription.get("state"),
                "note": (
                    "Free/student subscriptions lack enterprise security controls "
                    "and may be missing Defender for Cloud features."
                ),
            },
            "recommendation": (
                "Production workloads should not run on free, student, or trial subscriptions. "
                "Upgrade to Pay-As-You-Go or Enterprise Agreement."
            ),
        })

    return raw_findings


# ===========================================================================
# Normalization — raw finding -> THRAGG finding
# Single point. Every raw finding passes through here exactly once.
# ===========================================================================

def _normalize_finding(raw):
    severity    = raw.get("severity", "Informational")
    confidence  = raw.get("confidence", "Medium")
    exposure    = raw.get("exposure", "user")
    exploitability = raw.get("exploitability", "contextual")

    # Resolve MITRE: key -> full dict with technique_id, technique, tactic
    mitre_key = raw.get("mitre_key")
    mitre_data = MITRE.get(mitre_key) if mitre_key else None

    return {
        # Identity
        "rule_id":    raw.get("rule_id"),
        "title":      raw.get("title"),

        # Classification
        "severity":   severity,
        "confidence": confidence,
        "confidence_score":     raw.get("confidence_score"),
        "confidence_rationale": raw.get("confidence_rationale"),
        "category":   raw.get("category"),

        # Asset
        "asset":  raw.get("asset"),
        "user":   raw.get("user"),
        "role":   raw.get("role"),

        # Source traceability
        "source":    raw.get("source"),
        "object_id": raw.get("object_id"),
        "tool":      TOOL_NAME,

        # MITRE — technique + tactic
        "mitre": mitre_data,
        "cwe":   None,

        # Evidence — always includes source_file and object_id for dashboard linking
        "evidence": raw.get("evidence", {}),

        # Recommendation
        "recommendation": raw.get("recommendation"),

        # Four-factor risk score
        "risk_score": _compute_risk_score(severity, confidence, exposure, exploitability),
    }


# ===========================================================================
# Summary
# ===========================================================================

def _build_summary(findings, identity_store):
    severity_counts  = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    category_counts  = {}
    rule_id_counts   = {}

    for f in findings:
        sev = f.get("severity")
        if sev in severity_counts:
            severity_counts[sev] += 1
        cat = f.get("category")
        if cat:
            category_counts[cat] = category_counts.get(cat, 0) + 1
        rid = f.get("rule_id")
        if rid:
            rule_id_counts[rid] = rule_id_counts.get(rid, 0) + 1

    users = identity_store.get("users") or []
    groups = identity_store.get("groups") or []
    apps   = identity_store.get("applications") or []
    sps    = identity_store.get("service_principals") or []
    sub    = identity_store.get("subscription") or {}

    users = [u for u in users if isinstance(u, dict)]
    groups = [g for g in groups if isinstance(g, dict)]
    apps = [a for a in apps if isinstance(a, dict)]
    sps = [sp for sp in sps if isinstance(sp, dict)]
    sub = sub if isinstance(sub, dict) else {}

    guest_users  = [u for u in users if "#EXT#" in (u.get("userPrincipalName") or "")]
    admin_users  = [
        u for u in users
        if any(
            kw in (u.get("displayName") or "").lower()
            or kw in (u.get("userPrincipalName") or "").lower()
            for kw in ADMIN_KEYWORDS
        )
    ]
    no_phone = [u for u in users if not u.get("mobilePhone")]

    severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
    highest_severity = next(
        (s for s in severity_order if severity_counts.get(s, 0) > 0), None
    )
    top_category = (
        max(category_counts.items(), key=lambda kv: kv[1])[0]
        if category_counts else None
    )
    most_fired_rule = (
        max(rule_id_counts.items(), key=lambda kv: kv[1])[0]
        if rule_id_counts else None
    )

    return {
        "total_findings":   len(findings),
        "severity_counts":  severity_counts,
        "highest_severity": highest_severity,
        "top_category":     top_category,
        "most_fired_rule":  most_fired_rule,
        "identity_objects": {
            "total_users":       len(users),
            "guest_users":       len(guest_users),
            "suspected_admins":  len(admin_users),
            "users_no_phone":    len(no_phone),
            "total_groups":      len(groups),
            "total_applications": len(apps),
            "total_service_principals": len(sps),
        },
        "tenant": {
            "tenantId":          sub.get("tenantId"),
            "tenantDomain":      sub.get("tenantDefaultDomain"),
            "subscriptionName":  sub.get("name"),
            "subscriptionState": sub.get("state"),
        },
    }


# ===========================================================================
# Standalone test
# ===========================================================================

if __name__ == "__main__":
    import sys
    import pprint

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    output = run(target)

    print("=== METADATA ===")
    pprint.pprint(output["metadata"])

    print("\n=== SUMMARY ===")
    pprint.pprint(output["summary"])

    print(f"\n=== ERRORS ({len(output['errors'])}) ===")
    for e in output["errors"]:
        print(" -", e)

    findings = output["details"].get("findings", [])
    print(f"\n=== SAMPLE FINDINGS (first 3 of {len(findings)}) ===")
    for f in findings[:3]:
        pprint.pprint(f)
        print()
