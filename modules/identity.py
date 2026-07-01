"""
THRAGG Module: identity
Version: 1.2.0

Public API:
    run(input_path, profile="all")                    -> Mode 1  Evidence Ingestion
    run_cli(output_dir, profile="all")                -> Mode 2  Azure CLI collection → run()
    run_api(output_dir, profile="all",
            graph_version="v1.0",
            tenant_id=None, client_id=None,
            client_secret=None)                       -> Mode 3  Graph API collection → run()

Contract (frozen, matches THRAGG standard):
    {
        "metadata": {...},
        "summary": {...},
        "details": {...},
        "artifacts": {...},
        "errors": [...]
    }

Architecture:
    Mode 1 is the brain. Modes 2 and 3 only collect evidence and call run().
    One parser. One normalization pipeline. One rule engine. One summary builder.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from modules import base as base_module

# ─────────────────────────────────────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger("thragg.identity")

# ─────────────────────────────────────────────────────────────────────────────
# Module Constants
# ─────────────────────────────────────────────────────────────────────────────

MODULE_NAME    = "identity"
MODULE_VERSION = "1.2.0"
TOOL_NAME      = "Azure / Entra ID"
SUPPORTED_FORMATS = frozenset({".json"})

# ─────────────────────────────────────────────────────────────────────────────
# Timeout Constants
# ─────────────────────────────────────────────────────────────────────────────

AUTH_TIMEOUT = 30
CLI_TIMEOUT  = 120
REST_TIMEOUT = 60

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_CREDENTIAL_EXPIRY_DAYS = 30
DEFAULT_GRAPH_VERSION = "v1.0"
MIN_AZ_CLI_VERSION = "2.40.0"

# Maximum retries for Graph API throttling (HTTP 429)
GRAPH_MAX_RETRIES = 3
GRAPH_RETRY_BASE_SECONDS = 2

# ─────────────────────────────────────────────────────────────────────────────
# Collection Profiles
# ─────────────────────────────────────────────────────────────────────────────

COLLECTION_PROFILES: Dict[str, List[str]] = {
    "all": [
        "users", "groups", "applications",
        "service_principals", "role_assignments", "subscription",
    ],
    "users": ["users"],
    "groups": ["groups"],
    "applications": ["applications", "service_principals"],
    "privileged": ["role_assignments", "applications", "service_principals"],
    "authentication": ["users"],
}

# ─────────────────────────────────────────────────────────────────────────────
# Azure CLI Command Table
# ─────────────────────────────────────────────────────────────────────────────

CLI_COMMANDS: Dict[str, Tuple[List[str], str]] = {
    "users":              (["az", "ad", "user", "list", "--output", "json"],         "users.json"),
    "groups":             (["az", "ad", "group", "list", "--output", "json"],        "groups.json"),
    "applications":       (["az", "ad", "app", "list", "--output", "json"],          "applications.json"),
    "service_principals": (["az", "ad", "sp", "list", "--output", "json"],           "servicePrincipals.json"),
    "role_assignments":   (["az", "role", "assignment", "list", "--output", "json"], "roleAssignments.json"),
    "subscription":       (["az", "account", "show", "--output", "json"],            "subscription.json"),
}

# ─────────────────────────────────────────────────────────────────────────────
# Microsoft Graph API Endpoint Table
# Uses {graph_version} placeholder — resolved at call time.
# ─────────────────────────────────────────────────────────────────────────────

GRAPH_BASE_TEMPLATE = "https://graph.microsoft.com/{graph_version}"

GRAPH_ENDPOINTS: Dict[str, Tuple[str, str]] = {
    "users":              ("/users?$select=id,displayName,userPrincipalName,"
                           "accountEnabled,userType,createdDateTime,"
                           "signInActivity,assignedLicenses",
                           "users.json"),
    "groups":             ("/groups?$select=id,displayName,groupTypes,"
                           "securityEnabled,mailEnabled,members",
                           "groups.json"),
    "applications":       ("/applications?$select=id,appId,displayName,"
                           "signInAudience,requiredResourceAccess,"
                           "keyCredentials,passwordCredentials",
                           "applications.json"),
    "service_principals": ("/servicePrincipals?$select=id,appId,displayName,"
                           "servicePrincipalType,accountEnabled,"
                           "keyCredentials,passwordCredentials",
                           "servicePrincipals.json"),
    "role_assignments":   ("/roleManagement/directory/roleAssignments"
                           "?$expand=principal",
                           "roleAssignments.json"),
}

# ─────────────────────────────────────────────────────────────────────────────
# Filename → Resource Type Map
# ─────────────────────────────────────────────────────────────────────────────

FILENAME_RESOURCE_MAP: Dict[str, str] = {
    "users":             "users",
    "groups":            "groups",
    "applications":      "applications",
    "apps":              "applications",
    "serviceprincipals": "service_principals",
    "serviceprincipal":  "service_principals",
    "roleassignments":   "role_assignments",
    "roleassignment":    "role_assignments",
    "subscription":      "subscription",
}

# ─────────────────────────────────────────────────────────────────────────────
# Identity Constants
# ─────────────────────────────────────────────────────────────────────────────

_GUEST_MARKER = "#ext#"

_PRIVILEGED_ROLES = frozenset({
    "global administrator",
    "privileged role administrator",
    "security administrator",
    "exchange administrator",
    "sharepoint administrator",
    "user administrator",
    "authentication administrator",
    "cloud application administrator",
    "application administrator",
    "billing administrator",
    "hybrid identity administrator",
})

_SENSITIVE_PERMISSION_IDS = frozenset({
    "df021288-bdef-4463-88db-98f22de89214",  # User.ReadWrite.All
    "741f803b-c850-494e-b5df-cde7c675a1ca",  # User.ReadWrite.All (delegated)
    "62a82d76-70ea-41e2-9197-370581804d09",  # Group.ReadWrite.All
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7",  # Directory.ReadWrite.All
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe9",  # RoleManagement.ReadWrite.Directory
})


# ─────────────────────────────────────────────────────────────────────────────
# Module-Scope Dispatch Tables
# Avoids re-creating dicts on every function call.
# ─────────────────────────────────────────────────────────────────────────────

# Populated after function definitions (bottom of internal section)
PARSERS: Dict[str, Callable] = {}
ANALYZERS: Dict[str, Callable] = {}


# ═════════════════════════════════════════════════════════════════════════════
# MODE 1 — Evidence Ingestion & Analysis  (THE BRAIN)
# ═════════════════════════════════════════════════════════════════════════════

def run(
    input_path: str,
    profile: str = "all",
    credential_expiry_days: int = DEFAULT_CREDENTIAL_EXPIRY_DAYS,
) -> Dict:
    """
    Mode 1 — Accept a path to one identity JSON export or a folder.
    Parse, analyze, normalize, summarize, and return the THRAGG contract.
    """
    start_time = time.time()
    pipeline   = base_module.Pipeline()
    errors: List[str] = []

    metadata = base_module.build_metadata(
        MODULE_NAME, MODULE_VERSION, TOOL_NAME, input_path,
    )
    pipeline.add("init")
    logger.info("Mode 1 started — input_path=%s  profile=%s", input_path, profile)

    # ── Collect files ──────────────────────────────────────────────────────
    files = base_module.collect_files(input_path, SUPPORTED_FORMATS, errors)
    pipeline.add(f"collect_files: {len(files)} found")
    logger.debug("Collected %d file(s)", len(files))

    # ── Initialise identity store and detail buckets ───────────────────────
    identity_store: Dict[str, List[Dict]] = {
        "users":              [],
        "groups":             [],
        "applications":       [],
        "service_principals": [],
        "role_assignments":   [],
        "subscriptions":      [],
    }

    details = base_module.build_empty_details(
        "users", "groups", "applications",
        "service_principals", "rbac", "tenant", "unknown",
    )

    all_findings: List[Dict] = []
    files_processed = 0

    # ── Parse + analyse each file ──────────────────────────────────────────
    for filepath in files:
        data, load_err = base_module.load_json_file(filepath)
        if load_err:
            errors.append(load_err)
            logger.warning("Load error: %s", load_err)
            continue

        resource_type = _detect_resource_type(filepath, data)
        logger.debug("Detected resource type '%s' for %s", resource_type, filepath)

        parsed, parse_errs = _parse_resource(resource_type, data, filepath)
        errors.extend(parse_errs)

        store_key = resource_type if resource_type in identity_store else None
        if store_key:
            identity_store[store_key].extend(parsed)

        findings, analysis_errs = _analyze_resource(
            resource_type, parsed, filepath, credential_expiry_days,
        )
        errors.extend(analysis_errs)
        all_findings.extend(findings)

        _categorize_findings(findings, details)
        files_processed += 1

    pipeline.add(f"parse: {files_processed} files")
    pipeline.add(f"analyze: {len(all_findings)} findings")

    # ── Summary ────────────────────────────────────────────────────────────
    rule_stats = base_module.build_rule_statistics(all_findings)

    extra_summary = {
        "files_processed": files_processed,
        "profile":         profile,
        "identity_counts": {k: len(v) for k, v in identity_store.items()},
    }

    summary = base_module.build_summary(
        all_findings, rule_stats=rule_stats, extra_summary=extra_summary,
    )
    pipeline.add("summary")

    # ── Finalize metadata ──────────────────────────────────────────────────
    metadata["files_processed"]  = files_processed
    metadata["processing_stats"] = base_module.build_processing_stats(identity_store)
    metadata["module_health"]    = base_module.build_module_health(identity_store)
    metadata["rule_statistics"]  = rule_stats
    base_module.finalize_metadata(metadata, time.time() - start_time, pipeline)

    logger.info(
        "Mode 1 complete — %d findings in %.4fs",
        len(all_findings), metadata["execution_time"],
    )

    return {
        "metadata":  metadata,
        "summary":   summary,
        "details":   details,
        "artifacts": {"input_path": input_path, "files": files},
        "errors":    errors,
    }


# ═════════════════════════════════════════════════════════════════════════════
# MODE 2 — Azure CLI Collection
# ═════════════════════════════════════════════════════════════════════════════

def run_cli(
    output_dir: str = "thragg_results/identity_cli",
    profile: str = "all",
    credential_expiry_days: int = DEFAULT_CREDENTIAL_EXPIRY_DAYS,
) -> Dict:
    """
    Mode 2 — Validate Azure CLI, authenticate, collect identity exports,
    write JSON files to output_dir, then hand off to run().
    Mode 2 performs NO parsing, scoring, or analysis.
    """
    errors: List[str] = []
    collection_status: Dict[str, str] = {}

    logger.info("Mode 2 (CLI) started — output_dir=%s  profile=%s", output_dir, profile)

    # ── Validate CLI ───────────────────────────────────────────────────────
    cli_ok, cli_err = _validate_cli()
    if not cli_ok:
        return _early_failure(errors, cli_err, output_dir, profile)

    # ── Validate CLI version ───────────────────────────────────────────────
    ver_ok, ver_err = _validate_cli_version()
    if not ver_ok:
        logger.warning("CLI version check: %s", ver_err)
        errors.append(ver_err)
        # Non-fatal: continue with available CLI

    # ── Validate authentication ────────────────────────────────────────────
    auth_ok, auth_err = _validate_authentication_cli()
    if not auth_ok:
        return _early_failure(errors, auth_err, output_dir, profile)

    # ── Prepare output directory ───────────────────────────────────────────
    dir_ok, dir_err = _ensure_output_directory(output_dir)
    if not dir_ok:
        return _early_failure(errors, dir_err, output_dir, profile)

    # ── Collect resources ──────────────────────────────────────────────────
    resource_types = COLLECTION_PROFILES.get(profile, COLLECTION_PROFILES["all"])

    for resource_type in resource_types:
        cmd_spec = CLI_COMMANDS.get(resource_type)
        if not cmd_spec:
            errors.append(f"No CLI command for resource type: {resource_type}")
            collection_status[resource_type] = "SKIPPED"
            continue

        cmd, filename = cmd_spec
        output_path = os.path.join(output_dir, filename)

        logger.info("Collecting %s ...", resource_type)
        success, cmd_err = _execute_cli_command(cmd, output_path)

        if success:
            collection_status[resource_type] = "SUCCESS"
            logger.info("  %s — SUCCESS", resource_type)
        else:
            collection_status[resource_type] = "FAILED"
            errors.append(f"CLI collection failed [{resource_type}]: {cmd_err}")
            logger.warning("  %s — FAILED: %s", resource_type, cmd_err)

    # ── Hand off to Mode 1 ─────────────────────────────────────────────────
    result = run(output_dir, profile=profile, credential_expiry_days=credential_expiry_days)
    result["errors"] = errors + result["errors"]

    # Inject collection summary into artifacts
    result["artifacts"]["collection_status"] = collection_status

    logger.info("Mode 2 complete — collection_status=%s", collection_status)
    return result


# ═════════════════════════════════════════════════════════════════════════════
# MODE 3 — Microsoft Graph API Collection
# ═════════════════════════════════════════════════════════════════════════════

def run_api(
    output_dir: str = "thragg_results/identity_api",
    profile: str = "all",
    graph_version: str = DEFAULT_GRAPH_VERSION,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    credential_expiry_days: int = DEFAULT_CREDENTIAL_EXPIRY_DAYS,
) -> Dict:
    """
    Mode 3 — Acquire Graph token, call Microsoft Graph API, download
    JSON to output_dir, then hand off to run().
    Mode 3 performs NO parsing or analysis.

    Args:
        graph_version: "v1.0" or "beta"
    """
    errors: List[str] = []
    download_status: Dict[str, str] = {}

    logger.info(
        "Mode 3 (Graph API) started — output_dir=%s  profile=%s  version=%s",
        output_dir, profile, graph_version,
    )

    # ── Validate graph_version ─────────────────────────────────────────────
    if graph_version not in ("v1.0", "beta"):
        logger.warning("Invalid graph_version '%s', defaulting to v1.0", graph_version)
        graph_version = "v1.0"

    graph_base = GRAPH_BASE_TEMPLATE.format(graph_version=graph_version)

    # ── Acquire token ──────────────────────────────────────────────────────
    if client_id and client_secret and tenant_id:
        token, token_err = _acquire_graph_token_client_credentials(
            tenant_id, client_id, client_secret,
        )
    else:
        token, token_err = _acquire_graph_token_cli()

    if not token:
        return _early_failure(errors, token_err, output_dir, profile)

    # ── Prepare output directory ───────────────────────────────────────────
    dir_ok, dir_err = _ensure_output_directory(output_dir)
    if not dir_ok:
        return _early_failure(errors, dir_err, output_dir, profile)

    # ── Download resources ─────────────────────────────────────────────────
    resource_types = COLLECTION_PROFILES.get(profile, COLLECTION_PROFILES["all"])

    for resource_type in resource_types:
        endpoint_spec = GRAPH_ENDPOINTS.get(resource_type)
        if not endpoint_spec:
            # subscription is CLI-only; skip gracefully
            download_status[resource_type] = "SKIPPED"
            logger.debug("Skipping %s — no Graph endpoint", resource_type)
            continue

        url_path, filename = endpoint_spec
        full_url    = graph_base + url_path
        output_path = os.path.join(output_dir, filename)

        logger.info("Downloading %s ...", resource_type)
        success, dl_err = _download_graph_json(full_url, token, output_path)

        if success:
            download_status[resource_type] = "SUCCESS"
            logger.info("  %s — SUCCESS", resource_type)
        else:
            download_status[resource_type] = "FAILED"
            errors.append(f"Graph download failed [{resource_type}]: {dl_err}")
            logger.warning("  %s — FAILED: %s", resource_type, dl_err)

    # ── Hand off to Mode 1 ─────────────────────────────────────────────────
    result = run(output_dir, profile=profile, credential_expiry_days=credential_expiry_days)
    result["errors"] = errors + result["errors"]

    # Inject download summary into artifacts
    result["artifacts"]["download_status"] = download_status
    result["artifacts"]["graph_version"]   = graph_version

    logger.info("Mode 3 complete — download_status=%s", download_status)
    return result


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Resource Type Detection
# ═════════════════════════════════════════════════════════════════════════════

def _detect_resource_type(filepath: str, data: Any) -> str:
    """Detect identity resource type from filename then data content."""
    stem = os.path.splitext(os.path.basename(filepath))[0].lower().strip()

    for hint, rtype in FILENAME_RESOURCE_MAP.items():
        if hint in stem:
            return rtype

    sample = data[0] if isinstance(data, list) and data else data
    if not isinstance(sample, dict):
        return "unknown"

    keys = set(sample.keys())

    if "userPrincipalName" in keys or "mail" in keys:
        return "users"
    if "groupTypes" in keys or "securityEnabled" in keys:
        return "groups"
    if "appId" in keys and "requiredResourceAccess" in keys:
        return "applications"
    if "appId" in keys and "servicePrincipalType" in keys:
        return "service_principals"
    if "roleDefinitionId" in keys or "principalId" in keys:
        return "role_assignments"
    if "subscriptionId" in keys or "tenantId" in keys:
        return "subscription"

    return "unknown"


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Resource Parsers
# ═════════════════════════════════════════════════════════════════════════════

def _parse_resource(
    resource_type: str, data: Any, filepath: str,
) -> Tuple[List[Dict], List[str]]:
    """Dispatch to the correct parser. Returns (parsed_list, errors)."""
    parser = PARSERS.get(resource_type)
    if not parser:
        return [], [f"No parser for resource type '{resource_type}' in {filepath}"]
    try:
        items = parser(data)
        return items, []
    except Exception as exc:
        logger.exception("Parser error [%s] in %s", resource_type, filepath)
        return [], [f"Parser error [{resource_type}] in {filepath}: {exc}"]


def _normalize_list_or_single(data: Any) -> List[Dict]:
    """Ensure data is always a list of dicts. Handles Graph {value:[]} wrapper."""
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        if "value" in data and isinstance(data["value"], list):
            return [d for d in data["value"] if isinstance(d, dict)]
        return [data]
    return []


def _parse_users(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        upn = item.get("userPrincipalName", "")
        result.append({
            "id":                  item.get("id"),
            "display_name":        item.get("displayName"),
            "upn":                 upn,
            "user_type":           item.get("userType", "Member"),
            "account_enabled":     item.get("accountEnabled", True),
            "is_guest":            _GUEST_MARKER in upn.lower()
                                   or item.get("userType", "Member") == "Guest",
            "created_datetime":    item.get("createdDateTime"),
            "last_sign_in":        base_module.safe_get(
                                       item, "signInActivity", "lastSignInDateTime",
                                   ),
            "assigned_licenses":   base_module.ensure_list(
                                       item.get("assignedLicenses", []),
                                   ),
            "strong_auth_methods": base_module.safe_get(
                                       item, "strongAuthenticationMethods", default=[],
                                   ),
            "mfa_registered":      _is_mfa_registered(item),
            "on_premises_sync":    item.get("onPremisesSyncEnabled", False),
            "mail":                item.get("mail"),
            "department":          item.get("department"),
            "job_title":           item.get("jobTitle"),
            "raw":                 item,
        })
    return result


def _parse_groups(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        result.append({
            "id":               item.get("id"),
            "display_name":     item.get("displayName"),
            "group_types":      base_module.ensure_list(item.get("groupTypes", [])),
            "security_enabled": item.get("securityEnabled", False),
            "mail_enabled":     item.get("mailEnabled", False),
            "member_count":     len(base_module.ensure_list(item.get("members", []))),
            "members":          base_module.ensure_list(item.get("members", [])),
            "on_premises_sync": item.get("onPremisesSyncEnabled", False),
            "raw":              item,
        })
    return result


def _parse_applications(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        key_creds  = base_module.ensure_list(item.get("keyCredentials", []))
        pass_creds = base_module.ensure_list(item.get("passwordCredentials", []))
        all_creds  = key_creds + pass_creds
        result.append({
            "id":                       item.get("id"),
            "app_id":                   item.get("appId"),
            "display_name":             item.get("displayName"),
            "sign_in_audience":         item.get("signInAudience", "AzureADMyOrg"),
            "required_resource_access": base_module.ensure_list(
                                            item.get("requiredResourceAccess", []),
                                        ),
            "key_credentials":          key_creds,
            "password_credentials":     pass_creds,
            "has_credentials":          bool(all_creds),
            "expiring_credentials":     [],  # populated at analysis time
            "publisher_domain":         item.get("publisherDomain"),
            "raw":                      item,
        })
    return result


def _parse_service_principals(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        key_creds  = base_module.ensure_list(item.get("keyCredentials", []))
        pass_creds = base_module.ensure_list(item.get("passwordCredentials", []))
        all_creds  = key_creds + pass_creds
        result.append({
            "id":                   item.get("id"),
            "app_id":               item.get("appId"),
            "display_name":         item.get("displayName"),
            "sp_type":              item.get("servicePrincipalType", "Application"),
            "account_enabled":      item.get("accountEnabled", True),
            "key_credentials":      key_creds,
            "password_credentials": pass_creds,
            "has_credentials":      bool(all_creds),
            "expiring_credentials": [],  # populated at analysis time
            "app_roles":            base_module.ensure_list(item.get("appRoles", [])),
            "oauth2_permissions":   base_module.ensure_list(
                                        item.get("oauth2PermissionScopes", []),
                                    ),
            "raw":                  item,
        })
    return result


def _parse_role_assignments(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        principal = base_module.ensure_dict(item.get("principal", {}))
        result.append({
            "id":                   item.get("id"),
            "role_definition_id":   item.get("roleDefinitionId"),
            "role_definition_name": item.get("roleDefinitionName")
                                    or base_module.safe_get(
                                        item, "roleDefinition", "displayName",
                                    ),
            "principal_id":         item.get("principalId")
                                    or principal.get("id"),
            "principal_name":       item.get("principalName")
                                    or principal.get("displayName"),
            "principal_type":       item.get("principalType")
                                    or principal.get("@odata.type", "").replace(
                                        "#microsoft.graph.", "",
                                    ),
            "scope":                item.get("scope", "/"),
            "created_on":           item.get("createdOn"),
            "raw":                  item,
        })
    return result


def _parse_subscription(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        result.append({
            "id":           item.get("id") or item.get("subscriptionId"),
            "display_name": item.get("displayName") or item.get("name"),
            "state":        item.get("state"),
            "tenant_id":    item.get("tenantId"),
            "raw":          item,
        })
    return result


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Security Rule Engine
# ═════════════════════════════════════════════════════════════════════════════

def _analyze_resource(
    resource_type: str,
    resources: List[Dict],
    source: str,
    credential_expiry_days: int = DEFAULT_CREDENTIAL_EXPIRY_DAYS,
) -> Tuple[List[Dict], List[str]]:
    """Dispatch to the correct analyzer. Returns (findings, errors)."""
    analyzer = ANALYZERS.get(resource_type)
    if not analyzer:
        return [], []

    findings: List[Dict] = []
    errors: List[str]    = []

    for resource in resources:
        try:
            new_findings = analyzer(resource, source, credential_expiry_days)
            findings.extend(new_findings)
        except Exception as exc:
            logger.exception(
                "Analysis error [%s] '%s'",
                resource_type, resource.get("display_name", "?"),
            )
            errors.append(
                f"Analysis error [{resource_type}] "
                f"'{resource.get('display_name', '?')}': {exc}"
            )

    return findings, errors


def _make_finding(
    rule_id: str,
    title: str,
    severity: str,
    confidence_signal: str,
    category: str,
    mitre_key: str,
    asset: str,
    evidence: Dict,
    recommendation: str,
    source: str,
    exposure_key: str = "user",
    exploitability_key: str = "moderate",
    signals: Optional[Dict[str, bool]] = None,
) -> Dict:
    """Central finding factory — called by every analyzer."""
    conf_label, conf_score, conf_rationale = base_module.compute_confidence(
        confidence_signal, signals or {},
    )
    raw = {
        "rule_id":              rule_id,
        "title":                title,
        "severity":             severity,
        "confidence":           conf_label,
        "confidence_score":     conf_score,
        "confidence_rationale": conf_rationale,
        "category":             category,
        "mitre_key":            mitre_key,
        "asset":                asset,
        "source":               source,
        "evidence":             evidence,
        "recommendation":       recommendation,
    }
    finding = base_module.normalize_finding(raw, TOOL_NAME)
    finding["risk_score"] = base_module.compute_risk_score(
        severity, conf_label, exposure_key, exploitability_key,
    )
    return finding


# ── User Rules ────────────────────────────────────────────────────────────────

def _analyze_users(
    user: Dict, source: str, credential_expiry_days: int,
) -> List[Dict]:
    findings = []
    name = user.get("display_name") or user.get("upn", "unknown")

    # IDN-USR-001: Guest account
    if user.get("is_guest"):
        findings.append(_make_finding(
            rule_id="IDN-USR-001",
            title="Guest / External User Account Detected",
            severity="Medium",
            confidence_signal="ext_marker",
            category="Guest Accounts",
            mitre_key="guest_abuse",
            asset=name,
            evidence={"upn": user.get("upn"), "user_type": user.get("user_type")},
            recommendation=(
                "Review guest account necessity. Apply Conditional Access policies "
                "and restrict guest permissions via External Collaboration Settings."
            ),
            source=source,
            exposure_key="user",
            exploitability_key="moderate",
        ))

    # IDN-USR-002: Disabled account retains license
    if not user.get("account_enabled") and user.get("assigned_licenses"):
        findings.append(_make_finding(
            rule_id="IDN-USR-002",
            title="Disabled Account Retains Active License Assignment",
            severity="Low",
            confidence_signal="field_present",
            category="Identity Hygiene",
            mitre_key="valid_accounts",
            asset=name,
            evidence={
                "account_enabled": False,
                "license_count": len(user.get("assigned_licenses", [])),
            },
            recommendation=(
                "Revoke licenses from disabled accounts to reduce cost and attack surface."
            ),
            source=source,
            exposure_key="user",
            exploitability_key="contextual",
        ))

    # IDN-USR-003: No MFA registered
    if not user.get("mfa_registered") and user.get("account_enabled"):
        findings.append(_make_finding(
            rule_id="IDN-USR-003",
            title="User Has No MFA Method Registered",
            severity="High",
            confidence_signal="field_null",
            category="MFA",
            mitre_key="modify_auth",
            asset=name,
            evidence={"mfa_registered": False, "upn": user.get("upn")},
            recommendation=(
                "Enforce MFA registration via Conditional Access or Authentication "
                "Strength policies. Require phishing-resistant methods where possible."
            ),
            source=source,
            exposure_key="user",
            exploitability_key="moderate",
            signals={"no_role_data": True},
        ))

    # IDN-USR-004: Stale account
    if user.get("account_enabled") and not user.get("last_sign_in"):
        findings.append(_make_finding(
            rule_id="IDN-USR-004",
            title="Active Account With No Recorded Sign-In Activity",
            severity="Low",
            confidence_signal="field_null",
            category="Identity Hygiene",
            mitre_key="valid_accounts",
            asset=name,
            evidence={"last_sign_in": None, "upn": user.get("upn")},
            recommendation=(
                "Investigate accounts with no sign-in history. "
                "Disable or remove accounts that are no longer needed."
            ),
            source=source,
            exposure_key="user",
            exploitability_key="contextual",
        ))

    return findings


# ── Group Rules ───────────────────────────────────────────────────────────────

def _analyze_groups(
    group: Dict, source: str, credential_expiry_days: int,
) -> List[Dict]:
    findings = []
    name = group.get("display_name", "unknown")

    # IDN-GRP-001: On-prem synced security group
    if group.get("on_premises_sync") and group.get("security_enabled"):
        findings.append(_make_finding(
            rule_id="IDN-GRP-001",
            title="On-Premises Synced Security Group",
            severity="Low",
            confidence_signal="field_present",
            category="Identity Hygiene",
            mitre_key="valid_accounts",
            asset=name,
            evidence={
                "on_premises_sync": True,
                "security_enabled": True,
            },
            recommendation=(
                "Ensure on-premises group membership is managed and reviewed. "
                "Consider migrating to cloud-native groups for cloud resources."
            ),
            source=source,
            exposure_key="group",
            exploitability_key="contextual",
        ))

    # IDN-GRP-002: Empty security group
    if group.get("security_enabled") and group.get("member_count", 0) == 0:
        findings.append(_make_finding(
            rule_id="IDN-GRP-002",
            title="Empty Security Group Detected",
            severity="Low",
            confidence_signal="list_empty",
            category="Identity Hygiene",
            mitre_key="valid_accounts",
            asset=name,
            evidence={"member_count": 0},
            recommendation=(
                "Remove empty security groups or populate them intentionally."
            ),
            source=source,
            exposure_key="group",
            exploitability_key="contextual",
        ))

    return findings


# ── Application Rules ─────────────────────────────────────────────────────────

def _analyze_applications(
    app: Dict, source: str, credential_expiry_days: int,
) -> List[Dict]:
    findings = []
    name = app.get("display_name", "unknown")

    # IDN-APP-001: Multi-tenant application
    audience = app.get("sign_in_audience", "")
    if audience in ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"):
        findings.append(_make_finding(
            rule_id="IDN-APP-001",
            title="Application Registered as Multi-Tenant",
            severity="Medium",
            confidence_signal="field_present",
            category="Applications",
            mitre_key="oauth_abuse",
            asset=name,
            evidence={"signInAudience": audience, "app_id": app.get("app_id")},
            recommendation=(
                "Restrict to AzureADMyOrg unless multi-tenant is a documented "
                "business requirement. Review consent grant policies."
            ),
            source=source,
            exposure_key="application",
            exploitability_key="moderate",
        ))

    # IDN-APP-002: Expiring credentials
    all_creds = (
        base_module.ensure_list(app.get("key_credentials", []))
        + base_module.ensure_list(app.get("password_credentials", []))
    )
    expiring = _find_expiring_credentials(all_creds, credential_expiry_days)
    if expiring:
        findings.append(_make_finding(
            rule_id="IDN-APP-002",
            title="Application Has Expiring Credentials",
            severity="Medium",
            confidence_signal="field_present",
            category="Applications",
            mitre_key="app_access_token",
            asset=name,
            evidence={"expiring_credentials": expiring, "count": len(expiring)},
            recommendation=(
                "Rotate expiring credentials before expiry. "
                "Consider managed identities to eliminate credential management."
            ),
            source=source,
            exposure_key="application",
            exploitability_key="contextual",
        ))

    # IDN-APP-003: Broad permission scope
    permissions = app.get("required_resource_access", [])
    if _has_broad_permissions(permissions):
        findings.append(_make_finding(
            rule_id="IDN-APP-003",
            title="Application Requests Broad API Permissions",
            severity="High",
            confidence_signal="pattern_match",
            category="Applications",
            mitre_key="oauth_abuse",
            asset=name,
            evidence={"required_resource_access_count": len(permissions)},
            recommendation=(
                "Audit API permissions. Apply least-privilege by removing unused scopes. "
                "Prefer delegated permissions over application permissions."
            ),
            source=source,
            exposure_key="application",
            exploitability_key="moderate",
        ))

    return findings


# ── Service Principal Rules ───────────────────────────────────────────────────

def _analyze_service_principals(
    sp: Dict, source: str, credential_expiry_days: int,
) -> List[Dict]:
    findings = []
    name = sp.get("display_name", "unknown")

    # IDN-SP-001: Disabled with credentials
    if not sp.get("account_enabled") and sp.get("has_credentials"):
        findings.append(_make_finding(
            rule_id="IDN-SP-001",
            title="Disabled Service Principal Retains Active Credentials",
            severity="Medium",
            confidence_signal="field_present",
            category="Service Principals",
            mitre_key="service_principal_abuse",
            asset=name,
            evidence={"account_enabled": False, "has_credentials": True},
            recommendation=(
                "Remove credentials from disabled service principals immediately."
            ),
            source=source,
            exposure_key="application",
            exploitability_key="moderate",
        ))

    # IDN-SP-002: Expiring credentials
    all_creds = (
        base_module.ensure_list(sp.get("key_credentials", []))
        + base_module.ensure_list(sp.get("password_credentials", []))
    )
    expiring = _find_expiring_credentials(all_creds, credential_expiry_days)
    if expiring:
        findings.append(_make_finding(
            rule_id="IDN-SP-002",
            title="Service Principal Has Expiring Credentials",
            severity="Medium",
            confidence_signal="field_present",
            category="Service Principals",
            mitre_key="service_principal_abuse",
            asset=name,
            evidence={"expiring_credentials": expiring, "count": len(expiring)},
            recommendation=(
                "Rotate expiring credentials before expiry. "
                "Use managed identities where possible."
            ),
            source=source,
            exposure_key="application",
            exploitability_key="contextual",
        ))

    # IDN-SP-003: Excessive app roles
    app_role_count = len(base_module.ensure_list(sp.get("app_roles", [])))
    if app_role_count > 10:
        findings.append(_make_finding(
            rule_id="IDN-SP-003",
            title="Service Principal Exposes Excessive App Roles",
            severity="Low",
            confidence_signal="threshold_exceeded",
            category="Service Principals",
            mitre_key="excessive_permissions",
            asset=name,
            evidence={"app_role_count": app_role_count},
            recommendation=(
                "Review and remove unused app role definitions."
            ),
            source=source,
            exposure_key="application",
            exploitability_key="contextual",
        ))

    return findings


# ── Role Assignment Rules ─────────────────────────────────────────────────────

def _analyze_role_assignments(
    assignment: Dict, source: str, credential_expiry_days: int,
) -> List[Dict]:
    findings = []
    role_name = (assignment.get("role_definition_name") or "unknown").lower()
    principal = assignment.get("principal_name", "unknown")
    scope     = assignment.get("scope", "/")

    # IDN-RBAC-001: Privileged role
    if role_name in _PRIVILEGED_ROLES:
        findings.append(_make_finding(
            rule_id="IDN-RBAC-001",
            title=f"Privileged Role Assignment: {role_name.title()}",
            severity="High",
            confidence_signal="name_match",
            category="RBAC",
            mitre_key="privilege_escalation",
            asset=principal,
            evidence={
                "role_definition_name": role_name,
                "principal_name":       principal,
                "principal_type":       assignment.get("principal_type"),
                "scope":                scope,
            },
            recommendation=(
                "Apply PIM for just-in-time access. "
                "Remove standing privileged access where possible."
            ),
            source=source,
            exposure_key="tenant",
            exploitability_key="moderate",
        ))

    # IDN-RBAC-002: Subscription-scope Owner
    is_owner = "owner" in role_name
    is_sub_scope = scope == "/" or scope.startswith("/subscriptions/")
    if is_owner and is_sub_scope:
        findings.append(_make_finding(
            rule_id="IDN-RBAC-002",
            title="Subscription-Level Owner Role Assigned",
            severity="Critical",
            confidence_signal="assignment_present",
            category="RBAC",
            mitre_key="privilege_escalation",
            asset=principal,
            evidence={
                "role_definition_name": role_name,
                "principal_name":       principal,
                "scope":                scope,
            },
            recommendation=(
                "Use Contributor or custom roles scoped to resource groups. "
                "Require PIM approval for Owner activation."
            ),
            source=source,
            exposure_key="tenant",
            exploitability_key="trivial",
        ))

    return findings


# ── Subscription Rules ────────────────────────────────────────────────────────

def _analyze_subscription(
    sub: Dict, source: str, credential_expiry_days: int,
) -> List[Dict]:
    findings = []
    name  = sub.get("display_name") or sub.get("id", "unknown")
    state = (sub.get("state") or "").lower()

    if state and state != "enabled":
        findings.append(_make_finding(
            rule_id="IDN-SUB-001",
            title="Subscription Not in Enabled State",
            severity="Medium",
            confidence_signal="field_present",
            category="Identity Hygiene",
            mitre_key="valid_accounts",
            asset=name,
            evidence={"state": state},
            recommendation=(
                "Investigate why the subscription is not enabled. "
                "Ensure active resources are migrated before decommissioning."
            ),
            source=source,
            exposure_key="tenant",
            exploitability_key="contextual",
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Finding Categorization
# ═════════════════════════════════════════════════════════════════════════════

_CATEGORY_BUCKET_MAP: Dict[str, str] = {
    "Guest Accounts":     "users",
    "MFA":                "users",
    "Identity Hygiene":   "users",
    "Account Discovery":  "users",
    "RBAC":               "rbac",
    "Applications":       "applications",
    "OAuth":              "applications",
    "Service Principals": "service_principals",
    "Monitoring":         "tenant",
    "Governance":         "tenant",
    "Privilege":          "rbac",
}


def _categorize_findings(findings: List[Dict], details: Dict) -> None:
    """
    Distribute findings into detail buckets.
    identity.py owns this logic — base.py has no category knowledge.
    """
    for finding in findings:
        category = finding.get("category", "")
        role     = (finding.get("role") or "").lower()
        bucket   = _CATEGORY_BUCKET_MAP.get(category)

        if not bucket:
            if "group" in role:
                bucket = "groups"
            elif "service principal" in role:
                bucket = "service_principals"
            elif "application" in role:
                bucket = "applications"
            else:
                bucket = "unknown"

        if bucket in details:
            details[bucket].append(finding)
        else:
            details["unknown"].append(finding)


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — CLI Helpers (Mode 2)
# ═════════════════════════════════════════════════════════════════════════════

def _validate_cli() -> Tuple[bool, Optional[str]]:
    """Check that az CLI is installed."""
    if shutil.which("az") is None:
        logger.error("Azure CLI not found in PATH")
        return False, "Azure CLI (az) is not installed or not found in PATH."
    return True, None


def _validate_cli_version() -> Tuple[bool, Optional[str]]:
    """
    Validate Azure CLI version meets minimum requirement.
    Returns (ok, warning_message). Non-fatal.
    """
    try:
        result = subprocess.run(
            ["az", "version", "--output", "json"],
            capture_output=True, text=True, timeout=AUTH_TIMEOUT,
        )
        if result.returncode != 0:
            return False, "Could not determine Azure CLI version."

        version_data = json.loads(result.stdout)
        cli_version = version_data.get("azure-cli", "0.0.0")

        if _compare_versions(cli_version, MIN_AZ_CLI_VERSION) < 0:
            return False, (
                f"Azure CLI version {cli_version} is below minimum "
                f"{MIN_AZ_CLI_VERSION}. Some commands may not work as expected."
            )
        logger.debug("Azure CLI version %s (minimum: %s)", cli_version, MIN_AZ_CLI_VERSION)
        return True, None
    except subprocess.TimeoutExpired:
        return False, "Azure CLI version check timed out."
    except Exception as exc:
        return False, f"Error checking CLI version: {exc}"


def _compare_versions(v1: str, v2: str) -> int:
    """
    Compare two semver-like version strings.
    Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
    """
    def parts(v: str) -> List[int]:
        return [int(x) for x in re.sub(r"[^0-9.]", "", v).split(".") if x]

    p1, p2 = parts(v1), parts(v2)
    for a, b in zip(p1, p2):
        if a < b:
            return -1
        if a > b:
            return 1
    if len(p1) < len(p2):
        return -1
    if len(p1) > len(p2):
        return 1
    return 0


def _validate_authentication_cli() -> Tuple[bool, Optional[str]]:
    """Run az account show to confirm an active login session."""
    try:
        result = subprocess.run(
            ["az", "account", "show"],
            capture_output=True, text=True, timeout=AUTH_TIMEOUT,
        )
        if result.returncode != 0:
            logger.error("CLI not authenticated: %s", result.stderr.strip())
            return (
                False,
                f"Azure CLI not authenticated. Run 'az login'. "
                f"Detail: {result.stderr.strip()}",
            )
        return True, None
    except subprocess.TimeoutExpired:
        return False, "Azure CLI authentication check timed out."
    except Exception as exc:
        return False, f"Unexpected error checking Azure CLI authentication: {exc}"


def _execute_cli_command(
    cmd: List[str], output_path: str,
) -> Tuple[bool, Optional[str]]:
    """Run az CLI command and write stdout to output_path."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CLI_TIMEOUT,
        )
        if result.returncode != 0:
            return False, result.stderr.strip()
        if not result.stdout.strip():
            return False, "Command returned empty output."
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(result.stdout)
        return True, None
    except subprocess.TimeoutExpired:
        return False, f"Command timed out: {' '.join(cmd)}"
    except Exception as exc:
        return False, f"Error executing CLI command: {exc}"


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Graph API Helpers (Mode 3)
# ═════════════════════════════════════════════════════════════════════════════

def _acquire_graph_token_cli() -> Tuple[Optional[str], Optional[str]]:
    """Acquire Graph token via az CLI. Reuses existing authentication."""
    if shutil.which("az") is None:
        return None, "Azure CLI (az) not installed. Required for token acquisition."
    try:
        result = subprocess.run(
            [
                "az", "account", "get-access-token",
                "--resource", "https://graph.microsoft.com",
                "--output", "json",
            ],
            capture_output=True, text=True, timeout=AUTH_TIMEOUT,
        )
        if result.returncode != 0:
            return None, (
                f"Token acquisition failed. Run 'az login'. "
                f"Detail: {result.stderr.strip()}"
            )
        token_data = json.loads(result.stdout)
        token = token_data.get("accessToken")
        if not token:
            return None, "Access token missing from az CLI response."
        return token, None
    except subprocess.TimeoutExpired:
        return None, "Token acquisition timed out."
    except json.JSONDecodeError:
        return None, "Failed to parse token response from az CLI."
    except Exception as exc:
        return None, f"Unexpected error acquiring token: {exc}"


def _acquire_graph_token_client_credentials(
    tenant_id: str, client_id: str, client_secret: str,
) -> Tuple[Optional[str], Optional[str]]:
    """Acquire Graph token via OAuth2 client-credentials flow."""
    token_url = (
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    )
    body = (
        f"grant_type=client_credentials"
        f"&client_id={urllib.request.quote(client_id)}"
        f"&client_secret={urllib.request.quote(client_secret)}"
        f"&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default"
    ).encode("utf-8")

    try:
        req = urllib.request.Request(
            token_url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=AUTH_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        token = data.get("access_token")
        if not token:
            return None, f"No access_token: {data.get('error_description')}"
        return token, None
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code} acquiring token: {exc.reason}"
    except urllib.error.URLError as exc:
        return None, f"Network error acquiring token: {exc.reason}"
    except Exception as exc:
        return None, f"Unexpected error acquiring token: {exc}"


def _execute_graph_request(
    url: str, token: str,
) -> Tuple[Optional[Any], Optional[str]]:
    """
    GET a Microsoft Graph URL with pagination and HTTP 429 retry.
    Returns aggregated value list or single object.
    """
    all_values: List[Any] = []
    next_url: Optional[str] = url

    while next_url:
        data, err = _execute_single_graph_request(next_url, token)
        if err:
            return None, err

        if "value" in data:
            all_values.extend(data["value"])
        else:
            return data, None

        next_url = data.get("@odata.nextLink")

    return all_values, None


def _execute_single_graph_request(
    url: str, token: str,
) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Execute a single Graph GET request with exponential backoff on HTTP 429.
    """
    for attempt in range(GRAPH_MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization":    f"Bearer {token}",
                    "Content-Type":     "application/json",
                    "ConsistencyLevel": "eventual",
                },
            )
            with urllib.request.urlopen(req, timeout=REST_TIMEOUT) as resp:
                raw = resp.read().decode("utf-8")
            return json.loads(raw), None

        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < GRAPH_MAX_RETRIES:
                # Respect Retry-After header if present
                retry_after = exc.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = int(retry_after)
                    except ValueError:
                        wait = GRAPH_RETRY_BASE_SECONDS * (2 ** attempt)
                else:
                    wait = GRAPH_RETRY_BASE_SECONDS * (2 ** attempt)

                logger.warning(
                    "Graph API throttled (429). Retry %d/%d in %ds — %s",
                    attempt + 1, GRAPH_MAX_RETRIES, wait, url,
                )
                time.sleep(wait)
                continue

            return None, f"HTTP {exc.code} from Graph API: {exc.reason}"

        except urllib.error.URLError as exc:
            return None, f"Network error calling Graph API: {exc.reason}"
        except json.JSONDecodeError as exc:
            return None, f"Failed to parse Graph API response: {exc}"
        except Exception as exc:
            return None, f"Unexpected error calling Graph API: {exc}"

    return None, f"Graph API request failed after {GRAPH_MAX_RETRIES} retries: {url}"


def _download_graph_json(
    url: str, token: str, output_path: str,
) -> Tuple[bool, Optional[str]]:
    """Execute a Graph request and write the result JSON to output_path."""
    data, err = _execute_graph_request(url, token)
    if err:
        return False, err
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        return True, None
    except Exception as exc:
        return False, f"Failed to write JSON to {output_path}: {exc}"


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Shared Utilities
# ═════════════════════════════════════════════════════════════════════════════

def _ensure_output_directory(directory: str) -> Tuple[bool, Optional[str]]:
    """Create directory if it does not exist."""
    try:
        os.makedirs(directory, exist_ok=True)
        return True, None
    except Exception as exc:
        return False, f"Could not create output directory '{directory}': {exc}"


def _early_failure(
    errors: List[str], new_error: str, input_path: str, profile: str,
) -> Dict:
    """Return a failed THRAGG contract when collection cannot begin."""
    errors.append(new_error)
    metadata = base_module.build_metadata(
        MODULE_NAME, MODULE_VERSION, TOOL_NAME, input_path,
    )
    metadata["status"] = "failed"
    return {
        "metadata":  metadata,
        "summary":   {"total_findings": 0},
        "details":   {},
        "artifacts": {"input_path": input_path},
        "errors":    errors,
    }


def _is_mfa_registered(user: Dict) -> bool:
    """Best-effort MFA detection from available export fields."""
    methods = base_module.ensure_list(
        user.get("strongAuthenticationMethods", [])
        or base_module.safe_get(user, "authentication", "methods", default=[])
    )
    return bool(methods)


def _find_expiring_credentials(
    credentials: List[Dict],
    expiry_days: int = DEFAULT_CREDENTIAL_EXPIRY_DAYS,
) -> List[Dict]:
    """
    Return credentials expiring within expiry_days or already expired.
    Works with keyCredentials and passwordCredentials.
    """
    import datetime

    now     = datetime.datetime.now(datetime.timezone.utc)
    horizon = now + datetime.timedelta(days=expiry_days)
    expiring: List[Dict] = []

    for cred in credentials:
        if not isinstance(cred, dict):
            continue
        end_str = cred.get("endDateTime") or cred.get("endDate")
        if not end_str:
            continue
        try:
            clean = end_str.rstrip("Z")
            if "+" not in clean and clean.count("-") < 3:
                clean += "+00:00"
            end_dt = datetime.datetime.fromisoformat(clean)
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=datetime.timezone.utc)
            if end_dt <= horizon:
                expiring.append({
                    "key_id":       cred.get("keyId") or cred.get("customKeyIdentifier"),
                    "display_name": cred.get("displayName"),
                    "end_datetime": end_str,
                    "expired":      end_dt < now,
                })
        except (ValueError, TypeError):
            continue

    return expiring


def _has_broad_permissions(required_resource_access: List[Dict]) -> bool:
    """Heuristic: flag apps with >5 resource entries or sensitive scopes."""
    if len(required_resource_access) > 5:
        return True

    for entry in required_resource_access:
        for scope in base_module.ensure_list(entry.get("resourceAccess", [])):
            if isinstance(scope, dict) and scope.get("id") in _SENSITIVE_PERMISSION_IDS:
                return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Register Module-Scope Dispatch Tables
# Must be done after function definitions.
# ─────────────────────────────────────────────────────────────────────────────

PARSERS.update({
    "users":              _parse_users,
    "groups":             _parse_groups,
    "applications":       _parse_applications,
    "service_principals": _parse_service_principals,
    "role_assignments":   _parse_role_assignments,
    "subscription":       _parse_subscription,
})

ANALYZERS.update({
    "users":              _analyze_users,
    "groups":             _analyze_groups,
    "applications":       _analyze_applications,
    "service_principals": _analyze_service_principals,
    "role_assignments":   _analyze_role_assignments,
    "subscription":       _analyze_subscription,
})


# ═════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(name)s: %(message)s",
    )

    _USAGE = (
        "Usage:\n"
        "  python identity.py run  <input_path> [profile]\n"
        "  python identity.py cli  <output_dir> [profile]\n"
        "  python identity.py api  <output_dir> [profile] "
        "[graph_version] [tenant_id] [client_id] [client_secret]\n"
    )

    if len(sys.argv) < 3:
        print(_USAGE)
        sys.exit(1)

    mode     = sys.argv[1].lower()
    arg2     = sys.argv[2]
    prof_arg = sys.argv[3] if len(sys.argv) > 3 else "all"

    if mode == "run":
        _result = run(arg2, profile=prof_arg)
    elif mode == "cli":
        _result = run_cli(output_dir=arg2, profile=prof_arg)
    elif mode == "api":
        _gv  = sys.argv[4] if len(sys.argv) > 4 else "v1.0"
        _tid = sys.argv[5] if len(sys.argv) > 5 else None
        _cid = sys.argv[6] if len(sys.argv) > 6 else None
        _cs  = sys.argv[7] if len(sys.argv) > 7 else None
        _result = run_api(
            output_dir=arg2,
            profile=prof_arg,
            graph_version=_gv,
            tenant_id=_tid,
            client_id=_cid,
            client_secret=_cs,
        )
    else:
        print(f"Unknown mode: {mode}\n{_USAGE}")
        sys.exit(1)

    print(json.dumps(_result, indent=2, default=str))
