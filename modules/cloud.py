"""
THRAGG Module: cloud
Version: 1.1.0

Public API:
    run(input_path, profile="all")       -> Mode 1  Evidence Ingestion (JSON export files)
    run_cli(output_dir, profile="all")   -> Mode 2  Azure CLI collection → run()
    run_api(output_dir, profile="all",
            subscription_id=None)        -> Mode 3  Azure REST API collection → run()

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
    One parser. One normalization pipeline. One summary builder.
"""

from __future__ import annotations

import os
import json
import time
import shutil
import subprocess
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Any, Tuple

from modules import base as base_module

MODULE_NAME = "cloud"
MODULE_VERSION = "1.1.0"
TOOL_NAME = "Azure Cloud Security"
OUTPUT_DIR = "thragg_results"
SUPPORTED_FORMATS = {".json"}

# ─────────────────────────────────────────────────────────────────────────────
# Timeout Constants
# ─────────────────────────────────────────────────────────────────────────────

AUTH_TIMEOUT = 30
CLI_TIMEOUT = 120
REST_TIMEOUT = 60

# ─────────────────────────────────────────────────────────────────────────────
# Collection Profiles
# Controls which resource types are collected in Modes 2 and 3.
# Does NOT change parser behavior.
# ─────────────────────────────────────────────────────────────────────────────

COLLECTION_PROFILES: Dict[str, List[str]] = {
    "all": [
        "subscription", "vm", "storage", "keyvault", "nsg", "vnet", "public_ip"
    ],
    "network": ["nsg", "vnet", "public_ip"],
    "compute": ["vm"],
    "storage": ["storage", "keyvault"],
    "identity": ["subscription"],
}

# ─────────────────────────────────────────────────────────────────────────────
# Azure CLI command table
# ─────────────────────────────────────────────────────────────────────────────

CLI_COMMANDS: Dict[str, Tuple[List[str], str]] = {
    "subscription": (["az", "account", "show"], "subscription.json"),
    "vm":           (["az", "vm", "list", "--output", "json"], "vm.json"),
    "storage":      (["az", "storage", "account", "list", "--output", "json"], "storage.json"),
    "keyvault":     (["az", "keyvault", "list", "--output", "json"], "keyvault.json"),
    "nsg":          (["az", "network", "nsg", "list", "--output", "json"], "nsg.json"),
    "vnet":         (["az", "network", "vnet", "list", "--output", "json"], "vnet.json"),
    "public_ip":    (["az", "network", "public-ip", "list", "--output", "json"], "publicip.json"),
}

# ─────────────────────────────────────────────────────────────────────────────
# Azure REST API resource table
# ─────────────────────────────────────────────────────────────────────────────

REST_RESOURCES: Dict[str, Tuple[str, str, str]] = {
    # resource_type -> (api_version, url_path_template, output_filename)
    "subscription": (
        "2022-12-01",
        "/subscriptions/{subscription_id}",
        "subscription.json",
    ),
    "vm": (
        "2023-03-01",
        "/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines",
        "vm.json",
    ),
    "storage": (
        "2023-01-01",
        "/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts",
        "storage.json",
    ),
    "keyvault": (
        "2023-02-01",
        "/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults",
        "keyvault.json",
    ),
    "nsg": (
        "2023-05-01",
        "/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups",
        "nsg.json",
    ),
    "vnet": (
        "2023-05-01",
        "/subscriptions/{subscription_id}/providers/Microsoft.Network/virtualNetworks",
        "vnet.json",
    ),
    "public_ip": (
        "2023-05-01",
        "/subscriptions/{subscription_id}/providers/Microsoft.Network/publicIPAddresses",
        "publicip.json",
    ),
}

AZURE_MANAGEMENT_BASE = "https://management.azure.com"

# ═════════════════════════════════════════════════════════════════════════════
# MODE 1 — Evidence Ingestion & Analysis (the brain)
# ═════════════════════════════════════════════════════════════════════════════

def run(input_path: str, profile: str = "all") -> Dict:
    """
    Mode 1: Accept a path to one Azure JSON export file or a folder of exports.
    Parse, analyze, normalize, summarize, and return the THRAGG contract.
    """
    start_time = time.time()
    pipeline = base_module.Pipeline()
    errors: List[str] = []

    metadata = base_module.build_metadata(MODULE_NAME, MODULE_VERSION, TOOL_NAME, input_path)
    pipeline.add("init")

    # ── Collect files ──────────────────────────────────────────────────────
    files = base_module.collect_files(input_path, SUPPORTED_FORMATS, errors)
    pipeline.add(f"collect_files: {len(files)} found")

    # ── Parse each file ────────────────────────────────────────────────────
    details = base_module.build_empty_details(
        "subscription", "vm", "storage", "keyvault", "nsg", "vnet", "public_ip", "unknown"
    )
    all_findings: List[Dict] = []
    files_processed = 0

    for filepath in files:
        data, load_error = base_module.load_json_file(filepath)
        if load_error:
            errors.append(load_error)
            continue

        resource_type = _detect_resource_type(filepath, data)
        parsed_resources, parse_errors = _parse_resource(resource_type, data, filepath)
        errors.extend(parse_errors)

        bucket = resource_type if resource_type in details else "unknown"
        details[bucket].extend(parsed_resources)

        findings, finding_errors = _analyze_resources(resource_type, parsed_resources, filepath)
        errors.extend(finding_errors)
        all_findings.extend(findings)

        files_processed += 1

    pipeline.add(f"parse: {files_processed} files processed")
    pipeline.add(f"analyze: {len(all_findings)} findings generated")

    # ── Summary ────────────────────────────────────────────────────────────
    rule_stats = base_module.build_rule_statistics(all_findings)
    extra = {
        "resources_parsed": sum(len(v) for v in details.values()),
        "files_processed": files_processed,
        "profile": profile,
    }
    summary = base_module.build_summary(all_findings, rule_stats=rule_stats, extra_summary=extra)
    pipeline.add("summary")

    # ── Finalize metadata ──────────────────────────────────────────────────
    metadata["files_processed"] = files_processed
    metadata["processing_stats"] = base_module.build_processing_stats(details)
    metadata["module_health"] = base_module.build_module_health(details)
    metadata["rule_statistics"] = rule_stats
    base_module.finalize_metadata(metadata, time.time() - start_time, pipeline)

    artifacts = {
        "input_path": input_path,
        "output_dir": OUTPUT_DIR,
    }

    return {
        "metadata": metadata,
        "summary": summary,
        "details": details,
        "artifacts": artifacts,
        "errors": errors,
    }


# ═════════════════════════════════════════════════════════════════════════════
# MODE 2 — Azure CLI Collection
# ═════════════════════════════════════════════════════════════════════════════

def run_cli(output_dir: str = "thragg_results/cloud_cli", profile: str = "all") -> Dict:
    """
    Mode 2: Validate Azure CLI, authenticate, collect exports via az commands,
    write JSON files to output_dir, then hand everything off to run() (Mode 1).
    """
    errors: List[str] = []

    # ── Validate CLI ───────────────────────────────────────────────────────
    cli_ok, cli_error = _validate_cli()
    if not cli_ok:
        return _early_failure(errors, cli_error, output_dir, profile)

    # ── Validate authentication ────────────────────────────────────────────
    auth_ok, auth_error = _validate_authentication_cli()
    if not auth_ok:
        return _early_failure(errors, auth_error, output_dir, profile)

    # ── Prepare output directory ───────────────────────────────────────────
    dir_ok, dir_error = _ensure_output_directory(output_dir)
    if not dir_ok:
        return _early_failure(errors, dir_error, output_dir, profile)

    # ── Collect resources ──────────────────────────────────────────────────
    resource_types = COLLECTION_PROFILES.get(profile, COLLECTION_PROFILES["all"])

    for resource_type in resource_types:
        cmd_spec = CLI_COMMANDS.get(resource_type)
        if not cmd_spec:
            errors.append(f"No CLI command defined for resource type: {resource_type}")
            continue

        cmd, filename = cmd_spec
        output_path = os.path.join(output_dir, filename)

        success, cmd_error = _execute_cli_command(cmd, output_path)
        if not success:
            errors.append(f"CLI collection failed for {resource_type}: {cmd_error}")

    # ── Hand off to Mode 1 ─────────────────────────────────────────────────
    result = run(output_dir, profile=profile)
    result["errors"] = errors + result["errors"]
    return result


# ═════════════════════════════════════════════════════════════════════════════
# MODE 3 — Azure REST API Collection
# ═════════════════════════════════════════════════════════════════════════════

def run_api(
    output_dir: str = "thragg_results/cloud_api",
    profile: str = "all",
    subscription_id: Optional[str] = None,
) -> Dict:
    """
    Mode 3: Acquire OAuth token via az CLI, call Azure REST API,
    download JSON resources to output_dir, then hand off to run() (Mode 1).
    """
    errors: List[str] = []

    # ── Acquire token ──────────────────────────────────────────────────────
    token, token_error = _acquire_access_token()
    if not token:
        return _early_failure(errors, token_error, output_dir, profile)

    # ── Resolve subscription ID ────────────────────────────────────────────
    if not subscription_id:
        subscription_id, sub_error = _get_subscription_id()
        if not subscription_id:
            return _early_failure(errors, sub_error, output_dir, profile)

    # ── Prepare output directory ───────────────────────────────────────────
    dir_ok, dir_error = _ensure_output_directory(output_dir)
    if not dir_ok:
        return _early_failure(errors, dir_error, output_dir, profile)

    # ── Download resources ─────────────────────────────────────────────────
    resource_types = COLLECTION_PROFILES.get(profile, COLLECTION_PROFILES["all"])

    for resource_type in resource_types:
        rest_spec = REST_RESOURCES.get(resource_type)
        if not rest_spec:
            errors.append(f"No REST spec defined for resource type: {resource_type}")
            continue

        api_version, url_template, filename = rest_spec
        url_path = url_template.format(subscription_id=subscription_id)
        full_url = f"{AZURE_MANAGEMENT_BASE}{url_path}?api-version={api_version}"
        output_path = os.path.join(output_dir, filename)

        success, dl_error = _download_json(full_url, token, output_path)
        if not success:
            errors.append(f"REST download failed for {resource_type}: {dl_error}")

    # ── Hand off to Mode 1 ─────────────────────────────────────────────────
    result = run(output_dir, profile=profile)
    result["errors"] = errors + result["errors"]
    return result


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Resource Type Detection
# ═════════════════════════════════════════════════════════════════════════════

def _detect_resource_type(filepath: str, data: Any) -> str:
    """
    Detect Azure resource type from filename and data structure.
    Returns a key matching COLLECTION_PROFILES resource types.
    """
    filename = os.path.basename(filepath).lower()

    # Filename-based hints
    name_hints = {
        "vm": "vm",
        "storage": "storage",
        "keyvault": "keyvault",
        "key_vault": "keyvault",
        "nsg": "nsg",
        "vnet": "vnet",
        "publicip": "public_ip",
        "public_ip": "public_ip",
        "subscription": "subscription",
    }
    for hint, resource_type in name_hints.items():
        if hint in filename:
            return resource_type

    # Data-structure-based detection
    sample = data[0] if isinstance(data, list) and data else data
    if isinstance(sample, dict):
        # Check type field (common in Azure resources)
        rtype = (
            base_module.safe_get(sample, "type") or
            base_module.safe_get(sample, "resourceType") or
            base_module.safe_get(sample, "kind") or
            base_module.safe_get(sample, "properties", "type")
        )
        
        if isinstance(rtype, str):
            rtype_lower = rtype.lower()
            if "virtualmachine" in rtype_lower:
                return "vm"
            if "storageaccount" in rtype_lower:
                return "storage"
            if "vaults" in rtype_lower or "keyvault" in rtype_lower:
                return "keyvault"
            if "networksecuritygroup" in rtype_lower:
                return "nsg"
            if "virtualnetwork" in rtype_lower:
                return "vnet"
            if "publicipaddress" in rtype_lower:
                return "public_ip"

        # Subscription detection
        if base_module.safe_get(sample, "subscriptionId") and base_module.safe_get(sample, "tenantId"):
            return "subscription"

    return "unknown"


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Resource Parsers
# ═════════════════════════════════════════════════════════════════════════════

def _parse_resource(resource_type: str, data: Any, filepath: str) -> Tuple[List[Dict], List[str]]:
    """
    Dispatch to the correct parser for the detected resource type.
    Returns (parsed_list, errors).
    """
    parsers = {
        "subscription": _parse_subscription,
        "vm":           _parse_vms,
        "storage":      _parse_storage_accounts,
        "keyvault":     _parse_keyvaults,
        "nsg":          _parse_nsgs,
        "vnet":         _parse_vnets,
        "public_ip":    _parse_public_ips,
    }

    parser = parsers.get(resource_type)
    if not parser:
        return [], [f"No parser for resource type '{resource_type}' in {filepath}"]

    try:
        items = parser(data)
        return items, []
    except Exception as exc:
        return [], [f"Parser error for {resource_type} in {filepath}: {exc}"]


def _normalize_list_or_single(data: Any) -> List[Dict]:
    """Ensure data is a list of dicts."""
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _parse_subscription(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        result.append({
            "subscription_id": item.get("id") or item.get("subscriptionId"),
            "display_name": item.get("displayName") or item.get("name"),
            "state": item.get("state"),
            "tenant_id": item.get("tenantId"),
            "raw": item,
        })
    return result


def _parse_vms(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        props = base_module.ensure_dict(item.get("properties", {}))
        os_profile = base_module.ensure_dict(props.get("osProfile", {}))
        storage_profile = base_module.ensure_dict(props.get("storageProfile", {}))
        os_disk = base_module.ensure_dict(storage_profile.get("osDisk", {}))
        network_profile = base_module.ensure_dict(props.get("networkProfile", {}))

        result.append({
            "name": item.get("name"),
            "resource_group": item.get("resourceGroup") or _rg_from_id(item.get("id", "")),
            "location": item.get("location"),
            "vm_size": base_module.safe_get(props, "hardwareProfile", "vmSize"),
            "os_type": os_disk.get("osType"),
            "computer_name": os_profile.get("computerName"),
            "disable_password_auth": base_module.safe_get(os_profile, "linuxConfiguration", "disablePasswordAuthentication"),
            "encryption_at_host": base_module.safe_get(props, "securityProfile", "encryptionAtHost"),
            "secure_boot": base_module.safe_get(props, "securityProfile", "uefiSettings", "secureBootEnabled"),
            "vtpm": base_module.safe_get(props, "securityProfile", "uefiSettings", "vTpmEnabled"),
            "os_disk_encryption": os_disk.get("encryptionSettings"),
            "network_interfaces": [
                nic.get("id") for nic in base_module.ensure_list(network_profile.get("networkInterfaces"))
            ],
            "provisioning_state": props.get("provisioningState"),
            "raw": item,
        })
    return result


def _parse_storage_accounts(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        props = base_module.ensure_dict(item.get("properties", {}))
        result.append({
            "name": item.get("name"),
            "resource_group": item.get("resourceGroup") or _rg_from_id(item.get("id", "")),
            "location": item.get("location"),
            "sku": base_module.safe_get(item, "sku", "name"),
            "kind": item.get("kind"),
            "https_only": props.get("supportsHttpsTrafficOnly"),
            "public_access": props.get("allowBlobPublicAccess"),
            "allow_shared_key": props.get("allowSharedKeyAccess"),
            "tls_version": props.get("minimumTlsVersion"),
            "network_acls_default": base_module.safe_get(props, "networkAcls", "defaultAction"),
            "blob_soft_delete": base_module.safe_get(props, "deleteRetentionPolicy", "enabled"),
            "versioning": base_module.safe_get(props, "blobServiceProperties", "isVersioningEnabled"),
            "raw": item,
        })
    return result


def _parse_keyvaults(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        props = base_module.ensure_dict(item.get("properties", {}))
        result.append({
            "name": item.get("name"),
            "resource_group": item.get("resourceGroup") or _rg_from_id(item.get("id", "")),
            "location": item.get("location"),
            "sku": base_module.safe_get(props, "sku", "name"),
            "tenant_id": props.get("tenantId"),
            "soft_delete_enabled": props.get("enableSoftDelete"),
            "soft_delete_retention": props.get("softDeleteRetentionInDays"),
            "purge_protection": props.get("enablePurgeProtection"),
            "public_network_access": props.get("publicNetworkAccess"),
            "network_acls_default": base_module.safe_get(props, "networkAcls", "defaultAction"),
            "access_policies": base_module.ensure_list(props.get("accessPolicies")),
            "rbac_authorization": props.get("enableRbacAuthorization"),
            "raw": item,
        })
    return result


def _parse_nsgs(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        props = base_module.ensure_dict(item.get("properties", {}))
        security_rules = base_module.ensure_list(props.get("securityRules", []))

        inbound_any = [
            r for r in security_rules
            if (
                base_module.safe_get(r, "properties", "direction") == "Inbound"
                and base_module.safe_get(r, "properties", "access") == "Allow"
                and base_module.safe_get(r, "properties", "sourceAddressPrefix") in ("*", "Internet", "Any")
            )
        ]

        result.append({
            "name": item.get("name"),
            "resource_group": item.get("resourceGroup") or _rg_from_id(item.get("id", "")),
            "location": item.get("location"),
            "security_rules": security_rules,
            "inbound_allow_any_rules": inbound_any,
            "subnets_count": len(base_module.ensure_list(props.get("subnets"))),
            "raw": item,
        })
    return result


def _parse_vnets(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        props = base_module.ensure_dict(item.get("properties", {}))
        result.append({
            "name": item.get("name"),
            "resource_group": item.get("resourceGroup") or _rg_from_id(item.get("id", "")),
            "location": item.get("location"),
            "address_space": base_module.safe_get(props, "addressSpace", "addressPrefixes", default=[]),
            "subnets": [
                {
                    "name": s.get("name"),
                    "prefix": base_module.safe_get(s, "properties", "addressPrefix"),
                    "nsg": base_module.safe_get(s, "properties", "networkSecurityGroup", "id"),
                }
                for s in base_module.ensure_list(props.get("subnets", []))
                if isinstance(s, dict)
            ],
            "ddos_protection": base_module.safe_get(props, "ddosProtectionPlan"),
            "raw": item,
        })
    return result


def _parse_public_ips(data: Any) -> List[Dict]:
    items = _normalize_list_or_single(data)
    result = []
    for item in items:
        props = base_module.ensure_dict(item.get("properties", {}))
        result.append({
            "name": item.get("name"),
            "resource_group": item.get("resourceGroup") or _rg_from_id(item.get("id", "")),
            "location": item.get("location"),
            "ip_address": props.get("ipAddress"),
            "allocation_method": props.get("publicIPAllocationMethod"),
            "sku": base_module.safe_get(item, "sku", "name"),
            "dns_label": base_module.safe_get(props, "dnsSettings", "domainNameLabel"),
            "associated_with": props.get("ipConfiguration", {}).get("id") if isinstance(props.get("ipConfiguration"), dict) else None,
            "ddos_protection": base_module.safe_get(props, "ddosSettings", "protectionMode"),
            "idle_timeout": props.get("idleTimeoutInMinutes"),
            "raw": item,
        })
    return result


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Security Analysis (Rule Engine)
# ═════════════════════════════════════════════════════════════════════════════

def _analyze_resources(
    resource_type: str, resources: List[Dict], source: str
) -> Tuple[List[Dict], List[str]]:
    """
    Dispatch to the correct analyzer for the resource type.
    Returns (findings, errors).
    """
    analyzers = {
        "subscription": _analyze_subscription,
        "vm":           _analyze_vms,
        "storage":      _analyze_storage_accounts,
        "keyvault":     _analyze_keyvaults,
        "nsg":          _analyze_nsgs,
        "vnet":         _analyze_vnets,
        "public_ip":    _analyze_public_ips,
    }
    analyzer = analyzers.get(resource_type)
    if not analyzer:
        return [], []

    findings: List[Dict] = []
    errors: List[str] = []
    for resource in resources:
        try:
            new_findings = analyzer(resource, source)
            findings.extend(new_findings)
        except Exception as exc:
            errors.append(f"Analysis error for {resource_type} '{resource.get('name', '?')}': {exc}")
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
    exposure_key: str = "application",
    exploitability_key: str = "moderate",
) -> Dict:
    """Build and normalize a single finding. Central helper — called by all analyzers."""
    conf_label, conf_score, conf_rationale = base_module.compute_confidence(confidence_signal)
    raw = {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": conf_label,
        "confidence_score": conf_score,
        "confidence_rationale": conf_rationale,
        "category": category,
        "mitre_key": mitre_key,
        "asset": asset,
        "source": source,
        "evidence": evidence,
        "recommendation": recommendation,
    }
    finding = base_module.normalize_finding(raw, TOOL_NAME)
    finding["risk_score"] = base_module.compute_risk_score(
        severity, conf_label, exposure_key, exploitability_key
    )
    return finding


def _analyze_subscription(resource: Dict, source: str) -> List[Dict]:
    findings = []
    name = resource.get("display_name") or resource.get("subscription_id", "unknown")
    state = resource.get("state", "")
    if state and state.lower() != "enabled":
        findings.append(_make_finding(
            rule_id="CLD-SUB-001",
            title="Subscription Not in Enabled State",
            severity="Medium",
            confidence_signal="field_present",
            category="Governance",
            mitre_key="cloud_infra",
            asset=name,
            evidence={"state": state},
            recommendation="Verify subscription state and investigate why it is not enabled.",
            source=source,
            exposure_key="subscription",
            exploitability_key="contextual",
        ))
    return findings


def _analyze_vms(resource: Dict, source: str) -> List[Dict]:
    findings = []
    name = resource.get("name", "unknown")

    if resource.get("disable_password_auth") is False:
        findings.append(_make_finding(
            rule_id="CLD-VM-001",
            title="VM Allows Password Authentication",
            severity="Medium",
            confidence_signal="field_present",
            category="Configuration",
            mitre_key="valid_accounts",
            asset=name,
            evidence={"disable_password_auth": False},
            recommendation="Disable password authentication and enforce SSH key-based access.",
            source=source,
            exposure_key="vm",
            exploitability_key="moderate",
        ))

    if resource.get("encryption_at_host") is False:
        findings.append(_make_finding(
            rule_id="CLD-VM-002",
            title="VM Encryption at Host Disabled",
            severity="Medium",
            confidence_signal="field_present",
            category="Data Protection",
            mitre_key="unsecured_creds",
            asset=name,
            evidence={"encryption_at_host": False},
            recommendation="Enable encryption at host to protect VM disk data at rest.",
            source=source,
            exposure_key="vm",
            exploitability_key="contextual",
        ))

    if resource.get("secure_boot") is False:
        findings.append(_make_finding(
            rule_id="CLD-VM-003",
            title="VM Secure Boot Disabled",
            severity="Low",
            confidence_signal="field_present",
            category="Configuration",
            mitre_key="cloud_infra",
            asset=name,
            evidence={"secure_boot": False},
            recommendation="Enable Secure Boot to protect against boot-level malware.",
            source=source,
            exposure_key="vm",
            exploitability_key="contextual",
        ))

    if not resource.get("os_disk_encryption"):
        findings.append(_make_finding(
            rule_id="CLD-VM-004",
            title="VM OS Disk Encryption Not Configured",
            severity="High",
            confidence_signal="field_null",
            category="Data Protection",
            mitre_key="unsecured_creds",
            asset=name,
            evidence={"os_disk_encryption": None},
            recommendation="Configure Azure Disk Encryption on OS disk to protect data at rest.",
            source=source,
            exposure_key="vm",
            exploitability_key="moderate",
        ))

    return findings


def _analyze_storage_accounts(resource: Dict, source: str) -> List[Dict]:
    findings = []
    name = resource.get("name", "unknown")

    if resource.get("https_only") is False:
        findings.append(_make_finding(
            rule_id="CLD-STG-001",
            title="Storage Account Allows HTTP Traffic",
            severity="High",
            confidence_signal="field_present",
            category="Data in Transit",
            mitre_key="traffic_intercept",
            asset=name,
            evidence={"supportsHttpsTrafficOnly": False},
            recommendation="Enable 'Secure transfer required' to enforce HTTPS-only access.",
            source=source,
            exposure_key="storage",
            exploitability_key="moderate",
        ))

    if resource.get("public_access") is True:
        findings.append(_make_finding(
            rule_id="CLD-STG-002",
            title="Storage Account Allows Public Blob Access",
            severity="High",
            confidence_signal="field_present",
            category="Data Exposure",
            mitre_key="data_exposed",
            asset=name,
            evidence={"allowBlobPublicAccess": True},
            recommendation="Disable public blob access unless explicitly required for public static hosting.",
            source=source,
            exposure_key="storage",
            exploitability_key="trivial",
        ))

    if resource.get("allow_shared_key") is not False:
        findings.append(_make_finding(
            rule_id="CLD-STG-003",
            title="Storage Account Allows Shared Key Authorization",
            severity="Medium",
            confidence_signal="field_present",
            category="Access Control",
            mitre_key="valid_accounts",
            asset=name,
            evidence={"allowSharedKeyAccess": resource.get("allow_shared_key")},
            recommendation="Disable shared key access and enforce Azure AD-based authorization.",
            source=source,
            exposure_key="storage",
            exploitability_key="moderate",
        ))

    tls = resource.get("tls_version", "")
    if tls and tls != "TLS1_2":
        findings.append(_make_finding(
            rule_id="CLD-STG-004",
            title="Storage Account Minimum TLS Below 1.2",
            severity="Medium",
            confidence_signal="field_present",
            category="Data in Transit",
            mitre_key="traffic_intercept",
            asset=name,
            evidence={"minimumTlsVersion": tls},
            recommendation="Set minimum TLS version to TLS 1.2 to prevent downgrade attacks.",
            source=source,
            exposure_key="storage",
            exploitability_key="moderate",
        ))

    acl_default = resource.get("network_acls_default", "")
    if acl_default and acl_default.lower() == "allow":
        findings.append(_make_finding(
            rule_id="CLD-STG-005",
            title="Storage Account Network ACL Default Action is Allow",
            severity="High",
            confidence_signal="field_present",
            category="Network Exposure",
            mitre_key="data_exposed",
            asset=name,
            evidence={"networkAcls.defaultAction": acl_default},
            recommendation="Set the network ACL default action to Deny and explicitly allow required networks.",
            source=source,
            exposure_key="storage",
            exploitability_key="trivial",
        ))

    return findings


def _analyze_keyvaults(resource: Dict, source: str) -> List[Dict]:
    findings = []
    name = resource.get("name", "unknown")

    if resource.get("soft_delete_enabled") is False:
        findings.append(_make_finding(
            rule_id="CLD-KV-001",
            title="Key Vault Soft Delete Disabled",
            severity="High",
            confidence_signal="field_present",
            category="Data Protection",
            mitre_key="unsecured_creds",
            asset=name,
            evidence={"enableSoftDelete": False},
            recommendation="Enable soft delete to prevent accidental or malicious permanent deletion of secrets.",
            source=source,
            exposure_key="keyvault",
            exploitability_key="moderate",
        ))

    if resource.get("purge_protection") is not True:
        findings.append(_make_finding(
            rule_id="CLD-KV-002",
            title="Key Vault Purge Protection Disabled",
            severity="High",
            confidence_signal="field_present",
            category="Data Protection",
            mitre_key="unsecured_creds",
            asset=name,
            evidence={"enablePurgeProtection": resource.get("purge_protection")},
            recommendation="Enable purge protection to prevent permanent loss of secrets during the retention window.",
            source=source,
            exposure_key="keyvault",
            exploitability_key="moderate",
        ))

    pna = resource.get("public_network_access", "")
    if isinstance(pna, str) and pna.lower() == "enabled":
        findings.append(_make_finding(
            rule_id="CLD-KV-003",
            title="Key Vault Public Network Access Enabled",
            severity="Medium",
            confidence_signal="field_present",
            category="Network Exposure",
            mitre_key="unsecured_creds",
            asset=name,
            evidence={"publicNetworkAccess": pna},
            recommendation="Disable public network access and use private endpoints for Key Vault connectivity.",
            source=source,
            exposure_key="keyvault",
            exploitability_key="moderate",
        ))

    acl_default = resource.get("network_acls_default", "")
    if acl_default and acl_default.lower() == "allow":
        findings.append(_make_finding(
            rule_id="CLD-KV-004",
            title="Key Vault Network ACL Default Action is Allow",
            severity="High",
            confidence_signal="field_present",
            category="Network Exposure",
            mitre_key="unsecured_creds",
            asset=name,
            evidence={"networkAcls.defaultAction": acl_default},
            recommendation="Set network ACL default action to Deny and allowlist required networks/IPs.",
            source=source,
            exposure_key="keyvault",
            exploitability_key="trivial",
        ))

    if resource.get("rbac_authorization") is False:
        findings.append(_make_finding(
            rule_id="CLD-KV-005",
            title="Key Vault Not Using RBAC Authorization",
            severity="Medium",
            confidence_signal="field_present",
            category="Access Control",
            mitre_key="privilege_escalation",
            asset=name,
            evidence={"enableRbacAuthorization": False},
            recommendation="Enable RBAC authorization for granular access control over Key Vault operations.",
            source=source,
            exposure_key="keyvault",
            exploitability_key="contextual",
        ))

    return findings


def _analyze_nsgs(resource: Dict, source: str) -> List[Dict]:
    findings = []
    name = resource.get("name", "unknown")
    inbound_any = resource.get("inbound_allow_any_rules", [])

    for rule in inbound_any:
        rule_props = base_module.ensure_dict(rule.get("properties", {}))
        dest_port = rule_props.get("destinationPortRange", "*")
        protocol = rule_props.get("protocol", "*")
        rule_name = rule.get("name", "unknown_rule")

        severity = "Critical" if dest_port in ("*", "Any", "0-65535") else "High"

        findings.append(_make_finding(
            rule_id="CLD-NSG-001",
            title=f"NSG Allows Unrestricted Inbound Traffic — Rule: {rule_name}",
            severity=severity,
            confidence_signal="field_present",
            category="Network Exposure",
            mitre_key="network_recon",
            asset=name,
            evidence={
                "rule_name": rule_name,
                "destination_port": dest_port,
                "protocol": protocol,
                "source_prefix": rule_props.get("sourceAddressPrefix"),
            },
            recommendation=(
                "Restrict inbound rules to specific source IPs, port ranges, and protocols. "
                "Remove or scope overly permissive 'Allow Any' rules."
            ),
            source=source,
            exposure_key="nsg",
            exploitability_key="trivial",
        ))

    return findings


def _analyze_vnets(resource: Dict, source: str) -> List[Dict]:
    findings = []
    name = resource.get("name", "unknown")

    subnets_without_nsg = [
        s["name"] for s in resource.get("subnets", [])
        if isinstance(s, dict) and not s.get("nsg")
    ]
    if subnets_without_nsg:
        findings.append(_make_finding(
            rule_id="CLD-VNET-001",
            title="VNet Subnets Without Network Security Groups",
            severity="Medium",
            confidence_signal="field_null",
            category="Network Exposure",
            mitre_key="network_recon",
            asset=name,
            evidence={"subnets_without_nsg": subnets_without_nsg, "count": len(subnets_without_nsg)},
            recommendation="Attach an NSG to every subnet to enforce network traffic controls.",
            source=source,
            exposure_key="nsg",
            exploitability_key="contextual",
        ))

    if not resource.get("ddos_protection"):
        findings.append(_make_finding(
            rule_id="CLD-VNET-002",
            title="VNet DDoS Protection Not Configured",
            severity="Low",
            confidence_signal="field_null",
            category="Availability",
            mitre_key="cloud_infra",
            asset=name,
            evidence={"ddos_protection": None},
            recommendation="Enable Azure DDoS Protection Standard for critical virtual networks.",
            source=source,
            exposure_key="nsg",
            exploitability_key="contextual",
        ))

    return findings


def _analyze_public_ips(resource: Dict, source: str) -> List[Dict]:
    findings = []
    name = resource.get("name", "unknown")
    ip = resource.get("ip_address")

    if ip and not resource.get("associated_with"):
        findings.append(_make_finding(
            rule_id="CLD-PIP-001",
            title="Unassociated Public IP Address",
            severity="Low",
            confidence_signal="field_null",
            category="Governance",
            mitre_key="cloud_infra",
            asset=name,
            evidence={"ip_address": ip, "associated_with": None},
            recommendation="Remove unused public IP addresses to reduce attack surface and unnecessary cost.",
            source=source,
            exposure_key="public_ip",
            exploitability_key="contextual",
        ))

    if resource.get("allocation_method", "").lower() == "dynamic":
        findings.append(_make_finding(
            rule_id="CLD-PIP-002",
            title="Public IP Using Dynamic Allocation",
            severity="Low",
            confidence_signal="field_present",
            category="Configuration",
            mitre_key="cloud_infra",
            asset=name,
            evidence={"allocation_method": "Dynamic"},
            recommendation=(
                "Consider switching to Static allocation for services that require a consistent IP address."
            ),
            source=source,
            exposure_key="public_ip",
            exploitability_key="contextual",
        ))

    if not resource.get("ddos_protection"):
        findings.append(_make_finding(
            rule_id="CLD-PIP-003",
            title="Public IP Without DDoS Protection",
            severity="Low",
            confidence_signal="field_null",
            category="Availability",
            mitre_key="cloud_infra",
            asset=name,
            evidence={"ddos_protection": None},
            recommendation="Enable DDoS protection for public IP addresses attached to critical resources.",
            source=source,
            exposure_key="public_ip",
            exploitability_key="contextual",
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — CLI Helpers (Mode 2)
# ═════════════════════════════════════════════════════════════════════════════

def _validate_cli() -> Tuple[bool, Optional[str]]:
    """Check that az CLI is installed and reachable."""
    if shutil.which("az") is None:
        return False, "Azure CLI (az) is not installed or not found in PATH."
    return True, None


def _validate_authentication_cli() -> Tuple[bool, Optional[str]]:
    """Run `az account show` to confirm an active login session."""
    try:
        result = subprocess.run(
            ["az", "account", "show"],
            capture_output=True, text=True, timeout=AUTH_TIMEOUT
        )
        if result.returncode != 0:
            return False, f"Azure CLI not authenticated. Run 'az login'. Detail: {result.stderr.strip()}"
        return True, None
    except subprocess.TimeoutExpired:
        return False, "Azure CLI authentication check timed out."
    except Exception as exc:
        return False, f"Unexpected error checking Azure CLI authentication: {exc}"


def _execute_cli_command(cmd: List[str], output_path: str) -> Tuple[bool, Optional[str]]:
    """Run az CLI command and write JSON output to output_path."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=CLI_TIMEOUT)
        if result.returncode != 0:
            return False, result.stderr.strip()
        if not result.stdout.strip():
            return False, "Command returned empty output."
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)
        return True, None
    except subprocess.TimeoutExpired:
        return False, f"Command timed out: {' '.join(cmd)}"
    except Exception as exc:
        return False, f"Error executing CLI command: {exc}"


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — REST API Helpers (Mode 3)
# ═════════════════════════════════════════════════════════════════════════════

def _acquire_access_token() -> Tuple[Optional[str], Optional[str]]:
    """
    Acquire an Azure management API access token via az CLI.
    Reuses existing CLI authentication — no re-implementation.
    """
    if shutil.which("az") is None:
        return None, "Azure CLI (az) not installed. Required for token acquisition."
    try:
        result = subprocess.run(
            ["az", "account", "get-access-token",
             "--resource", "https://management.azure.com",
             "--output", "json"],
            capture_output=True, text=True, timeout=AUTH_TIMEOUT
        )
        if result.returncode != 0:
            return None, f"Token acquisition failed. Run 'az login'. Detail: {result.stderr.strip()}"
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


def _get_subscription_id() -> Tuple[Optional[str], Optional[str]]:
    """Resolve subscription ID from active az CLI session."""
    try:
        result = subprocess.run(
            ["az", "account", "show", "--output", "json"],
            capture_output=True, text=True, timeout=AUTH_TIMEOUT
        )
        if result.returncode != 0:
            return None, f"Could not retrieve subscription ID: {result.stderr.strip()}"
        data = json.loads(result.stdout)
        sub_id = data.get("id")
        if not sub_id:
            return None, "Subscription ID not found in az account show output."
        return sub_id, None
    except Exception as exc:
        return None, f"Error resolving subscription ID: {exc}"


def _execute_rest_request(url: str, token: str) -> Tuple[Optional[Any], Optional[str]]:
    """
    Make a GET request to the Azure REST API.
    Returns (response_data, error).
    """
    try:
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=REST_TIMEOUT) as response:
            raw = response.read().decode("utf-8")
        data = json.loads(raw)
        # Azure list APIs wrap results in a "value" key
        return data.get("value", data), None
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code} from Azure REST API: {exc.reason}"
    except urllib.error.URLError as exc:
        return None, f"Network error calling Azure REST API: {exc.reason}"
    except json.JSONDecodeError as exc:
        return None, f"Failed to parse Azure REST API response: {exc}"
    except Exception as exc:
        return None, f"Unexpected error calling Azure REST API: {exc}"


def _download_json(url: str, token: str, output_path: str) -> Tuple[bool, Optional[str]]:
    """Execute REST request and write JSON to output_path."""
    data, error = _execute_rest_request(url, token)
    if error:
        return False, error
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True, None
    except Exception as exc:
        return False, f"Failed to write JSON to {output_path}: {exc}"


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Shared Utilities
# ═════════════════════════════════════════════════════════════════════════════

def _ensure_output_directory(directory: str) -> Tuple[bool, Optional[str]]:
    """Create directory if it doesn't exist."""
    try:
        os.makedirs(directory, exist_ok=True)
        return True, None
    except Exception as exc:
        return False, f"Could not create output directory '{directory}': {exc}"


def _rg_from_id(resource_id: str) -> Optional[str]:
    """Extract resource group name from an Azure resource ID."""
    parts = resource_id.lower().split("/")
    try:
        idx = parts.index("resourcegroups")
        return resource_id.split("/")[idx + 1]
    except (ValueError, IndexError):
        return None


def _early_failure(
    errors: List[str], new_error: str, input_path: str, profile: str
) -> Dict:
    """Build a failed THRAGG contract for when collection cannot begin."""
    errors.append(new_error)
    metadata = base_module.build_metadata(MODULE_NAME, MODULE_VERSION, TOOL_NAME, input_path)
    metadata["status"] = "failed"
    return {
        "metadata": metadata,
        "summary": {"total_findings": 0},
        "details": {},
        "artifacts": {"input_path": input_path},
        "errors": errors,
    }


# ═════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    usage = (
        "Usage:\n"
        "  python cloud.py run <input_path> [profile]\n"
        "  python cloud.py cli <output_dir> [profile]\n"
        "  python cloud.py api <output_dir> [profile] [subscription_id]\n"
    )

    if len(sys.argv) < 3:
        print(usage)
        sys.exit(1)

    mode = sys.argv[1].lower()
    arg2 = sys.argv[2]
    profile_arg = sys.argv[3] if len(sys.argv) > 3 else "all"

    if mode == "run":
        result = run(arg2, profile=profile_arg)
    elif mode == "cli":
        result = run_cli(output_dir=arg2, profile=profile_arg)
    elif mode == "api":
        sub_id = sys.argv[4] if len(sys.argv) > 4 else None
        result = run_api(output_dir=arg2, profile=profile_arg, subscription_id=sub_id)
    else:
        print(f"Unknown mode: {mode}\n{usage}")
        sys.exit(1)

    print(json.dumps(result, indent=2, default=str))
