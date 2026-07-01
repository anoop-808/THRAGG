"""THRAGG cloud.py
Azure cloud resource security analysis module.
Parses cloud exports, evaluates security rules, produces THRAGG findings.
No Azure API calls. No deployments. Evidence in. Findings out.
"""

import os
import json
import time
from typing import Dict, List, Optional

from modules.base import (
    Pipeline,
    build_metadata,
    finalize_metadata,
    build_result,
    build_summary,
    build_empty_details,
    build_processing_stats,
    build_module_health,
    build_rule_statistics,
    collect_files,
    load_json_file,
    normalize_finding,
    compute_confidence,
    compute_risk_score,
    safe_get,
    ensure_list,
    ensure_dict,
    ModuleError,
    ParserError,
)
# ═══════════════════════════════════════════════════════════════════════════════
# Module Constants
# ═══════════════════════════════════════════════════════════════════════════════

MODULE_NAME = "cloud"
MODULE_VERSION = "1.0.0"
TOOL_NAME = "Azure / ARM"
SUPPORTED_FORMATS = {".json"}

# Maps filename stems to resource type keys.
# Cloud.py detects resource type from filename automatically.
RESOURCE_TYPE_MAP = {
    "vm": "virtual_machines",
    "vms": "virtual_machines",
    "virtual_machines": "virtual_machines",
    "virtualmachines": "virtual_machines",
    "storage": "storage_accounts",
    "storage_accounts": "storage_accounts",
    "storageaccounts": "storage_accounts",
    "keyvault": "key_vaults",
    "keyvaults": "key_vaults",
    "key_vaults": "key_vaults",
    "key_vault": "key_vaults",
    "nsg": "network_security_groups",
    "nsgs": "network_security_groups",
    "network_security_groups": "network_security_groups",
    "networksecuritygroups": "network_security_groups",
    "vnet": "vnets",
    "vnets": "vnets",
    "virtual_networks": "vnets",
    "virtualnetworks": "vnets",
    "public_ip": "public_ips",
    "public_ips": "public_ips",
    "publicips": "public_ips",
    "publicipaddresses": "public_ips",
    "resource_groups": "resource_groups",
    "resourcegroups": "resource_groups",
    "subscription": "subscriptions",
    "subscriptions": "subscriptions",
}

# Cloud-specific asset exposure weights.
# Extends base ASSET_EXPOSURE for cloud resource types.
CLOUD_ASSET_EXPOSURE = {
    "subscription": 1.0,
    "virtual_machine": 0.95,
    "storage": 0.90,
    "key_vault": 0.90,
    "network": 0.85,
    "public_ip": 0.85,
    "resource_group": 0.70,
    "monitoring": 0.65,
}


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def run(input_path: str) -> Dict:
    """
    Cloud module entry point.

    Args:
        input_path: Path to cloud export file or folder.

    Returns:
        Standard THRAGG result dict.
    """
    start_time = time.time()
    pipeline = Pipeline()

    # ── Bootstrap ────────────────────────────────────────────────────────────
    metadata = build_metadata(MODULE_NAME, MODULE_VERSION, TOOL_NAME, input_path)
    result = build_result(metadata)
    errors = result["errors"]

    details = build_empty_details(
        "compute",
        "storage",
        "network",
        "secrets",
        "governance",
        "monitoring",
    )

    cloud_store = _empty_cloud_store()
    findings: List[Dict] = []
    pipeline.add("bootstrap")

    # ── Collect Files ─────────────────────────────────────────────────────────
    files = collect_files(input_path, SUPPORTED_FORMATS, errors)
    if not files:
        result["errors"] = errors
        return result

    metadata["files_processed"] = len(files)
    pipeline.add("collect_files")

    # ── Detect, Load, Parse ───────────────────────────────────────────────────
    for filepath in files:
        resource_type = _detect_resource_type(filepath)
        if not resource_type:
            errors.append(f"Could not detect resource type for: {filepath}")
            continue

        data, err = load_json_file(filepath)
        if err:
            errors.append(err)
            continue

        records = ensure_list(data)
        _parse_resource(resource_type, records, cloud_store, errors)

    pipeline.add("parse_resources")

    # ── Run Rules ─────────────────────────────────────────────────────────────
    findings.extend(_rules_vm(cloud_store["virtual_machines"]))
    findings.extend(_rules_storage(cloud_store["storage_accounts"]))
    findings.extend(_rules_keyvault(cloud_store["key_vaults"]))
    findings.extend(_rules_nsg(cloud_store["network_security_groups"]))
    findings.extend(_rules_network(cloud_store["vnets"]))
    findings.extend(_rules_public_ip(cloud_store["public_ips"]))
    findings.extend(_rules_resource_group(cloud_store["resource_groups"]))
    findings.extend(_rules_subscription(cloud_store["subscriptions"]))
    pipeline.add("rules")

    # ── Categorize Findings ───────────────────────────────────────────────────
    details = _categorize_findings(findings, details)
    pipeline.add("categorize")

    # ── Build Metadata Stats ──────────────────────────────────────────────────
    metadata["processing_stats"] = build_processing_stats(cloud_store)
    metadata["module_health"] = build_module_health(cloud_store)
    rule_stats = build_rule_statistics(findings)
    metadata["rule_statistics"] = rule_stats
    pipeline.add("stats")

    # ── Build Summary ─────────────────────────────────────────────────────────
    extra_summary = _build_cloud_summary(cloud_store, findings)
    result["summary"] = build_summary(
        findings,
        rule_stats=rule_stats,
        extra_summary=extra_summary,
    )
    pipeline.add("summary")

    # ── Finalize ──────────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    finalize_metadata(metadata, elapsed, pipeline)

    result["metadata"] = metadata
    result["details"] = details
    result["errors"] = errors

    pipeline.add("complete")
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Cloud Store
# ═══════════════════════════════════════════════════════════════════════════════

def _empty_cloud_store() -> Dict[str, List]:
    """Initialize empty cloud resource store."""
    return {
        "virtual_machines": [],
        "storage_accounts": [],
        "network_security_groups": [],
        "vnets": [],
        "key_vaults": [],
        "public_ips": [],
        "resource_groups": [],
        "subscriptions": [],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Resource Type Detection
# ═══════════════════════════════════════════════════════════════════════════════

def _detect_resource_type(filepath: str) -> Optional[str]:
    """
    Detect Azure resource type from filename stem.

    Examples:
        vm.json            -> virtual_machines
        storage.json       -> storage_accounts
        nsg.json           -> network_security_groups
        keyvault.json      -> key_vaults
        public_ip.json     -> public_ips
        subscriptions.json -> subscriptions
    """
    stem = os.path.splitext(os.path.basename(filepath))[0].lower().strip()
    return RESOURCE_TYPE_MAP.get(stem)


# ═══════════════════════════════════════════════════════════════════════════════
# Resource Parsers
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_resource(
    resource_type: str,
    records: List[Dict],
    cloud_store: Dict,
    errors: List[str],
) -> None:
    """
    Dispatch records to the correct parser based on resource type.
    Parsed objects are appended to cloud_store in place.
    """
    parsers = {
        "virtual_machines": _parse_vm,
        "storage_accounts": _parse_storage,
        "key_vaults": _parse_keyvault,
        "network_security_groups": _parse_nsg,
        "vnets": _parse_vnet,
        "public_ips": _parse_public_ip,
        "resource_groups": _parse_resource_group,
        "subscriptions": _parse_subscription,
    }

    parser = parsers.get(resource_type)
    if not parser:
        errors.append(f"No parser registered for resource type: {resource_type}")
        return

    for record in records:
        if not isinstance(record, dict):
            errors.append(f"WARNING: Malformed {resource_type} record skipped.")
            continue
        try:
            obj = parser(record)
            if obj:
                cloud_store[resource_type].append(obj)
        except Exception as exc:
            errors.append(f"Parse error [{resource_type}]: {exc}")


def _parse_vm(record: Dict) -> Dict:
    """
    Normalize Azure VM record into standard cloud object.

    Expected fields from ARM export:
        name, id, location, properties.storageProfile.osDisk.osType,
        properties.osProfile, properties.networkProfile,
        properties.diagnosticsProfile, tags
    """
    props = ensure_dict(record.get("properties", {}))
    storage_profile = ensure_dict(props.get("storageProfile", {}))
    os_disk = ensure_dict(storage_profile.get("osDisk", {}))
    network_profile = ensure_dict(props.get("networkProfile", {}))
    diagnostics = ensure_dict(props.get("diagnosticsProfile", {}))
    boot_diag = ensure_dict(diagnostics.get("bootDiagnostics", {}))

    # Collect network interfaces
    interfaces = ensure_list(network_profile.get("networkInterfaces", []))
    has_public_ip = any(
        ensure_dict(iface).get("publicIpAddress") or
        ensure_dict(ensure_dict(iface).get("properties", {})).get("publicIPAddress")
        for iface in interfaces
    )

    # Encryption at rest
    managed_disk = ensure_dict(os_disk.get("managedDisk", {}))
    encryption = ensure_dict(managed_disk.get("diskEncryptionSet", {}))
    disk_encrypted = bool(encryption.get("id"))

    return {
        "name": record.get("name"),
        "id": record.get("id"),
        "location": record.get("location"),
        "resource_group": _extract_resource_group(record.get("id", "")),
        "os_type": os_disk.get("osType"),
        "vm_size": safe_get(props, "hardwareProfile", "vmSize"),
        "public_ip_attached": has_public_ip,
        "disk_encrypted": disk_encrypted,
        "boot_diagnostics_enabled": boot_diag.get("enabled", False),
        "tags": ensure_dict(record.get("tags", {})),
        "raw": record,
    }


def _parse_storage(record: Dict) -> Dict:
    """
    Normalize Azure Storage Account record.

    Expected fields from ARM export:
        name, id, location, kind, properties.publicNetworkAccess,
        properties.allowBlobPublicAccess, properties.supportsHttpsTrafficOnly,
        properties.minimumTlsVersion, properties.encryption
    """
    props = ensure_dict(record.get("properties", {}))
    encryption = ensure_dict(props.get("encryption", {}))
    services = ensure_dict(encryption.get("services", {}))
    blob_enc = ensure_dict(services.get("blob", {}))
    file_enc = ensure_dict(services.get("file", {}))

    return {
        "name": record.get("name"),
        "id": record.get("id"),
        "location": record.get("location"),
        "resource_group": _extract_resource_group(record.get("id", "")),
        "kind": record.get("kind"),
        "public_network_access": props.get("publicNetworkAccess", "Enabled"),
        "allow_blob_public_access": props.get("allowBlobPublicAccess", True),
        "https_only": props.get("supportsHttpsTrafficOnly", False),
        "minimum_tls_version": props.get("minimumTlsVersion", "TLS1_0"),
        "blob_encryption_enabled": blob_enc.get("enabled", False),
        "file_encryption_enabled": file_enc.get("enabled", False),
        "tags": ensure_dict(record.get("tags", {})),
        "raw": record,
    }


def _parse_keyvault(record: Dict) -> Dict:
    """
    Normalize Azure Key Vault record.

    Expected fields from ARM export:
        name, id, location, properties.publicNetworkAccess,
        properties.enableSoftDelete, properties.softDeleteRetentionInDays,
        properties.enablePurgeProtection, properties.networkAcls
    """
    props = ensure_dict(record.get("properties", {}))
    network_acls = ensure_dict(props.get("networkAcls", {}))

    return {
        "name": record.get("name"),
        "id": record.get("id"),
        "location": record.get("location"),
        "resource_group": _extract_resource_group(record.get("id", "")),
        "public_network_access": props.get("publicNetworkAccess", "Enabled"),
        "soft_delete_enabled": props.get("enableSoftDelete", False),
        "soft_delete_retention_days": props.get("softDeleteRetentionInDays", 0),
        "purge_protection_enabled": props.get("enablePurgeProtection", False),
        "network_acl_default_action": network_acls.get("defaultAction", "Allow"),
        "tags": ensure_dict(record.get("tags", {})),
        "raw": record,
    }


def _parse_nsg(record: Dict) -> Dict:
    """
    Normalize Azure NSG record.

    Expected fields from ARM export:
        name, id, location,
        properties.securityRules[].properties (direction, access,
        protocol, sourceAddressPrefix, destinationPortRange)
    """
    props = ensure_dict(record.get("properties", {}))
    raw_rules = ensure_list(props.get("securityRules", []))

    inbound = []
    outbound = []

    for rule in raw_rules:
        rule = ensure_dict(rule)
        rp = ensure_dict(rule.get("properties", {}))
        normalized_rule = {
            "name": rule.get("name"),
            "priority": rp.get("priority"),
            "direction": rp.get("direction"),
            "access": rp.get("access"),
            "protocol": rp.get("protocol"),
            "source_address": rp.get("sourceAddressPrefix", ""),
            "destination_address": rp.get("destinationAddressPrefix", ""),
            "destination_port": str(rp.get("destinationPortRange", "")),
            "source_port": str(rp.get("sourcePortRange", "")),
        }
        if rp.get("direction") == "Inbound":
            inbound.append(normalized_rule)
        else:
            outbound.append(normalized_rule)

    return {
        "name": record.get("name"),
        "id": record.get("id"),
        "location": record.get("location"),
        "resource_group": _extract_resource_group(record.get("id", "")),
        "inbound_rules": inbound,
        "outbound_rules": outbound,
        "tags": ensure_dict(record.get("tags", {})),
        "raw": record,
    }


def _parse_vnet(record: Dict) -> Dict:
    """
    Normalize Azure VNet record.

    Expected fields from ARM export:
        name, id, location,
        properties.addressSpace.addressPrefixes,
        properties.subnets[].properties.networkSecurityGroup,
        properties.enableDdosProtection
    """
    props = ensure_dict(record.get("properties", {}))
    address_space = ensure_dict(props.get("addressSpace", {}))
    raw_subnets = ensure_list(props.get("subnets", []))

    subnets = []
    for subnet in raw_subnets:
        subnet = ensure_dict(subnet)
        sp = ensure_dict(subnet.get("properties", {}))
        subnets.append({
            "name": subnet.get("name"),
            "address_prefix": sp.get("addressPrefix"),
            "has_nsg": bool(sp.get("networkSecurityGroup")),
            "nsg_id": safe_get(sp, "networkSecurityGroup", "id"),
        })

    return {
        "name": record.get("name"),
        "id": record.get("id"),
        "location": record.get("location"),
        "resource_group": _extract_resource_group(record.get("id", "")),
        "address_prefixes": ensure_list(address_space.get("addressPrefixes", [])),
        "ddos_protection_enabled": props.get("enableDdosProtection", False),
        "subnets": subnets,
        "tags": ensure_dict(record.get("tags", {})),
        "raw": record,
    }


def _parse_public_ip(record: Dict) -> Dict:
    """
    Normalize Azure Public IP record.

    Expected fields from ARM export:
        name, id, location,
        properties.publicIPAllocationMethod,
        properties.ipConfiguration (presence = attached)
    """
    props = ensure_dict(record.get("properties", {}))
    ip_config = props.get("ipConfiguration")

    return {
        "name": record.get("name"),
        "id": record.get("id"),
        "location": record.get("location"),
        "resource_group": _extract_resource_group(record.get("id", "")),
        "allocation_method": props.get("publicIPAllocationMethod", "Dynamic"),
        "ip_address": props.get("ipAddress"),
        "attached": bool(ip_config),
        "tags": ensure_dict(record.get("tags", {})),
        "raw": record,
    }


def _parse_resource_group(record: Dict) -> Dict:
    """
    Normalize Azure Resource Group record.

    Expected fields from ARM export:
        name, id, location, tags
    """
    return {
        "name": record.get("name"),
        "id": record.get("id"),
        "location": record.get("location"),
        "tags": ensure_dict(record.get("tags", {})),
        "raw": record,
    }


def _parse_subscription(record: Dict) -> Dict:
    """
    Normalize Azure Subscription record.

    Expected fields from ARM export:
        subscriptionId, displayName, state,
        properties.tenantId,
        diagnosticSettings (presence = enabled)
    """
    props = ensure_dict(record.get("properties", {}))
    diag_settings = ensure_list(record.get("diagnosticSettings", []))

    return {
        "name": record.get("displayName"),
        "id": record.get("subscriptionId"),
        "state": record.get("state"),
        "tenant_id": props.get("tenantId"),
        "diagnostic_settings_present": bool(diag_settings),
        "diagnostic_settings_count": len(diag_settings),
        "tags": ensure_dict(record.get("tags", {})),
        "raw": record,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Rule Engine — Compute (VM)
# ═══════════════════════════════════════════════════════════════════════════════

def _rules_vm(vms: List[Dict]) -> List[Dict]:
    """Evaluate security rules against virtual machines."""
    findings = []

    for vm in vms:
        name = vm.get("name", "unknown")
        resource_group = vm.get("resource_group", "unknown")
        location = vm.get("location", "unknown")

        # ── CLD-VM-001: Public IP Attached ────────────────────────────────────
        if vm.get("public_ip_attached"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-VM-001",
                    "title": "Virtual Machine Has Public IP Attached",
                    "severity": "High",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Compute",
                    "asset": name,
                    "role": "virtual_machine",
                    "source": resource_group,
                    "object_id": vm.get("id"),
                    "mitre_key": "valid_accounts",
                    "evidence": {
                        "vm_name": name,
                        "location": location,
                        "public_ip_attached": True,
                    },
                    "recommendation": (
                        "Remove the public IP from this VM. "
                        "Use Azure Bastion or a jump host for administrative access. "
                        "Restrict inbound access using NSG rules."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "virtual_machine",
                "trivial",
            )
            findings.append(finding)

        # ── CLD-VM-002: OS Disk Not Encrypted ─────────────────────────────────
        if not vm.get("disk_encrypted"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-VM-002",
                    "title": "Virtual Machine OS Disk Encryption Not Configured",
                    "severity": "High",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Compute",
                    "asset": name,
                    "role": "virtual_machine",
                    "source": resource_group,
                    "object_id": vm.get("id"),
                    "mitre_key": "valid_accounts",
                    "evidence": {
                        "vm_name": name,
                        "disk_encrypted": False,
                    },
                    "recommendation": (
                        "Enable Azure Disk Encryption or server-side encryption "
                        "with a customer-managed key for the OS disk."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "virtual_machine",
                "contextual",
            )
            findings.append(finding)

        # ── CLD-VM-003: Boot Diagnostics Disabled ─────────────────────────────
        if not vm.get("boot_diagnostics_enabled"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-VM-003",
                    "title": "Virtual Machine Boot Diagnostics Disabled",
                    "severity": "Medium",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Monitoring",
                    "asset": name,
                    "role": "virtual_machine",
                    "source": resource_group,
                    "object_id": vm.get("id"),
                    "evidence": {
                        "vm_name": name,
                        "boot_diagnostics_enabled": False,
                    },
                    "recommendation": (
                        "Enable boot diagnostics on this VM to capture serial "
                        "console output and screenshots for incident investigation."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "monitoring",
                "contextual",
            )
            findings.append(finding)

        # ── CLD-VM-004: Missing Tags ───────────────────────────────────────────
        if not vm.get("tags"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_null",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-VM-004",
                    "title": "Virtual Machine Has No Tags",
                    "severity": "Low",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Governance",
                    "asset": name,
                    "role": "virtual_machine",
                    "source": resource_group,
                    "object_id": vm.get("id"),
                    "evidence": {
                        "vm_name": name,
                        "tags": {},
                    },
                    "recommendation": (
                        "Apply tags to this VM for ownership, environment, "
                        "and cost tracking."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "resource_group",
                "contextual",
            )
            findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Rule Engine — Storage
# ═══════════════════════════════════════════════════════════════════════════════

def _rules_storage(accounts: List[Dict]) -> List[Dict]:
    """Evaluate security rules against storage accounts."""
    findings = []

    for account in accounts:
        name = account.get("name", "unknown")
        resource_group = account.get("resource_group", "unknown")

        # ── CLD-STG-001: Anonymous Blob Access Enabled ─────────────────────────
        if account.get("allow_blob_public_access"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-STG-001",
                    "title": "Storage Account Allows Anonymous Blob Access",
                    "severity": "Critical",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Storage",
                    "asset": name,
                    "role": "storage_account",
                    "source": resource_group,
                    "object_id": account.get("id"),
                    "mitre_key": "valid_accounts",
                    "evidence": {
                        "storage_name": name,
                        "allow_blob_public_access": True,
                    },
                    "recommendation": (
                        "Disable anonymous blob access on the storage account. "
                        "Set allowBlobPublicAccess to false. "
                        "Require authentication for all blob access."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "storage",
                "trivial",
            )
            findings.append(finding)

        # ── CLD-STG-002: HTTPS Not Enforced ───────────────────────────────────
        if not account.get("https_only"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-STG-002",
                    "title": "Storage Account Does Not Enforce HTTPS",
                    "severity": "High",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Storage",
                    "asset": name,
                    "role": "storage_account",
                    "source": resource_group,
                    "object_id": account.get("id"),
                    "evidence": {
                        "storage_name": name,
                        "https_only": False,
                    },
                    "recommendation": (
                        "Enable 'Secure transfer required' on the storage account "
                        "to enforce HTTPS for all requests."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "storage",
                "moderate",
            )
            findings.append(finding)

        # ── CLD-STG-003: Weak TLS Version ─────────────────────────────────────
        tls = account.get("minimum_tls_version", "TLS1_0")
        if tls in ("TLS1_0", "TLS1_1"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-STG-003",
                    "title": "Storage Account Uses Weak TLS Version",
                    "severity": "High",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Storage",
                    "asset": name,
                    "role": "storage_account",
                    "source": resource_group,
                    "object_id": account.get("id"),
                    "evidence": {
                        "storage_name": name,
                        "minimum_tls_version": tls,
                    },
                    "recommendation": (
                        "Set minimumTlsVersion to TLS1_2 on the storage account. "
                        "Deprecate TLS 1.0 and TLS 1.1 support."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "storage",
                "moderate",
            )
            findings.append(finding)

        # ── CLD-STG-004: Public Network Access Enabled ─────────────────────────
        if account.get("public_network_access", "Enabled") == "Enabled":
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-STG-004",
                    "title": "Storage Account Public Network Access Enabled",
                    "severity": "Medium",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Storage",
                    "asset": name,
                    "role": "storage_account",
                    "source": resource_group,
                    "object_id": account.get("id"),
                    "evidence": {
                        "storage_name": name,
                        "public_network_access": "Enabled",
                    },
                    "recommendation": (
                        "Restrict public network access. Use private endpoints "
                        "and network ACLs to limit access to trusted networks."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "storage",
                "moderate",
            )
            findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Rule Engine — Key Vault
# ═══════════════════════════════════════════════════════════════════════════════

def _rules_keyvault(vaults: List[Dict]) -> List[Dict]:
    """Evaluate security rules against Key Vaults."""
    findings = []

    for vault in vaults:
        name = vault.get("name", "unknown")
        resource_group = vault.get("resource_group", "unknown")

        # ── CLD-KV-001: Public Network Access Enabled ──────────────────────────
        if vault.get("public_network_access", "Enabled") == "Enabled":
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-KV-001",
                    "title": "Key Vault Public Network Access Enabled",
                    "severity": "High",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Secrets",
                    "asset": name,
                    "role": "key_vault",
                    "source": resource_group,
                    "object_id": vault.get("id"),
                    "mitre_key": "steal_token",
                    "evidence": {
                        "vault_name": name,
                        "public_network_access": "Enabled",
                    },
                    "recommendation": (
                        "Disable public network access on Key Vault. "
                        "Configure private endpoints and restrict access "
                        "using network ACLs."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "key_vault",
                "moderate",
            )
            findings.append(finding)

        # ── CLD-KV-002: Soft Delete Disabled ──────────────────────────────────
        if not vault.get("soft_delete_enabled"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-KV-002",
                    "title": "Key Vault Soft Delete Not Enabled",
                    "severity": "Medium",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Secrets",
                    "asset": name,
                    "role": "key_vault",
                    "source": resource_group,
                    "object_id": vault.get("id"),
                    "evidence": {
                        "vault_name": name,
                        "soft_delete_enabled": False,
                    },
                    "recommendation": (
                        "Enable soft delete on Key Vault to protect against "
                        "accidental or malicious deletion of keys and secrets."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "key_vault",
                "contextual",
            )
            findings.append(finding)

        # ── CLD-KV-003: Purge Protection Disabled ─────────────────────────────
        if not vault.get("purge_protection_enabled"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-KV-003",
                    "title": "Key Vault Purge Protection Not Enabled",
                    "severity": "Medium",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Secrets",
                    "asset": name,
                    "role": "key_vault",
                    "source": resource_group,
                    "object_id": vault.get("id"),
                    "evidence": {
                        "vault_name": name,
                        "purge_protection_enabled": False,
                    },
                    "recommendation": (
                        "Enable purge protection to prevent permanent deletion "
                        "of Key Vault objects during the retention period."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "key_vault",
                "contextual",
            )
            findings.append(finding)

        # ── CLD-KV-004: Network ACL Default Action Allow ───────────────────────
        if vault.get("network_acl_default_action", "Allow") == "Allow":
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-KV-004",
                    "title": "Key Vault Network ACL Default Action Is Allow",
                    "severity": "High",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Secrets",
                    "asset": name,
                    "role": "key_vault",
                    "source": resource_group,
                    "object_id": vault.get("id"),
                    "mitre_key": "steal_token",
                    "evidence": {
                        "vault_name": name,
                        "network_acl_default_action": "Allow",
                    },
                    "recommendation": (
                        "Set the Key Vault network ACL default action to Deny. "
                        "Explicitly allowlist trusted IP ranges and VNet subnets."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "key_vault",
                "moderate",
            )
            findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Rule Engine — Network Security Groups
# ═══════════════════════════════════════════════════════════════════════════════

# Ports considered dangerous when exposed to the internet.
_DANGEROUS_PORTS = {
    "22": "SSH",
    "3389": "RDP",
    "23": "Telnet",
    "21": "FTP",
    "25": "SMTP",
    "445": "SMB",
    "135": "RPC",
    "5985": "WinRM-HTTP",
    "5986": "WinRM-HTTPS",
}

_INTERNET_SOURCES = {"*", "0.0.0.0/0", "Internet", "Any"}


def _rules_nsg(nsgs: List[Dict]) -> List[Dict]:
    """Evaluate security rules against Network Security Groups."""
    findings = []

    for nsg in nsgs:
        name = nsg.get("name", "unknown")
        resource_group = nsg.get("resource_group", "unknown")

        for rule in nsg.get("inbound_rules", []):
            if rule.get("access") != "Allow":
                continue

            source = rule.get("source_address", "")
            port = rule.get("destination_port", "")

            # ── CLD-NSG-001: Dangerous Port Open To Internet ───────────────────
            if source in _INTERNET_SOURCES:
                service_name = _DANGEROUS_PORTS.get(port)
                if service_name or port == "*":
                    exposed_port = port if port != "*" else "All Ports"
                    label = service_name if service_name else "All Ports"
                    conf_label, conf_score, conf_rationale = compute_confidence(
                        "field_present",
                    )
                    finding = normalize_finding(
                        {
                            "rule_id": "CLD-NSG-001",
                            "title": f"NSG Allows {label} Access From Internet",
                            "severity": "Critical" if port in ("22", "3389", "*") else "High",
                            "confidence": conf_label,
                            "confidence_score": conf_score,
                            "confidence_rationale": conf_rationale,
                            "category": "Network",
                            "asset": name,
                            "role": "network_security_group",
                            "source": resource_group,
                            "object_id": nsg.get("id"),
                            "mitre_key": "valid_accounts",
                            "evidence": {
                                "nsg_name": name,
                                "rule_name": rule.get("name"),
                                "source_address": source,
                                "destination_port": exposed_port,
                                "protocol": rule.get("protocol"),
                                "service": label,
                            },
                            "recommendation": (
                                f"Remove or restrict the inbound rule allowing "
                                f"{label} ({exposed_port}) from {source}. "
                                f"Limit access to known IP ranges only. "
                                f"Use Azure Bastion for administrative access."
                            ),
                        },
                        TOOL_NAME,
                    )
                    finding["risk_score"] = compute_risk_score(
                        finding["severity"],
                        finding["confidence"],
                        "network",
                        "trivial",
                    )
                    findings.append(finding)

            # ── CLD-NSG-002: Any-to-Any Inbound Rule ──────────────────────────
            if source in _INTERNET_SOURCES and port == "*":
                conf_label, conf_score, conf_rationale = compute_confidence(
                    "field_present",
                )
                finding = normalize_finding(
                    {
                        "rule_id": "CLD-NSG-002",
                        "title": "NSG Has Any-to-Any Inbound Allow Rule",
                        "severity": "Critical",
                        "confidence": conf_label,
                        "confidence_score": conf_score,
                        "confidence_rationale": conf_rationale,
                        "category": "Network",
                        "asset": name,
                        "role": "network_security_group",
                        "source": resource_group,
                        "object_id": nsg.get("id"),
                        "mitre_key": "valid_accounts",
                        "evidence": {
                            "nsg_name": name,
                            "rule_name": rule.get("name"),
                            "source_address": source,
                            "destination_port": "*",
                        },
                        "recommendation": (
                            "Immediately remove the any-to-any inbound allow rule. "
                            "Replace with explicit rules for required services only."
                        ),
                    },
                    TOOL_NAME,
                )
                finding["risk_score"] = compute_risk_score(
                    finding["severity"],
                    finding["confidence"],
                    "network",
                    "trivial",
                )
                findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Rule Engine — Network (VNet)
# ═══════════════════════════════════════════════════════════════════════════════

def _rules_network(vnets: List[Dict]) -> List[Dict]:
    """Evaluate security rules against VNets."""
    findings = []

    for vnet in vnets:
        name = vnet.get("name", "unknown")
        resource_group = vnet.get("resource_group", "unknown")

        # ── CLD-NET-001: DDoS Protection Not Enabled ──────────────────────────
        if not vnet.get("ddos_protection_enabled"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-NET-001",
                    "title": "VNet DDoS Protection Not Enabled",
                    "severity": "Medium",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Network",
                    "asset": name,
                    "role": "vnet",
                    "source": resource_group,
                    "object_id": vnet.get("id"),
                    "evidence": {
                        "vnet_name": name,
                        "ddos_protection_enabled": False,
                    },
                    "recommendation": (
                        "Enable Azure DDoS Network Protection on this VNet "
                        "to protect public-facing resources."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "network",
                "contextual",
            )
            findings.append(finding)

        # ── CLD-NET-002: Subnets Without NSG ──────────────────────────────────
        for subnet in vnet.get("subnets", []):
            if not subnet.get("has_nsg"):
                conf_label, conf_score, conf_rationale = compute_confidence(
                    "field_null",
                )
                finding = normalize_finding(
                    {
                        "rule_id": "CLD-NET-002",
                        "title": "Subnet Has No Network Security Group Attached",
                        "severity": "Medium",
                        "confidence": conf_label,
                        "confidence_score": conf_score,
                        "confidence_rationale": conf_rationale,
                        "category": "Network",
                        "asset": subnet.get("name", "unknown"),
                        "role": "subnet",
                        "source": resource_group,
                        "object_id": vnet.get("id"),
                        "evidence": {
                            "vnet_name": name,
                            "subnet_name": subnet.get("name"),
                            "address_prefix": subnet.get("address_prefix"),
                            "nsg_attached": False,
                        },
                        "recommendation": (
                            "Attach a Network Security Group to this subnet "
                            "to enforce traffic filtering rules."
                        ),
                    },
                    TOOL_NAME,
                )
                finding["risk_score"] = compute_risk_score(
                    finding["severity"],
                    finding["confidence"],
                    "network",
                    "moderate",
                )
                findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Rule Engine — Public IPs
# ═══════════════════════════════════════════════════════════════════════════════

def _rules_public_ip(public_ips: List[Dict]) -> List[Dict]:
    """Evaluate security rules against Public IP addresses."""
    findings = []

    for pip in public_ips:
        name = pip.get("name", "unknown")
        resource_group = pip.get("resource_group", "unknown")

        # ── CLD-PIP-001: Unattached Public IP ─────────────────────────────────
        if not pip.get("attached"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_null",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-PIP-001",
                    "title": "Unattached Public IP Address",
                    "severity": "Low",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Network",
                    "asset": name,
                    "role": "public_ip",
                    "source": resource_group,
                    "object_id": pip.get("id"),
                    "evidence": {
                        "pip_name": name,
                        "attached": False,
                        "ip_address": pip.get("ip_address"),
                    },
                    "recommendation": (
                        "Delete unattached public IP addresses to reduce "
                        "attack surface and unnecessary cost."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "public_ip",
                "contextual",
            )
            findings.append(finding)

        # ── CLD-PIP-002: Static Public IP Allocation ───────────────────────────
        if pip.get("allocation_method") == "Static" and pip.get("attached"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_present",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-PIP-002",
                    "title": "Static Public IP Address In Use",
                    "severity": "Informational",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Network",
                    "asset": name,
                    "role": "public_ip",
                    "source": resource_group,
                    "object_id": pip.get("id"),
                    "evidence": {
                        "pip_name": name,
                        "allocation_method": "Static",
                        "ip_address": pip.get("ip_address"),
                    },
                    "recommendation": (
                        "Verify this static public IP is required. "
                        "Document ownership and review firewall exposure."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "public_ip",
                "contextual",
            )
            findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Rule Engine — Resource Groups
# ═══════════════════════════════════════════════════════════════════════════════

def _rules_resource_group(resource_groups: List[Dict]) -> List[Dict]:
    """Evaluate security rules against Resource Groups."""
    findings = []

    for rg in resource_groups:
        name = rg.get("name", "unknown")

        # ── CLD-RG-001: Missing Tags ───────────────────────────────────────────
        if not rg.get("tags"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_null",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-RG-001",
                    "title": "Resource Group Has No Tags",
                    "severity": "Low",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Governance",
                    "asset": name,
                    "role": "resource_group",
                    "source": name,
                    "object_id": rg.get("id"),
                    "evidence": {
                        "resource_group": name,
                        "tags": {},
                    },
                    "recommendation": (
                        "Apply mandatory tags to resource groups: owner, "
                        "environment, cost-center, and project."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "resource_group",
                "contextual",
            )
            findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Rule Engine — Subscription
# ═══════════════════════════════════════════════════════════════════════════════

def _rules_subscription(subscriptions: List[Dict]) -> List[Dict]:
    """Evaluate security rules against Subscriptions."""
    findings = []

    for sub in subscriptions:
        name = sub.get("name", "unknown")
        sub_id = sub.get("id", "unknown")

        # ── CLD-SUB-001: No Diagnostic Settings ───────────────────────────────
        if not sub.get("diagnostic_settings_present"):
            conf_label, conf_score, conf_rationale = compute_confidence(
                "field_null",
            )
            finding = normalize_finding(
                {
                    "rule_id": "CLD-SUB-001",
                    "title": "Subscription Has No Diagnostic Settings Configured",
                    "severity": "High",
                    "confidence": conf_label,
                    "confidence_score": conf_score,
                    "confidence_rationale": conf_rationale,
                    "category": "Monitoring",
                    "asset": name,
                    "role": "subscription",
                    "source": sub_id,
                    "object_id": sub_id,
                    "evidence": {
                        "subscription_name": name,
                        "subscription_id": sub_id,
                        "diagnostic_settings_present": False,
                    },
                    "recommendation": (
                        "Configure subscription-level diagnostic settings to export "
                        "Activity Logs to a Log Analytics workspace or Storage Account. "
                        "Retain logs for at least 90 days."
                    ),
                },
                TOOL_NAME,
            )
            finding["risk_score"] = compute_risk_score(
                finding["severity"],
                finding["confidence"],
                "subscription",
                "contextual",
            )
            findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Finding Categorization
# ═══════════════════════════════════════════════════════════════════════════════

def _categorize_findings(findings: List[Dict], details: Dict) -> Dict:
    """
    Organize findings into cloud security domain buckets.

    Cloud.py owns this logic. base.py has no category knowledge.

    Domains:
        compute   — VM findings
        storage   — Storage account findings
        network   — NSG, VNet, Public IP findings
        secrets   — Key Vault findings
        governance — Tagging, policy findings
        monitoring — Diagnostics, logging findings
    """
    category_map = {
        "Compute": "compute",
        "Storage": "storage",
        "Network": "network",
        "Secrets": "secrets",
        "Governance": "governance",
        "Monitoring": "monitoring",
    }

    for finding in findings:
        category = finding.get("category", "")
        bucket = category_map.get(category)
        if bucket and bucket in details:
            details[bucket].append(finding)
        else:
            # Default: governance bucket for unknown categories
            details["governance"].append(finding)

    return details


# ═══════════════════════════════════════════════════════════════════════════════
# Cloud-Specific Summary
# ═══════════════════════════════════════════════════════════════════════════════

def _build_cloud_summary(cloud_store: Dict, findings: List[Dict]) -> Dict:
    """
    Build cloud-specific summary fields.

    Passed to build_summary() as extra_summary.
    Answers: how many VMs, storage accounts, etc. were analyzed.
    """
    total_findings = len(findings)
    high_critical = sum(
        1 for f in findings
        if f.get("severity") in ("Critical", "High")
    )

    # Simple cloud health score: 100 minus penalty per high/critical finding.
    # Capped at 0. Informational for awareness only.
    penalty_per_finding = 5
    health_score = max(0, 100 - (high_critical * penalty_per_finding))

    return {
        "resource_counts": {
            "virtual_machines": len(cloud_store["virtual_machines"]),
            "storage_accounts": len(cloud_store["storage_accounts"]),
            "key_vaults": len(cloud_store["key_vaults"]),
            "network_security_groups": len(cloud_store["network_security_groups"]),
            "vnets": len(cloud_store["vnets"]),
            "public_ips": len(cloud_store["public_ips"]),
            "resource_groups": len(cloud_store["resource_groups"]),
            "subscriptions": len(cloud_store["subscriptions"]),
        },
        "high_critical_findings": high_critical,
        "cloud_health_score": health_score,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Utilities
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_resource_group(resource_id: str) -> Optional[str]:
    """
    Extract resource group name from Azure resource ID.

    Example:
        /subscriptions/abc/resourceGroups/my-rg/providers/...
        -> my-rg
    """
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = next(
            i for i, p in enumerate(parts)
            if p.lower() == "resourcegroups"
        )
        return parts[idx + 1]
    except (StopIteration, IndexError):
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Example Usage
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json

    result = run("cloud_exports/")
    print(json.dumps(result, indent=2, default=str))
