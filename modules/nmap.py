"""THRAGG modules/nmap.py - Network Reconnaissance Module (v2.0.0)

Architecture:
  Mode 1 (run):     XML ingestion - THE BRAIN (parser, normalizer, scorer)
  Mode 2 (run_cli): CLI execution - feeds XML to Mode 1
  Mode 3 (run_api): Python-nmap execution - feeds XML to Mode 1

Framework utilities imported from modules.base. Nmap-specific logic preserved.
One parser. One normalization pipeline. One THRAGG contract.
"""

import os
import sys
import json
import time
import tempfile
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from xml.etree import ElementTree as ET

# Import shared framework utilities from modules.base
from modules.base import (
    compute_risk_score,
    collect_files,
)

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE METADATA
# ═══════════════════════════════════════════════════════════════════════════════

MODULE_NAME = "network"
MODULE_VERSION = "2.0.0"
TOOL_NAME = "Nmap"
SUPPORTED_FORMATS = {".xml"}

# Scan profiles: profile_name -> (nmap_flags, description)
SCAN_PROFILES = {
    "quick": {
        "flags": "-sV --script vuln -T4",
        "description": "Quick scan - fast service detection + vulnerability scripts",
    },
    "default": {
        "flags": "-sV -sC -O --script default -T3",
        "description": "Default scan - balanced speed and detail",
    },
    "full": {
        "flags": "-sV -sC -O -A --script all -T2",
        "description": "Full scan - comprehensive, all scripts, slow",
    },
    "stealth": {
        "flags": "-sS -sV -T1 --script vuln",
        "description": "Stealth scan - SYN stealth, slow, minimal footprint",
    },
}

# Severity mapping: port state/service -> (severity, confidence)
SERVICE_SEVERITY = {
    "ssh": ("Medium", "High"),
    "ftp": ("High", "High"),
    "telnet": ("Critical", "High"),
    "smtp": ("Medium", "Medium"),
    "http": ("Low", "High"),
    "https": ("Low", "High"),
    "dns": ("Medium", "Medium"),
    "snmp": ("High", "High"),
    "smb": ("Critical", "High"),
    "rdp": ("Critical", "High"),
    "mysql": ("High", "High"),
    "postgres": ("High", "High"),
    "mongodb": ("Critical", "High"),
    "redis": ("Critical", "High"),
}

# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API - MODE 1: XML INGESTION (THE BRAIN)
# ═══════════════════════════════════════════════════════════════════════════════

def run(input_path: str) -> Dict:
    """
    MODE 1: XML Ingestion and Parsing
    
    Accepts single XML file or folder containing XML reports.
    Parses, normalizes, scores, and returns THRAGG contract.
    
    Args:
        input_path: File or folder path
    
    Returns:
        THRAGG contract: {metadata, summary, details, artifacts, errors}
    """
    start = time.time()
    
    result = {
        "metadata": {
            "module": MODULE_NAME,
            "module_version": MODULE_VERSION,
            "tool": TOOL_NAME,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time": None,
            "files_processed": 0,
            "total_findings": 0,
            "artifacts": [],
        },
        "summary": {},
        "details": {},
        "artifacts": {},
        "errors": [],
    }
    
    if not input_path or not os.path.exists(input_path):
        result["errors"].append(f"Input path does not exist: {input_path}")
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    # Collect XML files (using base utility)
    xml_files = collect_files(input_path, SUPPORTED_FORMATS, result["errors"])
    if not xml_files:
        result["errors"].append("No XML files found to parse.")
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    result["metadata"]["artifacts"] = xml_files
    result["artifacts"] = {"input_files": xml_files}
    
    # Parse all XML files
    all_findings = []
    for xml_file in xml_files:
        findings, parse_err = _parse_xml_file(xml_file)
        if parse_err:
            result["errors"].append(parse_err)
            continue
        all_findings.extend(findings)
        result["metadata"]["files_processed"] += 1
    
    # Build summary
    result["details"] = {"findings": all_findings}
    result["summary"] = _build_summary(all_findings)
    result["metadata"]["total_findings"] = len(all_findings)
    result["metadata"]["execution_time"] = round(time.time() - start, 4)
    
    return result

# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API - MODE 2: CLI EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

def run_cli(
    targets: str,
    profile: str = "default",
    output_dir: Optional[str] = None,
    timeout: int = 300
) -> Dict:
    """
    MODE 2: CLI Execution
    
    Execute Nmap via CLI, generate XML, pass to Mode 1.
    
    Args:
        targets: Single IP, hostname, CIDR, or path to targets file
        profile: Scan profile (quick, default, full, stealth)
        output_dir: Directory for XML output (default: temp)
        timeout: Scan timeout in seconds
    
    Returns:
        THRAGG contract
    """
    start = time.time()
    
    result = {
        "metadata": {
            "module": MODULE_NAME,
            "module_version": MODULE_VERSION,
            "tool": TOOL_NAME,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time": None,
            "files_processed": 0,
            "total_findings": 0,
            "artifacts": [],
        },
        "summary": {},
        "details": {},
        "artifacts": {},
        "errors": [],
    }
    
    # Validate targets
    target_list, target_err = _collect_targets(targets)
    if target_err:
        result["errors"].append(target_err)
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    if not target_list:
        result["errors"].append("No valid targets provided.")
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    # Validate Nmap installed
    nmap_path, nmap_err = _locate_nmap()
    if nmap_err:
        result["errors"].append(nmap_err)
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    # Ensure output directory
    if output_dir is None:
        output_dir = tempfile.gettempdir()
    
    output_dir, dir_err = _ensure_output_directory(output_dir)
    if dir_err:
        result["errors"].append(dir_err)
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    # Build and execute scan command
    xml_file, scan_err = _execute_cli_scan(
        nmap_path, target_list, profile, output_dir, timeout
    )
    if scan_err:
        result["errors"].append(scan_err)
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    # Pass XML to Mode 1 parser
    result_mode1 = run(xml_file)
    
    # Merge results, preserve CLI metadata
    result["metadata"].update(result_mode1["metadata"])
    result["metadata"]["scan_mode"] = "cli"
    result["metadata"]["targets"] = target_list
    result["metadata"]["profile"] = profile
    result["summary"] = result_mode1["summary"]
    result["details"] = result_mode1["details"]
    result["artifacts"] = result_mode1["artifacts"]
    result["errors"].extend(result_mode1["errors"])
    
    result["metadata"]["execution_time"] = round(time.time() - start, 4)
    return result

# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API - MODE 3: PYTHON-NMAP API
# ═══════════════════════════════════════════════════════════════════════════════

def run_api(
    targets: str,
    profile: str = "default",
    output_dir: Optional[str] = None,
    timeout: int = 300
) -> Dict:
    """
    MODE 3: Python-Nmap API Execution
    
    Execute Nmap via python-nmap, export XML, pass to Mode 1.
    
    Args:
        targets: Single IP, hostname, CIDR, or path to targets file
        profile: Scan profile (quick, default, full, stealth)
        output_dir: Directory for XML output (default: temp)
        timeout: Scan timeout in seconds
    
    Returns:
        THRAGG contract
    """
    start = time.time()
    
    result = {
        "metadata": {
            "module": MODULE_NAME,
            "module_version": MODULE_VERSION,
            "tool": TOOL_NAME,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time": None,
            "files_processed": 0,
            "total_findings": 0,
            "artifacts": [],
        },
        "summary": {},
        "details": {},
        "artifacts": {},
        "errors": [],
    }
    
    # Validate targets
    target_list, target_err = _collect_targets(targets)
    if target_err:
        result["errors"].append(target_err)
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    if not target_list:
        result["errors"].append("No valid targets provided.")
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    # Validate python-nmap installed
    py_nmap_err = _validate_python_nmap()
    if py_nmap_err:
        result["errors"].append(py_nmap_err)
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    # Ensure output directory
    if output_dir is None:
        output_dir = tempfile.gettempdir()
    
    output_dir, dir_err = _ensure_output_directory(output_dir)
    if dir_err:
        result["errors"].append(dir_err)
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    # Execute scan via python-nmap
    xml_file, scan_err = _execute_python_scan(target_list, profile, output_dir, timeout)
    if scan_err:
        result["errors"].append(scan_err)
        result["metadata"]["execution_time"] = round(time.time() - start, 4)
        return result
    
    # Pass XML to Mode 1 parser
    result_mode1 = run(xml_file)
    
    # Merge results, preserve API metadata
    result["metadata"].update(result_mode1["metadata"])
    result["metadata"]["scan_mode"] = "api"
    result["metadata"]["targets"] = target_list
    result["metadata"]["profile"] = profile
    result["summary"] = result_mode1["summary"]
    result["details"] = result_mode1["details"]
    result["artifacts"] = result_mode1["artifacts"]
    result["errors"].extend(result_mode1["errors"])
    
    result["metadata"]["execution_time"] = round(time.time() - start, 4)
    return result

# ═══════════════════════════════════════════════════════════════════════════════
# NMAP-SPECIFIC HELPERS - XML PARSING & NORMALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_xml_file(xml_file: str) -> Tuple[List[Dict], Optional[str]]:
    """
    Parse Nmap XML file and normalize findings.
    
    Args:
        xml_file: Path to XML file
    
    Returns:
        (findings_list, error_message)
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as exc:
        return [], f"Failed to parse XML {xml_file}: {exc}"
    
    findings = []
    
    # Extract hosts from Nmap XML
    for host_elem in root.findall("host"):
        host_findings = _normalize_host(host_elem)
        findings.extend(host_findings)
    
    return findings, None

def _normalize_host(host_elem: ET.Element) -> List[Dict]:
    """
    Normalize Nmap host element into THRAGG findings.
    
    Args:
        host_elem: XML element for a host
    
    Returns:
        List of THRAGG findings
    """
    findings = []
    
    # Extract host info
    hostnames = host_elem.findall(".//hostname")
    hostname = hostnames[0].get("name") if hostnames else "unknown"
    
    status_elem = host_elem.find("status")
    host_status = status_elem.get("state") if status_elem is not None else "unknown"
    
    # Extract IP
    addresses = host_elem.findall(".//address[@addrtype='ipv4']")
    ip_addr = addresses[0].get("addr") if addresses else "unknown"
    
    # Extract OS if available
    os_elem = host_elem.find(".//osmatch")
    os_name = os_elem.get("name") if os_elem is not None else None
    
    # Process ports
    for port_elem in host_elem.findall(".//port"):
        port_num = port_elem.get("portid")
        protocol = port_elem.get("protocol")
        
        state_elem = port_elem.find("state")
        port_state = state_elem.get("state") if state_elem is not None else "unknown"
        
        service_elem = port_elem.find("service")
        service_name = service_elem.get("name") if service_elem is not None else "unknown"
        product = service_elem.get("product", "") if service_elem is not None else ""
        version = service_elem.get("version", "") if service_elem is not None else ""
        
        # Skip closed/filtered ports - only report open
        if port_state not in ("open", "open|filtered"):
            continue
        
        # Compute severity & confidence based on service
        severity, confidence = _get_service_severity(service_name)
        
        # Compute risk score (using base utility)
        # base.compute_risk_score(severity, confidence, exposure_key, exploitability_key)
        risk_score = compute_risk_score(severity, confidence, "user", "moderate")
        
        # Build finding
        finding = {
            "rule_id": f"NMAP-{ip_addr}-{port_num}",
            "title": f"Open Port {port_num}/{protocol} ({service_name})",
            "severity": severity,
            "confidence": confidence,
            "category": "Network Reconnaissance",
            "asset": ip_addr,
            "port": int(port_num),
            "protocol": protocol,
            "service": service_name,
            "product": product,
            "version": version,
            "host_status": host_status,
            "hostname": hostname,
            "os": os_name,
            "source": "nmap",
            "risk_score": risk_score,
            "evidence": {
                "ip_address": ip_addr,
                "port": int(port_num),
                "protocol": protocol,
                "service_name": service_name,
                "port_state": port_state,
                "product_version": f"{product} {version}".strip() if product or version else "unknown",
            },
            "recommendation": _get_port_recommendation(service_name, port_num),
        }
        
        findings.append(finding)
    
    return findings

def _get_service_severity(service_name: str) -> Tuple[str, str]:
    """
    Map service name to severity and confidence.
    
    Args:
        service_name: Service name from Nmap
    
    Returns:
        (severity, confidence)
    """
    service_lower = service_name.lower()
    
    # Direct match
    if service_lower in SERVICE_SEVERITY:
        return SERVICE_SEVERITY[service_lower]
    
    # Substring match
    for key, (sev, conf) in SERVICE_SEVERITY.items():
        if key in service_lower:
            return sev, conf
    
    # Default: open port is at least Medium
    return "Medium", "High"

def _get_port_recommendation(service_name: str, port_num: int) -> str:
    """Get security recommendation for open port."""
    service_lower = service_name.lower()
    
    recommendations = {
        "ssh": "Restrict SSH access to authorized networks. Use key-based authentication.",
        "ftp": "FTP is insecure. Use SFTP or SCP instead.",
        "telnet": "Telnet is deprecated. Replace with SSH.",
        "smtp": "Verify SMTP relay restrictions. Enable TLS.",
        "http": "Ensure HTTPS is available. Redirect HTTP to HTTPS.",
        "https": "Verify TLS certificate validity and cipher strength.",
        "dns": "Secure DNS with DNSSEC. Restrict zone transfers.",
        "snmp": "Disable SNMP v1/v2. Use SNMPv3 with authentication.",
        "smb": "Disable SMB v1. Patch Windows systems immediately.",
        "rdp": "Restrict RDP to VPN. Disable if not needed.",
        "mysql": "Move to private network. Disable remote root.",
        "mongodb": "Enable authentication. Restrict network access.",
        "redis": "Require authentication. Use private network.",
    }
    
    for key, rec in recommendations.items():
        if key in service_lower:
            return rec
    
    return f"Review necessity of open port {port_num}. Close if not required."

# ═══════════════════════════════════════════════════════════════════════════════
# NMAP-SPECIFIC HELPERS - SUMMARY (custom for Nmap context)
# ═══════════════════════════════════════════════════════════════════════════════

def _build_summary(findings: List[Dict]) -> Dict:
    """
    Build Nmap-specific summary from findings.
    
    Args:
        findings: List of normalized findings
    
    Returns:
        Summary dict
    """
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }
    
    unique_hosts = set()
    unique_ports = set()
    
    for finding in findings:
        severity = finding.get("severity", "Informational")
        if severity in severity_counts:
            severity_counts[severity] += 1
        
        unique_hosts.add(finding.get("asset"))
        unique_ports.add((finding.get("asset"), finding.get("port")))
    
    severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
    highest_severity = next(
        (s for s in severity_order if severity_counts[s] > 0), None
    )
    
    return {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "highest_severity": highest_severity,
        "unique_hosts": len(unique_hosts),
        "unique_open_ports": len(unique_ports),
        "hosts": sorted(list(unique_hosts)),
    }

# ═══════════════════════════════════════════════════════════════════════════════
# NMAP-SPECIFIC HELPERS - TARGET VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

def _validate_target(target: str) -> Tuple[bool, Optional[str]]:
    """
    Validate target is IP, hostname, or CIDR.
    
    Args:
        target: Target string
    
    Returns:
        (is_valid, error_message)
    """
    target = target.strip()
    
    if not target:
        return False, "Empty target"
    
    # Check if it's a file (starts with / or ./)
    if target.startswith("/") or target.startswith("./"):
        if os.path.isfile(target):
            return True, None
        return False, f"File not found: {target}"
    
    # Check if it looks like IPv4
    parts = target.split(".")
    if len(parts) == 4:
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False, f"Invalid IPv4: {target}"
            return True, None
        except ValueError:
            pass
    
    # Check if it looks like CIDR
    if "/" in target:
        try:
            ip, mask = target.split("/")
            mask_int = int(mask)
            if mask_int < 0 or mask_int > 32:
                return False, f"Invalid CIDR mask: {target}"
            parts = ip.split(".")
            if len(parts) != 4:
                return False, f"Invalid CIDR: {target}"
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False, f"Invalid CIDR: {target}"
            return True, None
        except ValueError:
            return False, f"Invalid CIDR: {target}"
    
    # Assume it's a hostname (basic validation)
    if len(target) > 0 and all(c.isalnum() or c in ".-_" for c in target):
        return True, None
    
    return False, f"Invalid target: {target}"

def _collect_targets(targets: str) -> Tuple[List[str], Optional[str]]:
    """
    Collect targets from string, comma-separated, or file.
    
    Args:
        targets: Single target, comma-separated, or file path
    
    Returns:
        (target_list, error_message)
    """
    target_list = []
    
    # Check if it's a file
    if os.path.isfile(targets):
        try:
            with open(targets, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        is_valid, err = _validate_target(line)
                        if is_valid:
                            target_list.append(line)
        except Exception as exc:
            return [], f"Failed to read targets file: {exc}"
        
        if not target_list:
            return [], "No valid targets in file"
        
        return target_list, None
    
    # Parse comma-separated or single target
    for target in targets.split(","):
        target = target.strip()
        is_valid, err = _validate_target(target)
        if is_valid:
            target_list.append(target)
    
    if not target_list:
        return [], f"No valid targets in: {targets}"
    
    return target_list, None

# ═══════════════════════════════════════════════════════════════════════════════
# NMAP-SPECIFIC HELPERS - NMAP LOCALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

def _locate_nmap() -> Tuple[Optional[str], Optional[str]]:
    """
    Locate Nmap executable.
    
    Returns:
        (nmap_path, error_message)
    """
    # Try 'which' on Unix-like systems
    if sys.platform in ("linux", "darwin"):
        try:
            result = subprocess.run(
                ["which", "nmap"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip(), None
        except Exception:
            pass
    
    # Try 'where' on Windows
    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["where", "nmap"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip(), None
        except Exception:
            pass
    
    # Try direct 'nmap' command
    try:
        result = subprocess.run(
            ["nmap", "-V"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return "nmap", None
    except Exception:
        pass
    
    return None, "Nmap not found. Install Nmap or add to PATH."

def _validate_python_nmap() -> Optional[str]:
    """
    Validate python-nmap is installed.
    
    Returns:
        Error message if not available
    """
    try:
        import nmap
        return None
    except ImportError:
        return "python-nmap not installed. Install with: pip install python-nmap"

# ═══════════════════════════════════════════════════════════════════════════════
# NMAP-SPECIFIC HELPERS - SCAN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

def _get_scan_profile(profile: str) -> Tuple[str, Optional[str]]:
    """Get scan flags for profile."""
    profile_lower = profile.lower()
    
    if profile_lower in SCAN_PROFILES:
        return SCAN_PROFILES[profile_lower]["flags"], None
    
    # Default to default profile
    return SCAN_PROFILES["default"]["flags"], None

def _build_scan_command(
    nmap_path: str,
    targets: List[str],
    profile: str
) -> Tuple[List[str], Optional[str]]:
    """Build Nmap CLI command."""
    flags, profile_err = _get_scan_profile(profile)
    if profile_err:
        return [], profile_err
    
    # Build command: nmap <flags> <targets> -oX <output_file>
    command = [nmap_path] + flags.split() + targets
    
    return command, None

def _execute_cli_scan(
    nmap_path: str,
    targets: List[str],
    profile: str,
    output_dir: str,
    timeout: int
) -> Tuple[Optional[str], Optional[str]]:
    """Execute Nmap scan via CLI."""
    # Build command
    command, cmd_err = _build_scan_command(nmap_path, targets, profile)
    if cmd_err:
        return None, cmd_err
    
    # Generate output filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_file = os.path.join(output_dir, f"nmap_scan_{timestamp}.xml")
    
    # Add output flag
    command.extend(["-oX", xml_file])
    
    try:
        subprocess.run(command, timeout=timeout, capture_output=True, check=True)
        
        if os.path.exists(xml_file):
            return xml_file, None
        else:
            return None, f"Nmap did not generate output file: {xml_file}"
    
    except subprocess.TimeoutExpired:
        return None, f"Nmap scan timed out after {timeout} seconds"
    except subprocess.CalledProcessError as exc:
        return None, f"Nmap scan failed: {exc}"
    except Exception as exc:
        return None, f"Nmap execution failed: {exc}"

def _execute_python_scan(
    targets: List[str],
    profile: str,
    output_dir: str,
    timeout: int
) -> Tuple[Optional[str], Optional[str]]:
    """Execute Nmap scan via python-nmap."""
    try:
        import nmap as python_nmap
    except ImportError:
        return None, "python-nmap not installed"
    
    # Get scan flags
    flags, profile_err = _get_scan_profile(profile)
    if profile_err:
        return None, profile_err
    
    # Join targets
    targets_str = " ".join(targets)
    
    try:
        nm = python_nmap.PortScanner()
        nm.scan(hosts=targets_str, arguments=flags, timeout=timeout)
        
        # Export to XML
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_file = os.path.join(output_dir, f"nmap_python_{timestamp}.xml")
        
        # Write XML from nmap output
        with open(xml_file, "w") as f:
            f.write(nm.get_nmap_last_output())
        
        return xml_file, None
    
    except Exception as exc:
        return None, f"python-nmap scan failed: {exc}"

def _ensure_output_directory(output_dir: str) -> Tuple[str, Optional[str]]:
    """Ensure output directory exists."""
    try:
        output_dir = os.path.abspath(output_dir)
        os.makedirs(output_dir, exist_ok=True)
        return output_dir, None
    except Exception as exc:
        return None, f"Failed to create output directory: {exc}"

# ═══════════════════════════════════════════════════════════════════════════════
# TESTING
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import pprint
    
    print("=" * 80)
    print("THRAGG nmap.py v2.0.0 - Integrated with modules.base")
    print("=" * 80)
    print("\nModule loaded. Use run(), run_cli(), or run_api().")
    print("\nExample:")
    print("  from modules.nmap import run")
    print("  result = run('/path/to/scan.xml')")
    print("  print(result['summary']['total_findings'])")
