"""
THRAGG Module: nmap
Version: 2.1.0-stable

Contract (frozen):
    run(target: str, profile: str = "default") -> dict
        {
            "metadata": {
                "module": "nmap",
                "module_version": str,
                "target": str,
                "timestamp": str (ISO 8601),
                "execution_time": float,
                "status": "completed" | "failed" | "skipped",
                "returncode": int or None
            },
            "summary": {
                "total_hosts": int,
                "hosts_up": int,
                "total_open_ports": int,
                "risky_services": [str, ...]
            },
            "details": {
                "hosts": [ {ip, state, open_ports: [...]}, ... ]
            },
            "artifacts": {
                "raw_output": str or None,
                "xml_output": str or None
            },
            "errors": [str, ...]
        }
"""

import subprocess
import shutil
import time
import os
import re
import json

from modules.base import (
    Pipeline,
    build_metadata,
    build_result,
    finalize_metadata,
)

MODULE_NAME = "nmap"
MODULE_VERSION = "2.1.0-stable"
TOOL_NAME = "Nmap"
OUTPUT_DIR = "thragg_results"
DEFAULT_TIMEOUT = 300

# Configurable scan profiles. Each profile defines the nmap flags used.
SCAN_PROFILES = {
    "default": ["-sV", "-T4"],
    "fast": ["-T4", "-F"],
    "deep": ["-sV", "-sC", "-T4", "-p-"],
    "stealth": ["-sS", "-T2"],
}

# Services commonly flagged as risky/high-value targets when found open.
RISKY_SERVICES = {
    "ftp", "telnet", "rsh", "rlogin", "vnc", "rdp", "ms-wbt-server",
    "smb", "microsoft-ds", "netbios-ssn", "mysql", "ms-sql-s",
    "postgresql", "mongodb", "redis", "memcached",
}


def ensure_output_dir():
    """Create the thragg_results directory if it doesn't exist. Returns the path."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    return OUTPUT_DIR


def _safe_target_name(target):
    """Sanitize target string for use in filenames."""
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", target)


def run_scan(target, output_dir, profile="default", timeout=DEFAULT_TIMEOUT):
    """
    Execute nmap against target using the given scan profile.
    Returns:
        {
            "raw_output_path": str or None,
            "xml_output_path": str or None,
            "returncode": int or None,
            "status": "completed" | "failed" | "skipped",
            "errors": [str, ...]
        }
    """
    errors = []
    raw_output_path = None
    xml_output_path = None
    returncode = None

    if shutil.which("nmap") is None:
        errors.append("nmap is not installed or not found in PATH.")
        return {
            "raw_output_path": None,
            "xml_output_path": None,
            "returncode": None,
            "status": "skipped",
            "errors": errors,
        }

    flags = SCAN_PROFILES.get(profile)
    if flags is None:
        errors.append(f"Unknown scan profile '{profile}', falling back to 'default'.")
        flags = SCAN_PROFILES["default"]

    safe_name = _safe_target_name(target)
    xml_output_path = os.path.join(output_dir, f"nmap_{safe_name}.xml")
    raw_output_path = os.path.join(output_dir, f"nmap_{safe_name}.txt")

    cmd = ["nmap", *flags, "-oX", xml_output_path, target]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        returncode = proc.returncode

        with open(raw_output_path, "w") as f:
            f.write(proc.stdout)
            if proc.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(proc.stderr)

        if returncode == 0:
            status = "completed"
        else:
            status = "failed"
            errors.append(
                f"nmap exited with non-zero status {returncode}. See raw output for details."
            )

    except subprocess.TimeoutExpired:
        errors.append(f"nmap scan timed out after {timeout} seconds.")
        xml_output_path = None
        status = "failed"
    except FileNotFoundError:
        errors.append("nmap executable not found at execution time.")
        xml_output_path = None
        status = "failed"
    except Exception as e:
        errors.append(f"Unexpected error running nmap: {e}")
        xml_output_path = None
        status = "failed"

    return {
        "raw_output_path": raw_output_path,
        "xml_output_path": xml_output_path,
        "returncode": returncode,
        "status": status,
        "errors": errors,
    }


def parse_results(xml_output_path):
    """
    Parse nmap XML output into a structured host list + quick stats.
    Returns:
        {
            "hosts": [
                {"ip": str, "state": str, "open_ports": [
                    {"port": int, "protocol": str, "service": str, "version": str}
                ]}
            ],
            "total_hosts": int,
            "hosts_up": int,
            "total_open_ports": int,
            "risky_services": [str, ...],
            "errors": [str, ...]
        }
    """
    errors = []
    hosts = []

    if not xml_output_path or not os.path.exists(xml_output_path):
        errors.append("No XML output available to parse.")
        return {
            "hosts": [],
            "total_hosts": 0,
            "hosts_up": 0,
            "total_open_ports": 0,
            "risky_services": [],
            "errors": errors,
        }

    try:
        import xml.etree.ElementTree as ET

        tree = ET.parse(xml_output_path)
        root = tree.getroot()

        for host_elem in root.findall("host"):
            status_elem = host_elem.find("status")
            state = status_elem.get("state") if status_elem is not None else "unknown"

            addr_elem = host_elem.find("address")
            ip = addr_elem.get("addr") if addr_elem is not None else "unknown"

            open_ports = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    portid = port_elem.get("portid")
                    try:
                        port_number = int(portid)
                    except (TypeError, ValueError):
                        errors.append(
                            f"Skipping malformed nmap port on host {ip}: "
                            f"invalid portid {portid!r}."
                        )
                        continue

                    port_state_elem = port_elem.find("state")
                    port_state = (
                        port_state_elem.get("state")
                        if port_state_elem is not None
                        else "unknown"
                    )
                    if port_state != "open":
                        continue

                    service_elem = port_elem.find("service")
                    service_name = (
                        service_elem.get("name") if service_elem is not None else ""
                    )
                    service_version = ""
                    if service_elem is not None:
                        product = service_elem.get("product", "")
                        version = service_elem.get("version", "")
                        service_version = f"{product} {version}".strip()

                    open_ports.append(
                        {
                            "port": port_number,
                            "protocol": port_elem.get("protocol", ""),
                            "service": service_name,
                            "version": service_version,
                        }
                    )

            hosts.append({"ip": ip, "state": state, "open_ports": open_ports})

    except ET.ParseError as e:
        errors.append(f"Failed to parse nmap XML output: {e}")
    except Exception as e:
        errors.append(f"Unexpected error parsing nmap results: {e}")

    hosts_up = sum(1 for h in hosts if h["state"] == "up")
    total_open_ports = sum(len(h["open_ports"]) for h in hosts)

    risky_found = set()
    for h in hosts:
        for p in h["open_ports"]:
            svc = (p["service"] or "").lower()
            if svc in RISKY_SERVICES:
                risky_found.add(svc)

    return {
        "hosts": hosts,
        "total_hosts": len(hosts),
        "hosts_up": hosts_up,
        "total_open_ports": total_open_ports,
        "risky_services": sorted(risky_found),
        "errors": errors,
    }


def run(target, profile="default"):
    """
    Main module entry point. Conforms to THRAGG frozen module contract v2.1.
    """
    start_time = time.time()
    pipeline = Pipeline()

    metadata = build_metadata(MODULE_NAME, MODULE_VERSION, TOOL_NAME, target)
    metadata["target"] = target
    result = build_result(metadata)
    errors = result["errors"]
    pipeline.add("bootstrap")

    output_dir = ensure_output_dir()
    pipeline.add("prepare_output")

    if (
        isinstance(target, str)
        and os.path.isfile(target)
        and target.lower().endswith(".xml")
    ):
        scan_result = {
            "raw_output_path": None,
            "xml_output_path": target,
            "returncode": 0,
            "status": "completed",
            "errors": [],
        }
    else:
        scan_result = run_scan(target, output_dir, profile=profile)
        errors.extend(scan_result["errors"])
    pipeline.add("scan")

    parsed = parse_results(scan_result["xml_output_path"])
    errors.extend(parsed["errors"])
    pipeline.add("parse_results")

    metadata["status"] = scan_result["status"]
    metadata["returncode"] = scan_result["returncode"]
    metadata["files_processed"] = 1 if scan_result["xml_output_path"] else 0
    metadata["processing_stats"] = {
        "total_hosts": parsed["total_hosts"],
        "hosts_up": parsed["hosts_up"],
        "total_open_ports": parsed["total_open_ports"],
    }
    metadata["module_health"] = {
        "nmap": "PASS" if scan_result["status"] == "completed" else "WARNING",
        "parser": "PASS" if not parsed["errors"] else "WARNING",
    }

    summary = {
        "total_hosts": parsed["total_hosts"],
        "hosts_up": parsed["hosts_up"],
        "total_open_ports": parsed["total_open_ports"],
        "risky_services": parsed["risky_services"],
    }
    pipeline.add("summary")

    details = {
        "hosts": parsed["hosts"],
    }

    artifacts = {
        "raw_output": scan_result["raw_output_path"],
        "xml_output": scan_result["xml_output_path"],
    }

    pipeline.add("complete")
    finalize_metadata(metadata, time.time() - start_time, pipeline)

    result["metadata"] = metadata
    result["summary"] = summary
    result["details"] = details
    result["artifacts"] = artifacts
    result["errors"] = errors

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python nmap.py <target> [profile]")
        sys.exit(1)

    target_arg = sys.argv[1]
    profile_arg = sys.argv[2] if len(sys.argv) > 2 else "default"

    result = run(target_arg, profile=profile_arg)
    print(json.dumps(result, indent=2))
