"""
THRAGG Module: zap
Version: 1.2.0

Public API:
    run(input_path)                      -> Mode 1  Evidence Ingestion (JSON + HTML reports)
    run_cli(target, output_dir, ...)     -> Mode 2  ZAP CLI execution → run()
    run_api(target, zap_base_url, ...)   -> Mode 3  ZAP REST API execution → run()

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
    Mode 1 auto-detects report format (JSON or HTML) and normalizes into
    a single internal structure before parsing alerts.

Dependencies:
    beautifulsoup4 (bs4) — required for HTML report parsing.
    Install: pip install beautifulsoup4
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
from typing import Any, Dict, List, Optional, Set, Tuple

from modules import base as base_module

# ─────────────────────────────────────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger("thragg.zap")

# ─────────────────────────────────────────────────────────────────────────────
# Module Constants
# ─────────────────────────────────────────────────────────────────────────────

MODULE_NAME    = "zap"
MODULE_VERSION = "1.2.0"
TOOL_NAME      = "OWASP ZAP"
SUPPORTED_FORMATS = frozenset({".json", ".html", ".htm"})

SUPPORTED_FORMATS_DISPLAY = "JSON (.json), HTML (.html, .htm)"

# ─────────────────────────────────────────────────────────────────────────────
# Timeout Constants
# ─────────────────────────────────────────────────────────────────────────────

CLI_TIMEOUT  = 600
REST_TIMEOUT = 30

# ─────────────────────────────────────────────────────────────────────────────
# ZAP Risk / Confidence Mapping
# ─────────────────────────────────────────────────────────────────────────────

ZAP_RISK_MAP: Dict[str, str] = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
}

ZAP_CONFIDENCE_MAP: Dict[str, str] = {
    "0": "Low",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Confirmed",
    "false positive": "Low",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "confirmed": "Confirmed",
}

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Mapping for Web Vulnerabilities
# ─────────────────────────────────────────────────────────────────────────────

ZAP_MITRE_MAP: Dict[str, str] = {
    "sql injection":               "T1190",
    "cross site scripting":        "T1189",
    "xss":                         "T1189",
    "remote file inclusion":       "T1190",
    "path traversal":              "T1083",
    "directory browsing":          "T1083",
    "command injection":           "T1059",
    "os command injection":        "T1059",
    "ldap injection":              "T1190",
    "xml injection":               "T1190",
    "server side request forgery": "T1090",
    "ssrf":                        "T1090",
    "insecure deserialization":    "T1190",
    "broken authentication":       "T1078",
    "session fixation":            "T1539",
    "csrf":                        "T1185",
    "cross-site request forgery":  "T1185",
    "information disclosure":      "T1005",
    "sensitive data exposure":     "T1005",
    "missing security header":     "T1190",
    "content security policy":     "T1190",
    "x-frame-options":             "T1185",
    "clickjacking":                "T1185",
    "open redirect":               "T1189",
    "buffer overflow":             "T1190",
}

# Headings to skip during heading-based extraction
_SKIP_HEADINGS = frozenset({
    "summary", "appendix", "alert detail", "alert details",
    "contents", "about", "report generated", "table of contents",
    "risk level", "alerts", "alert count", "overview",
})


# ═════════════════════════════════════════════════════════════════════════════
# MODE 1 — Evidence Ingestion (THE BRAIN)
# ═════════════════════════════════════════════════════════════════════════════

def run(input_path: str) -> Dict:
    """
    Mode 1 — Accept a ZAP report (JSON or HTML) or a folder containing
    ZAP reports. Auto-detect format, parse, analyze, normalize, and
    return the THRAGG contract.

    Backward compatible: existing JSON reports work unchanged.
    """
    start_time = time.time()
    pipeline   = base_module.Pipeline()
    errors: List[str] = []

    metadata = base_module.build_metadata(
        MODULE_NAME, MODULE_VERSION, TOOL_NAME, input_path,
    )
    pipeline.add("init")
    logger.info("Mode 1 started — input_path=%s", input_path)

    # ── Collect files ──────────────────────────────────────────────────────
    files = base_module.collect_files(input_path, SUPPORTED_FORMATS, errors)
    pipeline.add(f"collect_files: {len(files)} found")

    if not files:
        metadata["execution_time"] = round(time.time() - start_time, 4)
        return {
            "metadata":  metadata,
            "summary":   {"total_findings": 0},
            "details":   {},
            "artifacts": {"input_path": input_path},
            "errors":    errors,
        }

    # ── Parse each report ──────────────────────────────────────────────────
    details = base_module.build_empty_details(
        "web_alerts", "informational", "low", "medium", "high", "unknown",
    )

    all_findings: List[Dict] = []
    files_processed  = 0
    report_formats: List[str]  = []
    parsers_used: List[str]    = []
    format_counts: Dict[str, int] = {}

    for filepath in files:
        report_format = _detect_report_type(filepath)
        report_formats.append(report_format)
        format_counts[report_format] = format_counts.get(report_format, 0) + 1
        logger.debug("Detected format '%s' for %s", report_format, filepath)

        report_data, load_err, parser_used = _load_report(filepath, report_format)
        parsers_used.append(parser_used)

        if load_err:
            errors.append(load_err)
            logger.warning("Load error: %s", load_err)
            continue

        findings, parse_errs = _parse_alerts(report_data, filepath)
        errors.extend(parse_errs)
        all_findings.extend(findings)

        _categorize_findings(findings, details)
        files_processed += 1

    pipeline.add(f"parse: {files_processed} files")
    pipeline.add(f"analyze: {len(all_findings)} findings")

    # ── Summary ────────────────────────────────────────────────────────────
    rule_stats = base_module.build_rule_statistics(all_findings)

    extra_summary = {
        "files_processed": files_processed,
        "report_formats":  report_formats,
        "format_counts":   format_counts,
    }

    summary = base_module.build_summary(
        all_findings, rule_stats=rule_stats, extra_summary=extra_summary,
    )
    pipeline.add("summary")

    # ── Finalize metadata ──────────────────────────────────────────────────
    metadata["files_processed"] = files_processed
    metadata["report_format"]   = (
        report_formats[0] if len(report_formats) == 1 else report_formats
    )
    metadata["parser_used"] = (
        parsers_used[0] if len(parsers_used) == 1 else parsers_used
    )
    metadata["format_counts"]   = format_counts
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
# MODE 2 — ZAP CLI Execution
# ═════════════════════════════════════════════════════════════════════════════

def run_cli(
    target: str,
    output_dir: str = "thragg_results/zap_cli",
    scan_type: str = "baseline",
    report_format: str = "json",
    zap_path: Optional[str] = None,
    timeout: int = CLI_TIMEOUT,
) -> Dict:
    """
    Mode 2 — Execute ZAP scan via CLI, generate report, hand off to run().
    No parsing logic here. Mode 2 only collects evidence.

    Args:
        report_format: "json" or "html" — controls output format from ZAP CLI.
    """
    errors: List[str] = []

    logger.info(
        "Mode 2 (CLI) started — target=%s  scan_type=%s  format=%s",
        target, scan_type, report_format,
    )

    # ── Validate ZAP ──────────────────────────────────────────────────────
    zap_bin, zap_err = _locate_zap(zap_path)
    if zap_err:
        return _early_failure(errors, zap_err, output_dir)

    # ── Prepare output directory ──────────────────────────────────────────
    dir_ok, dir_err = _ensure_output_directory(output_dir)
    if not dir_ok:
        return _early_failure(errors, dir_err, output_dir)

    # ── Determine report extension ────────────────────────────────────────
    fmt_lower = report_format.lower()
    if fmt_lower in ("html", "htm"):
        ext = ".html"
        zap_flag = "-r"
    else:
        ext = ".json"
        zap_flag = "-J"

    report_path = os.path.join(output_dir, f"zap_report{ext}")

    # ── Execute scan ──────────────────────────────────────────────────────
    scan_ok, scan_err = _execute_zap_cli(
        zap_bin, target, scan_type, report_path, zap_flag, timeout,
    )
    if not scan_ok:
        return _early_failure(errors, scan_err, output_dir)

    # ── Hand off to Mode 1 ────────────────────────────────────────────────
    result = run(report_path)
    result["errors"] = errors + result["errors"]
    return result


# ═════════════════════════════════════════════════════════════════════════════
# MODE 3 — ZAP REST API Execution
# ═════════════════════════════════════════════════════════════════════════════

def run_api(
    target: str,
    zap_base_url: str = "http://localhost:8080",
    api_key: Optional[str] = None,
    output_dir: str = "thragg_results/zap_api",
    scan_type: str = "active",
    timeout: int = CLI_TIMEOUT,
) -> Dict:
    """
    Mode 3 — Execute ZAP scan via REST API, collect alerts, write to JSON,
    then hand off to run(). No parsing logic here.
    """
    errors: List[str] = []

    logger.info(
        "Mode 3 (API) started — target=%s  zap_url=%s", target, zap_base_url,
    )

    # ── Validate ZAP API ──────────────────────────────────────────────────
    api_ok, api_err = _validate_zap_api(zap_base_url, api_key)
    if not api_ok:
        return _early_failure(errors, api_err, output_dir)

    # ── Prepare output directory ──────────────────────────────────────────
    dir_ok, dir_err = _ensure_output_directory(output_dir)
    if not dir_ok:
        return _early_failure(errors, dir_err, output_dir)

    # ── Execute scan and collect alerts ───────────────────────────────────
    report_path = os.path.join(output_dir, "zap_api_report.json")
    scan_ok, scan_err = _execute_zap_api_scan(
        zap_base_url, api_key, target, scan_type, report_path, timeout,
    )
    if not scan_ok:
        return _early_failure(errors, scan_err, output_dir)

    # ── Hand off to Mode 1 ────────────────────────────────────────────────
    result = run(report_path)
    result["errors"] = errors + result["errors"]
    return result


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Report Type Detection
# ═════════════════════════════════════════════════════════════════════════════

def _detect_report_type(filepath: str) -> str:
    """
    Detect ZAP report format from file extension and content signature.

    Returns:
        "json", "html", or "unsupported"
    """
    ext = os.path.splitext(filepath)[1].lower()

    # Extension-based detection
    if ext == ".json":
        return "json"
    if ext in (".html", ".htm"):
        return "html"

    # Content-based fallback: read first 512 bytes
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            head = fh.read(512).strip()
    except Exception:
        return "unsupported"

    if not head:
        return "unsupported"

    if head.startswith("{") or head.startswith("["):
        return "json"
    if head.lower().startswith("<!doctype html") or head.lower().startswith("<html"):
        return "html"

    return "unsupported"


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Report Loaders
# ═════════════════════════════════════════════════════════════════════════════

def _load_report(
    filepath: str, report_format: str,
) -> Tuple[Optional[Dict], Optional[str], str]:
    """
    Load a ZAP report into the common internal structure.

    Both loaders return the SAME structure:
        {"site": [{"alerts": [...]}]}

    Returns:
        (report_data, error_message, parser_used)
    """
    if report_format == "json":
        data, err = _load_json_report(filepath)
        return data, err, "json_loader"

    if report_format == "html":
        data, err = _load_html_report(filepath)
        return data, err, "html_loader"

    # Unsupported format — provide helpful message
    actual_ext = os.path.splitext(filepath)[1].lower() or "(no extension)"
    return None, (
        f"Unsupported report format for {filepath}. "
        f"Received: {actual_ext}. "
        f"Supported: {SUPPORTED_FORMATS_DISPLAY}."
    ), "none"


def _load_json_report(filepath: str) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Load a ZAP JSON report into the common internal structure.

    Preserves ALL existing JSON loading behavior.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            raw = fh.read().strip()
    except Exception as exc:
        return None, f"Could not read JSON report {filepath}: {exc}"

    if not raw:
        return None, f"JSON report is empty: {filepath}"

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"Malformed JSON report {filepath}: {exc}"

    normalized = _normalize_report_structure(data)
    if normalized is None:
        return None, (
            f"JSON report does not contain recognizable ZAP alert data: {filepath}"
        )

    return normalized, None


def _load_html_report(filepath: str) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Load a ZAP HTML report into the common internal structure.

    Uses BeautifulSoup to extract security alert data from ZAP's HTML
    report format. Ignores all styling, CSS, JavaScript, and presentation.

    Merges results from ALL extraction strategies and deduplicates.

    Produces the SAME internal structure as _load_json_report():
        {"site": [{"alerts": [...]}]}
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return None, (
            "beautifulsoup4 is required for HTML report parsing. "
            "Install with: pip install beautifulsoup4"
        )

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            raw = fh.read()
    except Exception as exc:
        return None, f"Could not read HTML report {filepath}: {exc}"

    if not raw.strip():
        return None, f"HTML report is empty: {filepath}"

    try:
        soup = BeautifulSoup(raw, "html.parser")
    except Exception as exc:
        return None, f"Malformed HTML report {filepath}: {exc}"

    alerts = _extract_alerts_from_html(soup)

    if not alerts:
        return None, (
            f"Unable to parse HTML report — no alert data found: {filepath}"
        )

    return {"site": [{"alerts": alerts}]}, None


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — HTML Alert Extraction (MERGED + DEDUPLICATED)
# ═════════════════════════════════════════════════════════════════════════════

def _extract_alerts_from_html(soup: Any) -> List[Dict]:
    """
    Extract ZAP alert data from a BeautifulSoup-parsed HTML report.

    Runs ALL extraction strategies, merges results, and deduplicates.
    Each strategy is wrapped in try/except so one failing does not
    prevent others from contributing.

    Strategies:
        1. Table-based (traditional ZAP HTML — supports thead/tbody)
        2. Div/section-based (modern ZAP HTML)
        3. Heading-based (fallback — scans h2/h3/h4 and siblings)
        4. Details/summary-based (newer graphical reports)
        5. Definition list-based (dl/dt/dd structured reports)
    """
    all_alerts: List[Dict] = []

    # Strategy 1: Tables
    try:
        table_alerts = _extract_alerts_from_tables(soup)
        all_alerts.extend(table_alerts)
        logger.debug("Table strategy: %d alerts", len(table_alerts))
    except Exception as exc:
        logger.debug("Table extraction failed: %s", exc)

    # Strategy 2: Divs and sections
    try:
        div_alerts = _extract_alerts_from_divs(soup)
        all_alerts.extend(div_alerts)
        logger.debug("Div strategy: %d alerts", len(div_alerts))
    except Exception as exc:
        logger.debug("Div extraction failed: %s", exc)

    # Strategy 3: Headings
    try:
        heading_alerts = _extract_alerts_from_headings(soup)
        all_alerts.extend(heading_alerts)
        logger.debug("Heading strategy: %d alerts", len(heading_alerts))
    except Exception as exc:
        logger.debug("Heading extraction failed: %s", exc)

    # Strategy 4: Details/summary elements
    try:
        details_alerts = _extract_alerts_from_details(soup)
        all_alerts.extend(details_alerts)
        logger.debug("Details/summary strategy: %d alerts", len(details_alerts))
    except Exception as exc:
        logger.debug("Details/summary extraction failed: %s", exc)

    # Strategy 5: Definition lists
    try:
        dl_alerts = _extract_alerts_from_definition_lists(soup)
        all_alerts.extend(dl_alerts)
        logger.debug("Definition list strategy: %d alerts", len(dl_alerts))
    except Exception as exc:
        logger.debug("Definition list extraction failed: %s", exc)

    # Deduplicate
    deduped = _deduplicate_alerts(all_alerts)
    logger.debug(
        "Merged %d raw alerts → %d after deduplication",
        len(all_alerts), len(deduped),
    )

    return deduped


# ─────────────────────────────────────────────────────────────────────────────
# HTML Label → Alert Key Mapping (shared across all strategies)
# ─────────────────────────────────────────────────────────────────────────────

_HTML_LABEL_MAP: Dict[str, str] = {
    "alert":          "alert",
    "name":           "alert",
    "risk":           "riskdesc",
    "risk level":     "riskdesc",
    "confidence":     "confidence",
    "description":    "desc",
    "solution":       "solution",
    "reference":      "reference",
    "cwe id":         "cweid",
    "cwe":            "cweid",
    "wasc id":        "wascid",
    "wasc":           "wascid",
    "url":            "uri",
    "parameter":      "param",
    "attack":         "attack",
    "evidence":       "evidence",
    "other info":     "other",
    "other":          "other",
    "method":         "method",
    "count":          "count",
    "plugin id":      "pluginid",
    "plugin-id":      "pluginid",
    "pluginid":       "pluginid",
    "alert id":       "alertid",
    "alert-id":       "alertid",
    "alertid":        "alertid",
    "tags":           "tags",
    "tag":            "tags",
    "owasp":          "owasp_category",
    "owasp category": "owasp_category",
    "source":         "sourceid",
    "source id":      "sourceid",
    "input vector":   "inputvector",
}

# Instance-level fields (collected per URL, not per alert)
_INSTANCE_FIELDS = frozenset({"uri", "param", "attack", "evidence", "method"})


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 1: Table-Based Extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_alerts_from_tables(soup: Any) -> List[Dict]:
    """
    Extract alerts from ZAP's table-based HTML reports.
    Supports thead/tbody wrapping.
    """
    alerts: List[Dict] = []

    for table in soup.find_all("table"):
        # Collect all rows, accounting for thead/tbody
        rows = []
        thead = table.find("thead")
        if thead:
            rows.extend(thead.find_all("tr"))
        tbody = table.find("tbody")
        if tbody:
            rows.extend(tbody.find_all("tr"))
        if not rows:
            rows = table.find_all("tr")
        if not rows:
            continue

        # Extract headers from first row
        header_row = rows[0]
        headers = [
            cell.get_text(strip=True).lower()
            for cell in header_row.find_all(["th", "td"])
        ]

        # Multi-column alert summary table
        if any(h in headers for h in ("alert", "risk level", "risk", "name")):
            for row in rows[1:]:
                cells = row.find_all(["td", "th"])
                if len(cells) < 2:
                    continue
                alert = _build_alert_from_table_row(cells, headers)
                if alert and alert.get("alert"):
                    alerts.append(alert)
            continue

        # Two-column key-value detail table
        if len(headers) <= 2:
            alert = _build_alert_from_kv_table(rows)
            if alert and alert.get("alert"):
                alerts.append(alert)

    return alerts


def _build_alert_from_table_row(cells: List, headers: List[str]) -> Dict:
    """Build an alert dict from a table row using column headers."""
    alert: Dict[str, Any] = {}

    for idx, cell in enumerate(cells):
        if idx >= len(headers):
            break
        mapped_key = _HTML_LABEL_MAP.get(headers[idx])
        if mapped_key:
            alert[mapped_key] = cell.get_text(strip=True)

    if "uri" in alert:
        alert["instances"] = [{"uri": alert.pop("uri")}]

    return alert


def _build_alert_from_kv_table(rows: List) -> Dict:
    """Build an alert dict from a two-column key-value table."""
    alert: Dict[str, Any] = {}
    instances: List[Dict] = []
    current_instance: Dict[str, str] = {}

    for row in rows:
        cells = row.find_all(["td", "th"])
        if len(cells) < 2:
            continue

        label = cells[0].get_text(strip=True).lower().rstrip(":")
        value = cells[1].get_text(strip=True)

        mapped = _HTML_LABEL_MAP.get(label)
        if not mapped:
            continue

        if mapped in _INSTANCE_FIELDS:
            current_instance[mapped] = value
            if mapped == "uri" and current_instance:
                instances.append(dict(current_instance))
                current_instance = {}
        else:
            alert[mapped] = value

    if current_instance:
        instances.append(current_instance)
    if instances:
        alert["instances"] = instances

    return alert


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 2: Div/Section-Based Extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_alerts_from_divs(soup: Any) -> List[Dict]:
    """Extract alerts from div/section/article-based layouts."""
    alerts: List[Dict] = []

    selectors = [
        ("div", "alert"),
        ("div", "alert-item"),
        ("div", "vulnerability"),
        ("section", "alert"),
        ("article", "alert"),
        ("article", "vulnerability"),
    ]

    found_elements = []
    for tag, cls in selectors:
        found_elements.extend(soup.find_all(tag, class_=cls))

    for element in found_elements:
        alert = _extract_alert_from_block(element)
        if alert and alert.get("alert"):
            alerts.append(alert)

    return alerts


def _extract_alert_from_block(block: Any) -> Dict:
    """Extract alert data from a single block element (div/section/article)."""
    alert: Dict[str, Any] = {}

    # Alert name from heading
    heading = block.find(["h1", "h2", "h3", "h4", "h5"])
    if heading:
        alert["alert"] = heading.get_text(strip=True)

    # Key-value pairs from nested elements
    for element in block.find_all(["p", "div", "span", "dt", "dd", "li"]):
        text = element.get_text(strip=True)
        _extract_kv_from_text(text, alert)

    # Build instances
    if "uri" in alert:
        alert["instances"] = [{"uri": alert.pop("uri")}]

    return alert


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 3: Heading-Based Extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_alerts_from_headings(soup: Any) -> List[Dict]:
    """
    Fallback: parse alerts by scanning headings (h2/h3/h4) and
    the content between them.
    """
    alerts: List[Dict] = []

    for heading in soup.find_all(["h2", "h3", "h4"]):
        heading_text = heading.get_text(strip=True)

        if heading_text.lower() in _SKIP_HEADINGS:
            continue
        if len(heading_text) < 3:
            continue

        alert: Dict[str, Any] = {"alert": heading_text}

        # Collect sibling content until next heading
        sibling = heading.find_next_sibling()
        content_parts: List[str] = []

        while sibling and sibling.name not in ("h2", "h3", "h4"):
            text = sibling.get_text(strip=True)
            if text:
                content_parts.append(text)
                _extract_kv_from_text(text, alert)

            sibling = sibling.find_next_sibling()

        # Fallback description
        if "desc" not in alert and content_parts:
            alert["desc"] = " ".join(content_parts[:3])

        # Infer risk from heading text
        if "riskdesc" not in alert:
            for keyword in ("high", "medium", "low", "informational"):
                if keyword in heading_text.lower():
                    alert["riskdesc"] = keyword.capitalize()
                    break

        # Build instances
        if "uri" in alert:
            alert.setdefault("instances", []).append({"uri": alert.pop("uri")})

        if alert.get("alert"):
            alerts.append(alert)

    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 4: Details/Summary-Based Extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_alerts_from_details(soup: Any) -> List[Dict]:
    """
    Extract alerts from <details>/<summary> elements.
    Newer ZAP graphical reports use these collapsible sections.
    """
    alerts: List[Dict] = []

    for details_elem in soup.find_all("details"):
        summary = details_elem.find("summary")
        if not summary:
            continue

        alert: Dict[str, Any] = {
            "alert": summary.get_text(strip=True),
        }

        # Extract content within the details block
        for element in details_elem.find_all(
            ["p", "div", "span", "dt", "dd", "li", "td", "th"]
        ):
            if element == summary:
                continue
            text = element.get_text(strip=True)
            if text:
                _extract_kv_from_text(text, alert)

        # Check for nested tables within details
        for table in details_elem.find_all("table"):
            rows = table.find_all("tr")
            kv_alert = _build_alert_from_kv_table(rows)
            for key, val in kv_alert.items():
                if key not in alert:
                    alert[key] = val

        if "uri" in alert:
            alert.setdefault("instances", []).append({"uri": alert.pop("uri")})

        if alert.get("alert"):
            alerts.append(alert)

    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 5: Definition List-Based Extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_alerts_from_definition_lists(soup: Any) -> List[Dict]:
    """
    Extract alerts from <dl>/<dt>/<dd> structured reports.
    """
    alerts: List[Dict] = []

    for dl in soup.find_all("dl"):
        alert: Dict[str, Any] = {}
        instances: List[Dict] = []
        current_instance: Dict[str, str] = {}

        dts = dl.find_all("dt")
        dds = dl.find_all("dd")

        for dt, dd in zip(dts, dds):
            label = dt.get_text(strip=True).lower().rstrip(":")
            value = dd.get_text(strip=True)

            mapped = _HTML_LABEL_MAP.get(label)
            if not mapped:
                continue

            if mapped in _INSTANCE_FIELDS:
                current_instance[mapped] = value
                if mapped == "uri" and current_instance:
                    instances.append(dict(current_instance))
                    current_instance = {}
            else:
                alert[mapped] = value

        if current_instance:
            instances.append(current_instance)
        if instances:
            alert["instances"] = instances

        if alert.get("alert"):
            alerts.append(alert)

    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# Shared HTML Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_kv_from_text(text: str, alert: Dict) -> None:
    """
    Try to extract a key:value pair from a text string into an alert dict.
    Modifies alert in place.
    """
    for label, key in _HTML_LABEL_MAP.items():
        if text.lower().startswith(label + ":"):
            value = text[len(label) + 1:].strip()
            if key in _INSTANCE_FIELDS:
                if key == "uri":
                    alert.setdefault("instances", []).append({"uri": value})
                else:
                    alert[key] = value
            else:
                alert[key] = value
            return


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Alert Deduplication
# ═════════════════════════════════════════════════════════════════════════════

def _deduplicate_alerts(alerts: List[Dict]) -> List[Dict]:
    """
    Deduplicate alerts using (alert_name, uri, param) as a composite key.

    When duplicates are found, instances are merged into the first occurrence.
    """
    seen: Dict[str, int] = {}
    deduped: List[Dict]  = []

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        alert_name = alert.get("alert", "")
        if not alert_name:
            continue

        instances = base_module.ensure_list(alert.get("instances", []))

        if not instances:
            # No instances — deduplicate by alert name only
            key = alert_name.lower().strip()
            if key not in seen:
                seen[key] = len(deduped)
                deduped.append(alert)
            else:
                # Merge any additional fields into existing alert
                _merge_alert_fields(deduped[seen[key]], alert)
        else:
            for instance in instances:
                uri   = instance.get("uri", "") if isinstance(instance, dict) else ""
                param = instance.get("param", "") if isinstance(instance, dict) else ""
                key   = f"{alert_name.lower().strip()}|{uri}|{param}"

                if key not in seen:
                    # Create a new alert with this single instance
                    alert_copy = {
                        k: v for k, v in alert.items() if k != "instances"
                    }
                    alert_copy["instances"] = [instance]
                    seen[key] = len(deduped)
                    deduped.append(alert_copy)
                else:
                    _merge_alert_fields(deduped[seen[key]], alert)

    return deduped


def _merge_alert_fields(target: Dict, source: Dict) -> None:
    """
    Merge non-empty fields from source into target without overwriting
    existing non-empty values. Preserves richer data.
    """
    for key, value in source.items():
        if key == "instances":
            continue
        if key not in target or not target[key]:
            target[key] = value


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Report Structure Normalization
# ═════════════════════════════════════════════════════════════════════════════

def _normalize_report_structure(data: Any) -> Optional[Dict]:
    """
    Normalize various ZAP JSON shapes into the common internal structure:
        {"site": [{"alerts": [...]}]}
    """
    if isinstance(data, dict):
        if "site" in data:
            sites = data["site"]
            if isinstance(sites, list):
                return data
            if isinstance(sites, dict):
                return {"site": [sites]}

        if "alerts" in data:
            alerts = data["alerts"]
            if isinstance(alerts, list):
                return {"site": [{"alerts": alerts}]}

    if isinstance(data, list) and data:
        if isinstance(data[0], dict) and (
            "alert" in data[0] or "name" in data[0] or "riskdesc" in data[0]
        ):
            return {"site": [{"alerts": data}]}

    return None


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Alert Parsing (SHARED — used by ALL formats)
# ═════════════════════════════════════════════════════════════════════════════

def _parse_alerts(
    report_data: Dict, source: str,
) -> Tuple[List[Dict], List[str]]:
    """
    Parse alerts from the common internal structure and produce THRAGG findings.

    This function does NOT know whether the source was JSON or HTML.
    """
    findings: List[Dict] = []
    errors: List[str]    = []

    sites = base_module.ensure_list(report_data.get("site", []))

    for site in sites:
        if not isinstance(site, dict):
            continue

        site_name = site.get("@name") or site.get("name", "unknown")
        alerts    = base_module.ensure_list(site.get("alerts", []))

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            try:
                finding = _normalize_alert(alert, site_name, source)
                if finding:
                    findings.append(finding)
            except Exception as exc:
                alert_name = alert.get("alert", alert.get("name", "unknown"))
                errors.append(
                    f"Error parsing alert '{alert_name}' from {source}: {exc}"
                )
                logger.debug("Alert parse error", exc_info=True)

    return findings, errors


def _normalize_alert(alert: Dict, site_name: str, source: str) -> Optional[Dict]:
    """
    Normalize a single ZAP alert dict into a THRAGG finding.
    Handles both numeric and string risk/confidence values.
    """
    alert_name = alert.get("alert") or alert.get("name")
    if not alert_name:
        return None

    # Resolve risk / severity
    risk_raw = str(alert.get("riskcode", alert.get("riskdesc", "0"))).strip()
    severity = _resolve_risk(risk_raw)

    # Resolve confidence
    conf_raw = str(
        alert.get("confidence", alert.get("confidencedesc", "1"))
    ).strip()
    confidence = _resolve_confidence(conf_raw)

    # CWE and WASC
    cweid  = alert.get("cweid", alert.get("cwe"))
    wascid = alert.get("wascid", alert.get("wasc"))

    # Plugin ID, Alert ID, Tags, Source, OWASP Category
    plugin_id      = alert.get("pluginid", alert.get("pluginId"))
    alert_id       = alert.get("alertid", alert.get("alertId"))
    tags           = alert.get("tags")
    source_id      = alert.get("sourceid", alert.get("sourceId"))
    owasp_category = alert.get("owasp_category")
    input_vector   = alert.get("inputvector", alert.get("inputVector"))

    # Instances
    instances = base_module.ensure_list(alert.get("instances", []))
    instance_details = []
    for inst in instances:
        if isinstance(inst, dict):
            instance_details.append({
                "uri":      inst.get("uri", ""),
                "method":   inst.get("method", ""),
                "param":    inst.get("param", ""),
                "attack":   inst.get("attack", ""),
                "evidence": inst.get("evidence", ""),
            })

    # MITRE mapping
    mitre_id = _resolve_mitre(alert_name)

    # Build rule ID
    if cweid:
        rule_id = f"ZAP-{cweid}"
    elif plugin_id:
        rule_id = f"ZAP-P{plugin_id}"
    else:
        rule_id = f"ZAP-{_slugify(alert_name)}"

    # Build finding using base framework
    conf_label, conf_score, conf_rationale = base_module.compute_confidence(
        "field_present",
    )
    conf_label = confidence

    raw_finding = {
        "rule_id":              rule_id,
        "title":                alert_name,
        "severity":             severity,
        "confidence":           conf_label,
        "confidence_score":     conf_score,
        "confidence_rationale": f"ZAP reported confidence: {conf_raw}",
        "category":             "Web Application Security",
        "asset":                site_name,
        "source":               source,
        "mitre_key":            None,
        "evidence": {
            "description":    alert.get("desc", ""),
            "solution":       alert.get("solution", ""),
            "reference":      alert.get("reference", ""),
            "other_info":     alert.get("other", alert.get("otherinfo", "")),
            "cwe_id":         cweid,
            "wasc_id":        wascid,
            "plugin_id":      plugin_id,
            "alert_id":       alert_id,
            "tags":           tags,
            "source_id":      source_id,
            "owasp_category": owasp_category,
            "input_vector":   input_vector,
            "instances":      instance_details,
            "instance_count": len(instance_details),
        },
        "recommendation": alert.get("solution", "Review and remediate this finding."),
    }

    finding = base_module.normalize_finding(raw_finding, TOOL_NAME)

    finding["risk_score"] = base_module.compute_risk_score(
        severity, conf_label, "application", "moderate",
    )

    if mitre_id:
        finding["mitre"] = {"technique_id": mitre_id}

    return finding


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Risk / Confidence Resolution
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_risk(raw: str) -> str:
    """Resolve ZAP risk code or description to THRAGG severity."""
    if raw in ZAP_RISK_MAP:
        return ZAP_RISK_MAP[raw]

    lower = raw.lower().strip()
    for key, val in ZAP_RISK_MAP.items():
        if key in lower:
            return val

    return "Informational"


def _resolve_confidence(raw: str) -> str:
    """Resolve ZAP confidence code or description to THRAGG confidence."""
    if raw in ZAP_CONFIDENCE_MAP:
        return ZAP_CONFIDENCE_MAP[raw]

    lower = raw.lower().strip()
    for key, val in ZAP_CONFIDENCE_MAP.items():
        if key in lower:
            return val

    return "Medium"


def _resolve_mitre(alert_name: str) -> Optional[str]:
    """Resolve ZAP alert name to MITRE ATT&CK technique ID."""
    name_lower = alert_name.lower()
    for keyword, technique_id in ZAP_MITRE_MAP.items():
        if keyword in name_lower:
            return technique_id
    return None


def _slugify(text: str) -> str:
    """Create a simple slug from alert name for rule ID."""
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower())
    return slug[:40].strip("-")


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Finding Categorization
# ═════════════════════════════════════════════════════════════════════════════

def _categorize_findings(findings: List[Dict], details: Dict) -> None:
    """
    Distribute findings into detail buckets by severity.
    zap.py owns its own categorization.
    """
    severity_bucket_map = {
        "Informational": "informational",
        "Low":           "low",
        "Medium":        "medium",
        "High":          "high",
        "Critical":      "high",
    }

    for finding in findings:
        severity = finding.get("severity", "Informational")
        bucket   = severity_bucket_map.get(severity, "unknown")

        if "web_alerts" in details:
            details["web_alerts"].append(finding)

        if bucket in details:
            details[bucket].append(finding)
        else:
            details["unknown"].append(finding)


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — CLI Helpers (Mode 2)
# ═════════════════════════════════════════════════════════════════════════════

def _locate_zap(
    zap_path: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Locate ZAP executable."""
    if zap_path and os.path.isfile(zap_path):
        return zap_path, None

    candidates = [
        "zap.sh", "zap.bat", "zaproxy",
        "zap-cli", "zap-baseline.py", "zap-full-scan.py",
    ]

    for name in candidates:
        found = shutil.which(name)
        if found:
            return found, None

    return None, (
        "OWASP ZAP not found. Install ZAP or provide path via zap_path parameter."
    )


def _execute_zap_cli(
    zap_bin: str,
    target: str,
    scan_type: str,
    report_path: str,
    report_flag: str,
    timeout: int,
) -> Tuple[bool, Optional[str]]:
    """Execute ZAP scan via CLI."""
    cmd = [zap_bin, "-t", target, report_flag, report_path]

    logger.info("Executing ZAP CLI: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        if os.path.isfile(report_path):
            return True, None
        if result.returncode != 0:
            return False, f"ZAP CLI failed: {result.stderr.strip()}"
        return False, f"ZAP did not generate report at: {report_path}"
    except subprocess.TimeoutExpired:
        return False, f"ZAP scan timed out after {timeout} seconds"
    except Exception as exc:
        return False, f"ZAP CLI execution failed: {exc}"


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — REST API Helpers (Mode 3)
# ═════════════════════════════════════════════════════════════════════════════

def _validate_zap_api(
    base_url: str, api_key: Optional[str],
) -> Tuple[bool, Optional[str]]:
    """Validate ZAP API is reachable."""
    url = f"{base_url}/JSON/core/view/version/"
    if api_key:
        url += f"?apikey={api_key}"

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=REST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        version = data.get("version")
        if version:
            logger.info("ZAP API version: %s", version)
            return True, None
        return False, "ZAP API responded but version not found."
    except urllib.error.URLError as exc:
        return False, f"Cannot reach ZAP API at {base_url}: {exc.reason}"
    except Exception as exc:
        return False, f"Error validating ZAP API: {exc}"


def _execute_zap_api_scan(
    base_url: str,
    api_key: Optional[str],
    target: str,
    scan_type: str,
    report_path: str,
    timeout: int,
) -> Tuple[bool, Optional[str]]:
    """Execute ZAP scan via REST API and collect alerts."""
    api_param = f"&apikey={api_key}" if api_key else ""

    # ── Spider the target ──────────────────────────────────────────────────
    spider_url = (
        f"{base_url}/JSON/spider/action/scan/"
        f"?url={urllib.request.quote(target, safe='')}{api_param}"
    )
    try:
        req = urllib.request.Request(spider_url)
        with urllib.request.urlopen(req, timeout=REST_TIMEOUT) as resp:
            spider_data = json.loads(resp.read().decode("utf-8"))
        spider_id = spider_data.get("scan")
        logger.info("Spider started — scan_id=%s", spider_id)
    except Exception as exc:
        return False, f"Failed to start ZAP spider: {exc}"

    _wait_for_scan(base_url, api_key, "spider", spider_id, timeout)

    # ── Active scan if requested ───────────────────────────────────────────
    if scan_type.lower() in ("active", "full"):
        ascan_url = (
            f"{base_url}/JSON/ascan/action/scan/"
            f"?url={urllib.request.quote(target, safe='')}{api_param}"
        )
        try:
            req = urllib.request.Request(ascan_url)
            with urllib.request.urlopen(req, timeout=REST_TIMEOUT) as resp:
                ascan_data = json.loads(resp.read().decode("utf-8"))
            ascan_id = ascan_data.get("scan")
            logger.info("Active scan started — scan_id=%s", ascan_id)
        except Exception as exc:
            return False, f"Failed to start ZAP active scan: {exc}"

        _wait_for_scan(base_url, api_key, "ascan", ascan_id, timeout)

    # ── Collect alerts ─────────────────────────────────────────────────────
    api_suffix = f"?apikey={api_key}" if api_key else ""
    alerts_url = f"{base_url}/JSON/core/view/alerts/{api_suffix}"
    try:
        req = urllib.request.Request(alerts_url)
        with urllib.request.urlopen(req, timeout=REST_TIMEOUT) as resp:
            alerts_data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return False, f"Failed to collect ZAP alerts: {exc}"

    alerts = alerts_data.get("alerts", [])
    report = {"site": [{"@name": target, "alerts": alerts}]}

    try:
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        return True, None
    except Exception as exc:
        return False, f"Failed to write report: {exc}"


def _wait_for_scan(
    base_url: str,
    api_key: Optional[str],
    scan_type: str,
    scan_id: Optional[str],
    timeout: int,
) -> None:
    """Poll ZAP scan status until complete or timeout."""
    if not scan_id:
        return

    api_param = f"&apikey={api_key}" if api_key else ""
    status_url = (
        f"{base_url}/JSON/{scan_type}/view/status/"
        f"?scanId={scan_id}{api_param}"
    )

    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(status_url)
            with urllib.request.urlopen(req, timeout=REST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            status = data.get("status", "0")
            if int(status) >= 100:
                logger.info("%s scan complete", scan_type)
                return
        except Exception:
            pass
        time.sleep(5)

    logger.warning("%s scan did not complete within %ds", scan_type, timeout)


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
    errors: List[str], new_error: str, input_path: str,
) -> Dict:
    """Return a failed THRAGG contract when execution cannot begin."""
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
        "  python zap.py run <report_path_or_folder>\n"
        "  python zap.py cli <target_url> [output_dir] [report_format]\n"
        "  python zap.py api <target_url> [zap_base_url] [api_key]\n"
    )

    if len(sys.argv) < 3:
        print(_USAGE)
        sys.exit(1)

    mode = sys.argv[1].lower()
    arg2 = sys.argv[2]

    if mode == "run":
        _result = run(arg2)
    elif mode == "cli":
        _out = sys.argv[3] if len(sys.argv) > 3 else "thragg_results/zap_cli"
        _fmt = sys.argv[4] if len(sys.argv) > 4 else "json"
        _result = run_cli(target=arg2, output_dir=_out, report_format=_fmt)
    elif mode == "api":
        _url = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:8080"
        _key = sys.argv[4] if len(sys.argv) > 4 else None
        _result = run_api(target=arg2, zap_base_url=_url, api_key=_key)
    else:
        print(f"Unknown mode: {mode}\n{_USAGE}")
        sys.exit(1)

    print(json.dumps(_result, indent=2, default=str))
