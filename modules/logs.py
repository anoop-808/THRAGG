"""
THRAGG Module: logs
Version: 1.1.0

Public API:
    run(input_path, profile="all")                    -> Mode 1  Evidence Ingestion
    run_cli(output_dir, profile="all")                -> Mode 2  Local log collection → run()
    run_api(endpoint, output_dir, profile="all",
            token=None, headers=None, params=None,
            paginate=True, max_pages=50)              -> Mode 3  Remote API collection → run()

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
    Every parser normalizes logs into a common event schema BEFORE analysis.
    Detection rules NEVER inspect raw log lines.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from modules import base as base_module

# ─────────────────────────────────────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger("thragg.logs")

# ─────────────────────────────────────────────────────────────────────────────
# Module Constants
# ─────────────────────────────────────────────────────────────────────────────

MODULE_NAME    = "logs"
MODULE_VERSION = "1.1.0"
TOOL_NAME      = "Log Analysis"
SUPPORTED_FORMATS = frozenset({".log", ".txt", ".json", ".gz"})

# ─────────────────────────────────────────────────────────────────────────────
# Timeout Constants
# ─────────────────────────────────────────────────────────────────────────────

CLI_TIMEOUT  = 120
REST_TIMEOUT = 60
AUTH_TIMEOUT = 30
REST_RETRIES = 2
REST_RETRY_DELAY = 1

# ─────────────────────────────────────────────────────────────────────────────
# Detection Thresholds
# ─────────────────────────────────────────────────────────────────────────────

FAILED_LOGIN_THRESHOLD = 5
SUDO_FAILURE_THRESHOLD = 3

# ─────────────────────────────────────────────────────────────────────────────
# API Pagination Defaults
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_MAX_PAGES = 50

# ─────────────────────────────────────────────────────────────────────────────
# Collection Profiles
# ─────────────────────────────────────────────────────────────────────────────

COLLECTION_PROFILES: Dict[str, List[str]] = {
    "all":            ["auth", "syslog", "secure", "messages", "journal"],
    "authentication": ["auth", "secure"],
    "ssh":            ["auth", "secure"],
    "sudo":           ["auth", "secure"],
    "system":         ["syslog", "messages", "journal"],
    "security":       ["auth", "secure", "syslog"],
}

# ─────────────────────────────────────────────────────────────────────────────
# CLI Collection Command Table
# ─────────────────────────────────────────────────────────────────────────────

CLI_COMMANDS: Dict[str, Tuple[List[str], str]] = {
    "auth":     (["cat", "/var/log/auth.log"],                         "auth.log"),
    "syslog":   (["cat", "/var/log/syslog"],                           "syslog.log"),
    "secure":   (["cat", "/var/log/secure"],                           "secure.log"),
    "messages": (["cat", "/var/log/messages"],                         "messages.log"),
    "journal":  (["journalctl", "--no-pager", "--output", "short-iso"], "journal.log"),
}

# ─────────────────────────────────────────────────────────────────────────────
# Log Type → Filename Hint Map
# ─────────────────────────────────────────────────────────────────────────────

FILENAME_LOG_TYPE_MAP: Dict[str, str] = {
    "auth":     "auth",
    "secure":   "secure",
    "syslog":   "syslog",
    "messages": "messages",
    "journal":  "journal",
    "kern":     "syslog",
    "daemon":   "syslog",
    "user":     "syslog",
}

# ─────────────────────────────────────────────────────────────────────────────
# Rule → MITRE Mapping (centralized)
# ─────────────────────────────────────────────────────────────────────────────

RULE_MITRE: Dict[str, str] = {
    "LOG-AUTH-001": "valid_accounts",
    "LOG-AUTH-002": "valid_accounts",
    "LOG-AUTH-003": "account_discovery",
    "LOG-AUTH-004": "modify_auth",
    "LOG-PRIV-001": "privilege_escalation",
    "LOG-PRIV-002": "privilege_escalation",
    "LOG-PRIV-003": "privilege_escalation",
    "LOG-SESS-001": "valid_accounts",
    "LOG-SYS-001":  "valid_accounts",
    "LOG-SYS-002":  "valid_accounts",
    "LOG-NET-001":  "valid_accounts",
}

# ─────────────────────────────────────────────────────────────────────────────
# Syslog Month Mapping (for timestamp normalization)
# ─────────────────────────────────────────────────────────────────────────────

_SYSLOG_MONTHS: Dict[str, int] = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# ─────────────────────────────────────────────────────────────────────────────
# Compiled Regex Patterns
# ─────────────────────────────────────────────────────────────────────────────

_SYSLOG_RE = re.compile(
    r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

_JOURNAL_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_USER_PATTERNS = [
    re.compile(r"\bfor\s+(?:invalid\s+user\s+)?(\S+)\b"),
    re.compile(r"\bfor\s+user\s+(\S+)\b"),
    re.compile(r"\buser=(\S+)\b"),
    re.compile(r"\bUSER=(\S+)\b"),
    re.compile(r"\bby\s+(\S+)\b"),
]


# ═════════════════════════════════════════════════════════════════════════════
# MODE 1 — Evidence Ingestion & Analysis  (THE BRAIN)
# ═════════════════════════════════════════════════════════════════════════════

def run(
    input_path: str,
    profile: str = "all",
) -> Dict:
    """
    Mode 1 — Accept a path to one log file or a folder of log exports.
    Auto-detect log type, parse, normalize, analyze, summarize, and
    return the THRAGG contract.
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

    if not files:
        metadata["execution_time"] = round(time.time() - start_time, 4)
        return {
            "metadata":  metadata,
            "summary":   {"total_findings": 0},
            "details":   {},
            "artifacts": {"input_path": input_path},
            "errors":    errors,
        }

    # ── Initialise detail buckets and event store ──────────────────────────
    details = base_module.build_empty_details(
        "authentication", "privilege", "network",
        "session", "service", "cron", "unknown",
    )

    all_events:   List[Dict] = []
    all_findings: List[Dict] = []
    files_processed = 0
    log_type_counts: Dict[str, int] = {}

    # ── Parse each log file ────────────────────────────────────────────────
    for filepath in files:
        log_type = _detect_log_type(filepath)
        log_type_counts[log_type] = log_type_counts.get(log_type, 0) + 1
        logger.debug("Detected log type '%s' for %s", log_type, filepath)

        events, parse_errs = _parse_log_file(filepath, log_type)
        errors.extend(parse_errs)
        all_events.extend(events)
        files_processed += 1

    pipeline.add(f"parse: {files_processed} files, {len(all_events)} events")

    # ── Run rule engine against normalized events ──────────────────────────
    findings, analysis_errs = _run_rule_engine(all_events)
    errors.extend(analysis_errs)
    all_findings.extend(findings)

    pipeline.add(f"analyze: {len(all_findings)} findings")

    # ── Categorize findings ────────────────────────────────────────────────
    _categorize_findings(all_findings, details)

    # ── Summary ────────────────────────────────────────────────────────────
    rule_stats = base_module.build_rule_statistics(all_findings)

    event_summary = _build_event_summary(all_events)
    extra_summary = {
        "files_processed": files_processed,
        "profile":         profile,
        "log_type_counts": log_type_counts,
        "total_events":    len(all_events),
        **event_summary,
    }

    summary = base_module.build_summary(
        all_findings, rule_stats=rule_stats, extra_summary=extra_summary,
    )
    pipeline.add("summary")

    # ── Finalize metadata ──────────────────────────────────────────────────
    metadata["files_processed"]  = files_processed
    metadata["rule_statistics"]  = rule_stats
    metadata["log_type_counts"]  = log_type_counts
    base_module.finalize_metadata(metadata, time.time() - start_time, pipeline)

    logger.info(
        "Mode 1 complete — %d events, %d findings in %.4fs",
        len(all_events), len(all_findings), metadata["execution_time"],
    )

    return {
        "metadata":  metadata,
        "summary":   summary,
        "details":   details,
        "artifacts": {"input_path": input_path, "files": files},
        "errors":    errors,
    }


# ═════════════════════════════════════════════════════════════════════════════
# MODE 2 — Local CLI Log Collection
# ═════════════════════════════════════════════════════════════════════════════

def run_cli(
    output_dir: str = "thragg_results/logs_cli",
    profile: str = "all",
) -> Dict:
    """
    Mode 2 — Collect logs from the local machine via CLI commands,
    write log files to output_dir, then hand off to run().
    Mode 2 performs NO analysis.
    """
    errors: List[str] = []
    collection_status: Dict[str, str] = {}

    logger.info(
        "Mode 2 (CLI) started — output_dir=%s  profile=%s", output_dir, profile,
    )

    # ── Validate OS ────────────────────────────────────────────────────────
    os_ok, os_err = _validate_operating_system()
    if not os_ok:
        return _early_failure(errors, os_err, output_dir, profile)

    # ── Prepare output directory ───────────────────────────────────────────
    dir_ok, dir_err = _ensure_output_directory(output_dir)
    if not dir_ok:
        return _early_failure(errors, dir_err, output_dir, profile)

    # ── Collect log sources ────────────────────────────────────────────────
    sources = COLLECTION_PROFILES.get(profile, COLLECTION_PROFILES["all"])

    for source_key in sources:
        cmd_spec = CLI_COMMANDS.get(source_key)
        if not cmd_spec:
            collection_status[source_key] = "SKIPPED"
            errors.append(f"No CLI command for log source: {source_key}")
            continue

        cmd, filename = cmd_spec
        output_path = os.path.join(output_dir, filename)

        logger.info("Collecting %s ...", source_key)
        success, cmd_err = _execute_cli_command(cmd, output_path)

        if success:
            collection_status[source_key] = "SUCCESS"
            logger.info("  %s — SUCCESS", source_key)
        else:
            collection_status[source_key] = "SKIPPED"
            logger.warning("  %s — SKIPPED: %s", source_key, cmd_err)

    # ── Hand off to Mode 1 ─────────────────────────────────────────────────
    result = run(output_dir, profile=profile)
    result["errors"] = errors + result["errors"]
    result["artifacts"]["collection_status"] = collection_status

    logger.info("Mode 2 complete — collection_status=%s", collection_status)
    return result


# ═════════════════════════════════════════════════════════════════════════════
# MODE 3 — Remote REST API Log Collection
# ═════════════════════════════════════════════════════════════════════════════

def run_api(
    endpoint: str,
    output_dir: str = "thragg_results/logs_api",
    profile: str = "all",
    token: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    paginate: bool = True,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> Dict:
    """
    Mode 3 — Download logs from a remote REST endpoint, save to output_dir,
    then hand off to run(). Mode 3 performs NO analysis.

    Generic: works with Splunk, Elastic, Sentinel, or any REST endpoint.

    Supports automatic pagination via:
        - next_page / nextLink / cursor / continuation_token / scroll_id
        - offset-based pagination
    """
    errors: List[str] = []
    download_status: Dict[str, str] = {}

    logger.info(
        "Mode 3 (API) started — endpoint=%s  profile=%s  paginate=%s",
        endpoint, profile, paginate,
    )

    # ── Prepare output directory ───────────────────────────────────────────
    dir_ok, dir_err = _ensure_output_directory(output_dir)
    if not dir_ok:
        return _early_failure(errors, dir_err, output_dir, profile)

    # ── Build request headers ──────────────────────────────────────────────
    request_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    if headers:
        request_headers.update(headers)

    # ── Download log data ──────────────────────────────────────────────────
    output_path = os.path.join(output_dir, "api_logs.json")

    logger.info("Downloading logs from %s ...", endpoint)

    if paginate:
        success, dl_err, pages_fetched = _download_paginated(
            endpoint, request_headers, params, output_path, max_pages,
        )
    else:
        success, dl_err = _download_single_page(
            endpoint, request_headers, params, output_path,
        )
        pages_fetched = 1 if success else 0

    if success:
        download_status["api_logs"] = "SUCCESS"
        download_status["pages_fetched"] = str(pages_fetched)
        logger.info("  api_logs — SUCCESS (%d pages)", pages_fetched)
    else:
        download_status["api_logs"] = "FAILED"
        errors.append(f"API log download failed: {dl_err}")
        logger.warning("  api_logs — FAILED: %s", dl_err)
        return _early_failure(errors, dl_err, output_dir, profile)

    # ── Hand off to Mode 1 ─────────────────────────────────────────────────
    result = run(output_dir, profile=profile)
    result["errors"] = errors + result["errors"]
    result["artifacts"]["download_status"] = download_status
    result["artifacts"]["endpoint"]        = endpoint
    result["artifacts"]["pages_fetched"]   = pages_fetched

    logger.info("Mode 3 complete — download_status=%s", download_status)
    return result


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Log Type Detection
# ═════════════════════════════════════════════════════════════════════════════

def _detect_log_type(filepath: str) -> str:
    """
    Detect log type from filename then content.
    Handles .gz files by stripping the compression extension first.
    """
    basename = os.path.basename(filepath).lower()

    # Strip .gz to get the actual log name
    if basename.endswith(".gz"):
        basename = basename[:-3]

    stem = os.path.splitext(basename)[0]
    ext  = os.path.splitext(basename)[1]

    # Filename-based detection
    for hint, log_type in FILENAME_LOG_TYPE_MAP.items():
        if hint in stem:
            return log_type

    if ext == ".json":
        return "json"

    # Content-based fallback
    try:
        lines = _read_head_lines(filepath, 3)
    except Exception:
        return "unknown"

    combined = " ".join(lines).lower()

    stripped = combined.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"

    if re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", combined):
        return "journal"

    if any(kw in combined for kw in ("sshd", "sudo", "pam_", "login", "auth")):
        return "auth"

    if any(kw in combined for kw in ("kernel:", "systemd:", "dbus")):
        return "syslog"

    return "unknown"


def _read_head_lines(filepath: str, count: int) -> List[str]:
    """Read the first N lines from a file, handling .gz transparently."""
    ext = os.path.splitext(filepath)[1].lower()

    if ext == ".gz":
        with gzip.open(filepath, "rt", encoding="utf-8", errors="ignore") as fh:
            return [fh.readline() for _ in range(count)]

    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
        return [fh.readline() for _ in range(count)]


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — File Reading (gzip-aware)
# ═════════════════════════════════════════════════════════════════════════════

def _read_lines(filepath: str) -> Tuple[List[str], Optional[str]]:
    """
    Read all lines from a text log file.
    Transparently handles .gz compressed files.
    """
    ext = os.path.splitext(filepath)[1].lower()

    try:
        if ext == ".gz":
            with gzip.open(filepath, "rt", encoding="utf-8", errors="ignore") as fh:
                return fh.readlines(), None
        else:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                return fh.readlines(), None
    except PermissionError:
        return [], f"Permission denied reading: {filepath}"
    except Exception as exc:
        return [], f"Could not read {filepath}: {exc}"


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Timestamp Normalization
# ═════════════════════════════════════════════════════════════════════════════

def _normalize_timestamp(raw_ts: str) -> str:
    """
    Normalize any timestamp format to ISO 8601 (YYYY-MM-DDTHH:MM:SSZ).

    Handles:
        - Syslog:    "Jul  1 13:20:44"       → "2025-07-01T13:20:44Z"
        - Journald:  "2025-07-01T13:20:44+00:00" → "2025-07-01T13:20:44Z"
        - ISO 8601:  "2025-07-01T13:20:44Z"  → pass through
        - Epoch:     "1719835244"             → "2025-07-01T13:20:44Z"
    """
    if not raw_ts or not raw_ts.strip():
        return ""

    raw_ts = raw_ts.strip()

    # Already ISO 8601 with Z
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", raw_ts):
        return raw_ts

    # ISO 8601 with timezone offset: "2025-07-01T13:20:44+00:00"
    iso_match = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", raw_ts,
    )
    if iso_match:
        return iso_match.group(1) + "Z"

    # Syslog format: "Jul  1 13:20:44" or "Jul 15 13:20:44"
    syslog_match = re.match(
        r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$", raw_ts,
    )
    if syslog_match:
        month_str, day_str, time_str = syslog_match.groups()
        month = _SYSLOG_MONTHS.get(month_str.lower())
        if month:
            year = datetime.now(timezone.utc).year
            day  = int(day_str)
            return f"{year}-{month:02d}-{day:02d}T{time_str}Z"

    # Epoch timestamp (integer or float)
    if re.match(r"^\d{10,13}(\.\d+)?$", raw_ts):
        try:
            epoch = float(raw_ts)
            if epoch > 1e12:
                epoch /= 1000  # millisecond epoch
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OSError):
            pass

    # Could not normalize — return original
    return raw_ts


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Log Parsers
# ═════════════════════════════════════════════════════════════════════════════

def _parse_log_file(
    filepath: str, log_type: str,
) -> Tuple[List[Dict], List[str]]:
    """Dispatch to the correct parser."""
    parser = _LOG_PARSERS.get(log_type, _parse_unknown_log)
    try:
        events, errs = parser(filepath)
        return events, errs
    except Exception as exc:
        logger.exception("Parser error [%s] for %s", log_type, filepath)
        return [], [f"Parser error [{log_type}] for {filepath}: {exc}"]


# ─────────────────────────────────────────────────────────────────────────────
# Syslog Line Parser (shared)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_syslog_line(line: str) -> Optional[Dict]:
    """Parse a single syslog-family line into a partial event dict."""
    line = line.rstrip("\n")
    match = _SYSLOG_RE.match(line)
    if not match:
        return None

    m = match.groupdict()
    process = m["process"]
    if m.get("pid"):
        process = f"{process}[{m['pid']}]"

    raw_ts = f"{m['month']} {m['day']} {m['time']}"

    return {
        "timestamp": _normalize_timestamp(raw_ts),
        "hostname":  m["hostname"],
        "process":   process,
        "message":   m["message"].strip(),
        "raw":       line,
    }


def _parse_journal_line(line: str) -> Optional[Dict]:
    """Parse a single journald ISO-format line."""
    line = line.rstrip("\n")
    match = _JOURNAL_RE.match(line)
    if not match:
        return None

    m = match.groupdict()
    process = m["process"]
    if m.get("pid"):
        process = f"{process}[{m['pid']}]"

    return {
        "timestamp": _normalize_timestamp(m["timestamp"]),
        "hostname":  m["hostname"],
        "process":   process,
        "message":   m["message"].strip(),
        "raw":       line,
    }


def _classify_syslog_event(partial: Dict) -> Dict:
    """
    Classify a partially-parsed syslog event into a normalized event.
    Inspects ONLY the normalized 'message' field — never the raw line.
    """
    msg = partial.get("message", "").lower()

    username  = _extract_username(msg)
    source_ip = _extract_ip(msg)

    if "failed password" in msg or "authentication failure" in msg:
        event_type = "failed_login"
        severity   = "Medium"
    elif "accepted password" in msg or "accepted publickey" in msg:
        event_type = "success_login"
        severity   = "Low"
    elif "invalid user" in msg:
        event_type = "invalid_user"
        severity   = "Medium"
    elif "sudo" in msg and "incorrect password" in msg:
        event_type = "sudo"
        severity   = "Medium"
    elif "sudo" in msg and ("command" in msg or "session" in msg):
        event_type = "sudo"
        severity   = "Low"
    elif "session opened" in msg:
        event_type = "session_open"
        severity   = "Informational"
    elif "session closed" in msg:
        event_type = "session_close"
        severity   = "Informational"
    elif "cron" in partial.get("process", "").lower():
        event_type = "cron"
        severity   = "Informational"
    elif any(kw in msg for kw in ("error", "failed", "failure")):
        event_type = "authentication"
        severity   = "Low"
    else:
        event_type = "unknown"
        severity   = "Informational"

    return {
        **partial,
        "event_id":   str(uuid.uuid4()),
        "event_type": event_type,
        "username":   username,
        "source_ip":  source_ip,
        "severity":   severity,
        "source":     partial.get("hostname", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Individual Parsers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_auth_log(filepath: str) -> Tuple[List[Dict], List[str]]:
    """Parse /var/log/auth.log format."""
    lines, err = _read_lines(filepath)
    if err:
        return [], [err]

    events: List[Dict] = []
    for line in lines:
        partial = _parse_syslog_line(line)
        if partial:
            events.append(_classify_syslog_event(partial))

    return events, []


def _parse_secure_log(filepath: str) -> Tuple[List[Dict], List[str]]:
    """Parse /var/log/secure (RHEL/CentOS)."""
    return _parse_auth_log(filepath)


def _parse_syslog_file(filepath: str) -> Tuple[List[Dict], List[str]]:
    """Parse /var/log/syslog."""
    lines, err = _read_lines(filepath)
    if err:
        return [], [err]

    events: List[Dict] = []
    for line in lines:
        partial = _parse_syslog_line(line)
        if partial:
            events.append(_classify_syslog_event(partial))

    return events, []


def _parse_messages_log(filepath: str) -> Tuple[List[Dict], List[str]]:
    """Parse /var/log/messages."""
    return _parse_syslog_file(filepath)


def _parse_journal_export(filepath: str) -> Tuple[List[Dict], List[str]]:
    """Parse journalctl --output short-iso export."""
    lines, err = _read_lines(filepath)
    if err:
        return [], [err]

    events: List[Dict] = []
    for line in lines:
        partial = _parse_journal_line(line)
        if partial:
            events.append(_classify_syslog_event(partial))
        else:
            partial = _parse_syslog_line(line)
            if partial:
                events.append(_classify_syslog_event(partial))

    return events, []


def _parse_json_log(filepath: str) -> Tuple[List[Dict], List[str]]:
    """
    Parse JSON log exports.

    Accepts:
        - JSON array: [{...}, {...}]
        - Wrapped object: {"logs": [...]}
        - NDJSON: one JSON object per line
    """
    ext = os.path.splitext(filepath)[1].lower()

    try:
        if ext == ".gz":
            with gzip.open(filepath, "rt", encoding="utf-8", errors="ignore") as fh:
                raw = fh.read().strip()
        else:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                raw = fh.read().strip()
    except Exception as exc:
        return [], [f"Could not read JSON log {filepath}: {exc}"]

    if not raw:
        return [], [f"JSON log is empty: {filepath}"]

    # Try standard JSON
    try:
        data = json.loads(raw)
        records = _extract_json_records(data)
    except json.JSONDecodeError:
        # Try NDJSON
        records = []
        parse_errors: List[str] = []
        for line_num, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                parse_errors.append(
                    f"Malformed JSON line {line_num} in {filepath}: {exc}"
                )
        if not records:
            return [], [f"Could not parse JSON log {filepath}"]

    events = [_normalize_json_record(r) for r in records if isinstance(r, dict)]
    return events, []


def _extract_json_records(data: Any) -> List[Dict]:
    """Extract a list of log records from various JSON shapes."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("logs", "events", "records", "hits", "results", "data", "value"):
            if key in data and isinstance(data[key], list):
                return data[key]
        return [data]
    return []


def _normalize_json_record(record: Dict) -> Dict:
    """Normalize a JSON log record into the common event schema."""
    raw_ts = (
        record.get("timestamp")
        or record.get("@timestamp")
        or record.get("time")
        or record.get("eventTime")
        or record.get("created")
        or ""
    )

    hostname = (
        record.get("hostname")
        or record.get("host")
        or record.get("computer")
        or record.get("source_host")
        or ""
    )

    process = (
        record.get("process")
        or record.get("program")
        or record.get("app")
        or record.get("application")
        or ""
    )

    message = (
        record.get("message")
        or record.get("msg")
        or record.get("event_message")
        or record.get("description")
        or record.get("raw_message")
        or ""
    )

    username = _normalize_username_value(
        record.get("username")
        or record.get("user")
        or record.get("account")
        or record.get("subject_user_name")
        or ""
    )

    source_ip = (
        record.get("source_ip")
        or record.get("src_ip")
        or record.get("client_ip")
        or record.get("remote_addr")
        or record.get("ip_address")
        or _extract_ip(message)
        or ""
    )

    severity_raw = (
        record.get("severity")
        or record.get("level")
        or record.get("priority")
        or "informational"
    )
    severity = _normalize_severity(str(severity_raw))

    partial = {
        "timestamp": _normalize_timestamp(str(raw_ts)),
        "hostname":  hostname,
        "process":   process,
        "message":   message,
        "raw":       json.dumps(record, default=str),
    }

    classified = _classify_syslog_event(partial)

    classified["username"]  = username  or classified.get("username", "")
    classified["source_ip"] = source_ip or classified.get("source_ip", "")
    classified["severity"]  = severity  if severity != "Informational" else classified.get("severity", "Informational")
    classified["source"]    = hostname  or classified.get("source", "")

    return classified


def _normalize_username_value(value: Any) -> str:
    """Convert common JSON user shapes into the event schema username string."""
    if value is None:
        return ""

    if isinstance(value, dict):
        for key in ("username", "userPrincipalName", "name", "displayName", "id"):
            nested = value.get(key)
            if nested:
                return str(nested)
        return ""

    return str(value)


def _parse_unknown_log(filepath: str) -> Tuple[List[Dict], List[str]]:
    """Fallback parser for unknown log formats."""
    lines, err = _read_lines(filepath)
    if err:
        return [], [err]

    events: List[Dict] = []
    for line in lines:
        partial = _parse_syslog_line(line) or _parse_journal_line(line)
        if partial:
            events.append(_classify_syslog_event(partial))

    if not events:
        return [], [f"Could not parse unknown log format: {filepath}"]

    return events, []


# ─────────────────────────────────────────────────────────────────────────────
# Module-Scope Parser Dispatch Table
# ─────────────────────────────────────────────────────────────────────────────

_LOG_PARSERS: Dict[str, Callable] = {
    "auth":     _parse_auth_log,
    "secure":   _parse_secure_log,
    "syslog":   _parse_syslog_file,
    "messages": _parse_messages_log,
    "journal":  _parse_journal_export,
    "json":     _parse_json_log,
    "unknown":  _parse_unknown_log,
}


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Detection Rule Engine
# ═════════════════════════════════════════════════════════════════════════════

# Rule registry — registered at module scope
RULES: List[Callable] = []


def _run_rule_engine(
    events: List[Dict],
) -> Tuple[List[Dict], List[str]]:
    """
    Run all registered detection rules against normalized events.
    Rules NEVER inspect raw log lines. They only inspect event fields.
    """
    all_findings: List[Dict] = []
    errors: List[str]        = []

    for rule in RULES:
        try:
            findings = rule(events)
            all_findings.extend(findings)
        except Exception as exc:
            logger.exception("Rule engine error in %s", rule.__name__)
            errors.append(f"Rule engine error [{rule.__name__}]: {exc}")

    return all_findings, errors


def _make_finding(
    rule_id: str,
    title: str,
    severity: str,
    confidence_signal: str,
    category: str,
    asset: str,
    evidence: Dict,
    recommendation: str,
    exposure_key: str = "user",
    exploitability_key: str = "moderate",
    signals: Optional[Dict[str, bool]] = None,
) -> Dict:
    """Central finding factory for all log analyzers."""
    mitre_key = RULE_MITRE.get(rule_id, "valid_accounts")

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
        "source":               asset,
        "evidence":             evidence,
        "recommendation":       recommendation,
    }
    finding = base_module.normalize_finding(raw, TOOL_NAME)
    finding["risk_score"] = base_module.compute_risk_score(
        severity, conf_label, exposure_key, exploitability_key,
    )
    finding["finding_id"] = str(uuid.uuid4())
    return finding


# ─────────────────────────────────────────────────────────────────────────────
# Analyzers
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_failed_logins(events: List[Dict]) -> List[Dict]:
    """Detect brute-force: multiple failed logins from the same IP."""
    findings: List[Dict] = []

    failed = [
        e for e in events
        if e.get("event_type") == "failed_login" and e.get("source_ip")
    ]

    by_ip: Dict[str, List[Dict]] = {}
    for event in failed:
        by_ip.setdefault(event["source_ip"], []).append(event)

    for ip, ip_events in by_ip.items():
        if len(ip_events) >= FAILED_LOGIN_THRESHOLD:
            usernames = list({e.get("username", "") for e in ip_events})
            hostnames = list({e.get("hostname", "") for e in ip_events})
            host      = hostnames[0] if hostnames else ip

            findings.append(_make_finding(
                rule_id="LOG-AUTH-001",
                title=f"Brute-Force Login Attempt from {ip}",
                severity="High",
                confidence_signal="threshold_exceeded",
                category="Authentication",
                asset=host,
                evidence={
                    "source_ip":     ip,
                    "attempt_count": len(ip_events),
                    "usernames":     usernames,
                    "threshold":     FAILED_LOGIN_THRESHOLD,
                },
                recommendation=(
                    "Block the source IP. Investigate account lockout status. "
                    "Enable fail2ban or equivalent rate-limiting."
                ),
                exploitability_key="trivial",
            ))

    return findings


def _analyze_successful_logins(events: List[Dict]) -> List[Dict]:
    """Flag successful logins for visibility."""
    findings: List[Dict] = []

    success_events = [
        e for e in events if e.get("event_type") == "success_login"
    ]

    seen: set = set()
    for event in success_events:
        username  = event.get("username", "unknown")
        source_ip = event.get("source_ip", "unknown")
        host      = event.get("hostname", "unknown")
        key       = (username, source_ip, host)

        if key in seen:
            continue
        seen.add(key)

        findings.append(_make_finding(
            rule_id="LOG-AUTH-002",
            title=f"Successful Login: {username} from {source_ip}",
            severity="Informational",
            confidence_signal="field_present",
            category="Authentication",
            asset=host,
            evidence={
                "username":  username,
                "source_ip": source_ip,
                "timestamp": event.get("timestamp"),
            },
            recommendation="Verify this login was expected and authorized.",
            exploitability_key="contextual",
        ))

    return findings


def _analyze_invalid_users(events: List[Dict]) -> List[Dict]:
    """Detect login attempts for non-existent users."""
    findings: List[Dict] = []

    invalid = [
        e for e in events if e.get("event_type") == "invalid_user"
    ]

    by_ip: Dict[str, List[Dict]] = {}
    for event in invalid:
        ip = event.get("source_ip", "unknown")
        by_ip.setdefault(ip, []).append(event)

    for ip, ip_events in by_ip.items():
        usernames = list({e.get("username", "") for e in ip_events})
        hostnames = list({e.get("hostname", "") for e in ip_events})
        host      = hostnames[0] if hostnames else ip
        severity  = "High" if len(ip_events) >= 3 else "Medium"

        findings.append(_make_finding(
            rule_id="LOG-AUTH-003",
            title=f"Invalid User Login Attempt from {ip}",
            severity=severity,
            confidence_signal="field_present",
            category="Authentication",
            asset=host,
            evidence={
                "source_ip":       ip,
                "attempt_count":   len(ip_events),
                "usernames_tried": usernames,
            },
            recommendation=(
                "Investigate whether this represents account enumeration. "
                "Consider blocking the source IP."
            ),
        ))

    return findings


def _analyze_sudo(events: List[Dict]) -> List[Dict]:
    """Detect sudo failures and privilege escalation via sudo."""
    findings: List[Dict] = []

    sudo_events = [e for e in events if e.get("event_type") == "sudo"]

    # Failures
    failures = [
        e for e in sudo_events
        if "incorrect" in e.get("message", "").lower()
        or "failed" in e.get("message", "").lower()
    ]

    by_user: Dict[str, List[Dict]] = {}
    for event in failures:
        user = event.get("username", "unknown")
        by_user.setdefault(user, []).append(event)

    for user, user_events in by_user.items():
        host = user_events[0].get("hostname", "unknown")
        if len(user_events) >= SUDO_FAILURE_THRESHOLD:
            findings.append(_make_finding(
                rule_id="LOG-PRIV-001",
                title=f"Repeated Sudo Failures by {user}",
                severity="High",
                confidence_signal="threshold_exceeded",
                category="Privilege",
                asset=host,
                evidence={
                    "username":      user,
                    "failure_count": len(user_events),
                    "threshold":     SUDO_FAILURE_THRESHOLD,
                },
                recommendation=(
                    "Investigate why this user is repeatedly failing sudo. "
                    "Review sudoers configuration."
                ),
            ))

    # Successes
    successes = [
        e for e in sudo_events
        if "incorrect" not in e.get("message", "").lower()
        and "failed" not in e.get("message", "").lower()
        and "COMMAND" in e.get("raw", "")
    ]

    seen_cmds: set = set()
    for event in successes:
        user    = event.get("username", "unknown")
        host    = event.get("hostname", "unknown")
        message = event.get("message", "")
        cmd_key = (user, host, message[:50])

        if cmd_key in seen_cmds:
            continue
        seen_cmds.add(cmd_key)

        findings.append(_make_finding(
            rule_id="LOG-PRIV-002",
            title=f"Sudo Command Executed by {user}",
            severity="Low",
            confidence_signal="field_present",
            category="Privilege",
            asset=host,
            evidence={
                "username":  user,
                "timestamp": event.get("timestamp"),
                "message":   message[:200],
            },
            recommendation="Verify sudo command is authorized and expected.",
            exploitability_key="contextual",
        ))

    return findings


def _analyze_cron(events: List[Dict]) -> List[Dict]:
    """Flag cron activity."""
    findings: List[Dict] = []
    cron_events = [e for e in events if e.get("event_type") == "cron"]

    seen: set = set()
    for event in cron_events:
        user    = event.get("username", "unknown")
        host    = event.get("hostname", "unknown")
        message = event.get("message", "")
        key     = (user, host, message[:60])

        if key in seen:
            continue
        seen.add(key)

        findings.append(_make_finding(
            rule_id="LOG-SYS-001",
            title=f"Cron Job Executed by {user}",
            severity="Informational",
            confidence_signal="field_present",
            category="Service",
            asset=host,
            evidence={
                "username":  user,
                "timestamp": event.get("timestamp"),
                "message":   message[:200],
            },
            recommendation="Audit scheduled cron jobs for unexpected entries.",
            exploitability_key="contextual",
        ))

    return findings


def _analyze_sessions(events: List[Dict]) -> List[Dict]:
    """Track session opens."""
    findings: List[Dict] = []

    opens = [e for e in events if e.get("event_type") == "session_open"]

    seen: set = set()
    for event in opens:
        user = event.get("username", "unknown")
        host = event.get("hostname", "unknown")
        ip   = event.get("source_ip", "")
        key  = (user, host, ip)

        if key in seen:
            continue
        seen.add(key)

        severity = "Medium" if user in ("root",) else "Informational"

        findings.append(_make_finding(
            rule_id="LOG-SESS-001",
            title=f"Session Opened: {user} on {host}",
            severity=severity,
            confidence_signal="field_present",
            category="Authentication",
            asset=host,
            evidence={
                "username":  user,
                "source_ip": ip,
                "timestamp": event.get("timestamp"),
            },
            recommendation="Verify this session was expected and authorized.",
            exploitability_key="contextual",
        ))

    return findings


def _analyze_authentication(events: List[Dict]) -> List[Dict]:
    """Detect PAM authentication failures not covered by other rules."""
    findings: List[Dict] = []

    auth_events = [
        e for e in events
        if e.get("event_type") == "authentication"
        and "failure" in e.get("message", "").lower()
    ]

    by_user: Dict[str, List[Dict]] = {}
    for event in auth_events:
        user = event.get("username", "unknown")
        by_user.setdefault(user, []).append(event)

    for user, user_events in by_user.items():
        if len(user_events) < 3:
            continue
        host = user_events[0].get("hostname", "unknown")

        findings.append(_make_finding(
            rule_id="LOG-AUTH-004",
            title=f"Repeated Authentication Failures for {user}",
            severity="Medium",
            confidence_signal="threshold_exceeded",
            category="Authentication",
            asset=host,
            evidence={
                "username":      user,
                "failure_count": len(user_events),
            },
            recommendation=(
                "Investigate repeated authentication failures. "
                "Verify account is not under attack."
            ),
        ))

    return findings


def _analyze_privilege_escalation(events: List[Dict]) -> List[Dict]:
    """Detect privilege escalation indicators beyond sudo."""
    findings: List[Dict] = []

    for event in events:
        msg     = event.get("message", "").lower()
        process = event.get("process", "").lower()

        if "su" in process and "root" in msg:
            user = event.get("username", "unknown")
            host = event.get("hostname", "unknown")

            findings.append(_make_finding(
                rule_id="LOG-PRIV-003",
                title=f"Privilege Escalation via su: {user}",
                severity="High",
                confidence_signal="pattern_match",
                category="Privilege",
                asset=host,
                evidence={
                    "username":  user,
                    "timestamp": event.get("timestamp"),
                    "message":   event.get("message", "")[:200],
                },
                recommendation=(
                    "Investigate su usage. Prefer sudo with specific command "
                    "restrictions over su to root."
                ),
            ))

    return findings


def _analyze_network_events(events: List[Dict]) -> List[Dict]:
    """Flag unusual network-related log events."""
    findings: List[Dict] = []

    for event in events:
        msg = event.get("message", "").lower()

        if any(kw in msg for kw in (
            "connection refused", "connection reset", "no route to host"
        )):
            host = event.get("hostname", "unknown")
            ip   = event.get("source_ip", "")

            findings.append(_make_finding(
                rule_id="LOG-NET-001",
                title="Network Connection Error Detected",
                severity="Low",
                confidence_signal="keyword_match",
                category="Network",
                asset=host,
                evidence={
                    "source_ip": ip,
                    "timestamp": event.get("timestamp"),
                    "message":   event.get("message", "")[:200],
                },
                recommendation=(
                    "Investigate source of connection errors. "
                    "May indicate network scanning or misconfiguration."
                ),
                exploitability_key="contextual",
            ))

    return findings


def _analyze_service_activity(events: List[Dict]) -> List[Dict]:
    """Detect service start/stop activity."""
    findings: List[Dict] = []

    for event in events:
        msg     = event.get("message", "").lower()
        process = event.get("process", "").lower()

        if "systemd" in process and any(
            kw in msg for kw in ("started", "stopped", "failed", "activating")
        ):
            host     = event.get("hostname", "unknown")
            severity = "Medium" if "failed" in msg else "Low"

            findings.append(_make_finding(
                rule_id="LOG-SYS-002",
                title="System Service State Change",
                severity=severity,
                confidence_signal="keyword_match",
                category="Service",
                asset=host,
                evidence={
                    "process":   event.get("process"),
                    "timestamp": event.get("timestamp"),
                    "message":   event.get("message", "")[:200],
                },
                recommendation=(
                    "Verify service state changes are expected. "
                    "Investigate failed services."
                ),
                exploitability_key="contextual",
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Register Rules at Module Scope
# ─────────────────────────────────────────────────────────────────────────────

RULES.extend([
    _analyze_failed_logins,
    _analyze_successful_logins,
    _analyze_invalid_users,
    _analyze_sudo,
    _analyze_cron,
    _analyze_sessions,
    _analyze_authentication,
    _analyze_privilege_escalation,
    _analyze_network_events,
    _analyze_service_activity,
])


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Finding Categorization
# ═════════════════════════════════════════════════════════════════════════════

_CATEGORY_BUCKET_MAP: Dict[str, str] = {
    "Authentication": "authentication",
    "Privilege":      "privilege",
    "Network":        "network",
    "Session":        "session",
    "Service":        "service",
    "Cron":           "cron",
}


def _categorize_findings(findings: List[Dict], details: Dict) -> None:
    """Distribute findings into detail buckets."""
    for finding in findings:
        category = finding.get("category", "")
        bucket   = _CATEGORY_BUCKET_MAP.get(category, "unknown")

        if bucket in details:
            details[bucket].append(finding)
        else:
            details["unknown"].append(finding)


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Event Summary Builder
# ═════════════════════════════════════════════════════════════════════════════

def _build_event_summary(events: List[Dict]) -> Dict:
    """Build event-level statistics from normalized events."""
    event_type_counts: Dict[str, int] = {}
    unique_usernames:  set = set()
    unique_source_ips: set = set()

    for event in events:
        et = event.get("event_type", "unknown")
        event_type_counts[et] = event_type_counts.get(et, 0) + 1

        username = event.get("username")
        if username and username != "unknown":
            unique_usernames.add(username)

        source_ip = event.get("source_ip")
        if source_ip and source_ip != "unknown":
            unique_source_ips.add(source_ip)

    return {
        "event_type_counts":   event_type_counts,
        "failed_logins":       event_type_counts.get("failed_login", 0),
        "successful_logins":   event_type_counts.get("success_login", 0),
        "invalid_user_events": event_type_counts.get("invalid_user", 0),
        "sudo_events":         event_type_counts.get("sudo", 0),
        "session_opens":       event_type_counts.get("session_open", 0),
        "session_closes":      event_type_counts.get("session_close", 0),
        "cron_events":         event_type_counts.get("cron", 0),
        "unique_usernames":    len(unique_usernames),
        "unique_source_ips":   len(unique_source_ips),
    }


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — Field Extractors
# ═════════════════════════════════════════════════════════════════════════════

def _extract_ip(text: str) -> str:
    """Extract the first IPv4 address from text."""
    match = _IP_PATTERN.search(text)
    if match:
        ip = match.group()
        if ip not in ("0.0.0.0", "255.255.255.255"):
            return ip
    return ""


def _extract_username(text: str) -> str:
    """Extract a username from a normalized message."""
    for pattern in _USER_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1).rstrip(".,;:")
    return ""


def _normalize_severity(raw: str) -> str:
    """Normalize severity strings from various log formats."""
    mapping = {
        "debug":       "Informational",
        "info":        "Informational",
        "information": "Informational",
        "notice":      "Low",
        "warning":     "Low",
        "warn":        "Low",
        "error":       "Medium",
        "err":         "Medium",
        "critical":    "High",
        "crit":        "High",
        "alert":       "High",
        "emergency":   "Critical",
        "emerg":       "Critical",
    }
    return mapping.get(raw.lower(), "Informational")


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — CLI Helpers (Mode 2)
# ═════════════════════════════════════════════════════════════════════════════

def _validate_operating_system() -> Tuple[bool, Optional[str]]:
    """Validate that the current OS supports log collection."""
    import platform
    system = platform.system().lower()
    if system not in ("linux", "darwin"):
        return False, (
            f"Log collection via CLI is supported on Linux only. "
            f"Detected: {platform.system()}"
        )
    return True, None


def _execute_cli_command(
    cmd: List[str], output_path: str,
) -> Tuple[bool, Optional[str]]:
    """Run a CLI command and write stdout to output_path. Non-fatal."""
    if cmd[0] == "cat" and len(cmd) > 1:
        if not os.path.isfile(cmd[1]):
            return False, f"Log file not found: {cmd[1]}"

    if not shutil.which(cmd[0]):
        return False, f"Command not found: {cmd[0]}"

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CLI_TIMEOUT,
        )
        if not result.stdout.strip():
            return False, f"Command returned empty output: {' '.join(cmd)}"

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(result.stdout)

        return True, None
    except subprocess.TimeoutExpired:
        return False, f"Command timed out: {' '.join(cmd)}"
    except PermissionError:
        return False, f"Permission denied running: {' '.join(cmd)}"
    except Exception as exc:
        return False, f"Error running command: {exc}"


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL — REST API Helpers (Mode 3) with Pagination
# ═════════════════════════════════════════════════════════════════════════════

# Common pagination key names across SIEM platforms
_PAGINATION_KEYS = (
    "next",
    "nextLink",
    "@odata.nextLink",
    "next_page",
    "nextPageUrl",
    "cursor",
    "continuation_token",
    "scroll_id",
    "paging_token",
)

# Common data wrapper key names
_DATA_KEYS = (
    "results", "events", "logs", "records",
    "hits", "data", "value", "items",
)


def _download_paginated(
    url: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, str]],
    output_path: str,
    max_pages: int,
) -> Tuple[bool, Optional[str], int]:
    """
    Download JSON log data with automatic pagination.

    Supports:
        - Link-based: next, nextLink, @odata.nextLink, cursor, continuation_token
        - Offset-based: offset/limit query parameters

    Returns (success, error_message, pages_fetched).
    """
    all_records: List[Any] = []
    current_url = url
    pages_fetched = 0

    # Build initial URL with params
    if params:
        param_str   = "&".join(
            f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()
        )
        separator   = "&" if "?" in current_url else "?"
        current_url = f"{current_url}{separator}{param_str}"

    while current_url and pages_fetched < max_pages:
        pages_fetched += 1
        logger.debug("Fetching page %d: %s", pages_fetched, current_url[:120])

        raw, fetch_err = _fetch_json_url(current_url, headers)
        if fetch_err:
            return False, fetch_err, pages_fetched

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            return False, f"Remote endpoint returned non-JSON data: {exc}", pages_fetched

        # Extract records from this page
        page_records = _extract_page_records(data)
        all_records.extend(page_records)

        logger.debug("  Page %d: %d records", pages_fetched, len(page_records))

        # Find next page URL
        next_url = _find_next_page_url(data)
        if not next_url:
            break

        current_url = next_url

    if not all_records:
        return False, "API returned no log records across all pages.", pages_fetched

    # Write aggregated records
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(all_records, fh, indent=2, default=str)
        return True, None, pages_fetched
    except Exception as exc:
        return False, f"Failed to write log data: {exc}", pages_fetched


def _download_single_page(
    url: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, str]],
    output_path: str,
) -> Tuple[bool, Optional[str]]:
    """Download a single page of JSON log data (no pagination)."""
    if params:
        param_str = "&".join(
            f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()
        )
        separator = "&" if "?" in url else "?"
        full_url  = f"{url}{separator}{param_str}"
    else:
        full_url = url

    raw, fetch_err = _fetch_json_url(full_url, headers)
    if fetch_err:
        return False, fetch_err

    try:
        json.loads(raw)  # validate JSON

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(raw)

        return True, None
    except json.JSONDecodeError as exc:
        return False, f"Remote endpoint returned non-JSON data: {exc}"
    except Exception as exc:
        return False, f"Unexpected error downloading logs: {exc}"


def _fetch_json_url(url: str, headers: Dict[str, str]) -> Tuple[str, Optional[str]]:
    """Fetch a JSON endpoint with bounded retries for transient failures."""
    attempts = REST_RETRIES + 1

    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=REST_TIMEOUT) as resp:
                return resp.read().decode("utf-8"), None
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or attempt == attempts:
                return "", f"HTTP {exc.code} from {url}: {exc.reason}"
        except urllib.error.URLError as exc:
            if attempt == attempts:
                return "", f"Network error calling {url}: {exc.reason}"
        except Exception as exc:
            if attempt == attempts:
                return "", f"Unexpected error downloading logs: {exc}"

        time.sleep(REST_RETRY_DELAY)


def _extract_page_records(data: Any) -> List[Any]:
    """Extract log records from a single page response."""
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in _DATA_KEYS:
            if key in data and isinstance(data[key], list):
                return data[key]
        # Elasticsearch nested hits
        hits = data.get("hits")
        if isinstance(hits, dict):
            inner = hits.get("hits")
            if isinstance(inner, list):
                return [
                    h.get("_source", h) for h in inner
                    if isinstance(h, dict)
                ]
        return [data]

    return []


def _find_next_page_url(data: Any) -> Optional[str]:
    """
    Find the next-page URL from a paginated API response.

    Checks common pagination keys used by Splunk, Elastic, Sentinel,
    Microsoft Graph, and generic REST APIs.
    """
    if not isinstance(data, dict):
        return None

    for key in _PAGINATION_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value.startswith("http"):
            return value

    # Check nested paging objects
    paging = data.get("paging") or data.get("pagination")
    if isinstance(paging, dict):
        for key in ("next", "next_url", "nextLink"):
            value = paging.get(key)
            if isinstance(value, str) and value.startswith("http"):
                return value

    return None


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
        "  python logs.py run  <input_path> [profile]\n"
        "  python logs.py cli  <output_dir> [profile]\n"
        "  python logs.py api  <endpoint> [output_dir] [profile] [token]\n"
    )

    if len(sys.argv) < 3:
        print(_USAGE)
        sys.exit(1)

    mode = sys.argv[1].lower()
    arg2 = sys.argv[2]

    if mode == "run":
        prof    = sys.argv[3] if len(sys.argv) > 3 else "all"
        _result = run(arg2, profile=prof)

    elif mode == "cli":
        prof    = sys.argv[3] if len(sys.argv) > 3 else "all"
        _result = run_cli(output_dir=arg2, profile=prof)

    elif mode == "api":
        _endpoint = sys.argv[2]
        _out      = sys.argv[3] if len(sys.argv) > 3 else "thragg_results/logs_api"
        prof      = sys.argv[4] if len(sys.argv) > 4 else "all"
        _tok      = sys.argv[5] if len(sys.argv) > 5 else None
        _result   = run_api(
            endpoint=_endpoint, output_dir=_out, profile=prof, token=_tok,
        )

    else:
        print(f"Unknown mode: {mode}\n{_USAGE}")
        sys.exit(1)

    print(json.dumps(_result, indent=2, default=str))
