"""
thragg.py
THRAGG Orchestrator v1.0

Threat Hunting, Recon & Automated Gap Analysis Gateway

Responsibilities:
  1. Discover evidence files in an input folder.
  2. Dispatch each file to the correct analysis module.
  3. Execute modules and collect their results.
  4. Merge results into one unified security report.

This orchestrator does NOT scan, attack, reason, or correlate.
It only dispatches, collects, and merges.

Contract: Every module must return exactly:
    {
        "metadata": {},
        "summary": {},
        "details": {},
        "artifacts": {},
        "errors": []
    }

No exceptions. No top-level "findings". Findings live inside details.
"""

import importlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------
# Maps a (filename_pattern_fn) → module name.
# Each entry is a tuple of:
#   (predicate: Callable[[str], bool], module_name: str)
#
# Evaluated in order; first match wins.

def _is_auth_log(name: str) -> bool:
    return "auth" in name.lower() and name.endswith(".log")


def _is_nmap_xml(name: str) -> bool:
    return name.endswith(".xml")


def _is_zap_report(name: str) -> bool:
    lower = name.lower()
    return ("zap" in lower or "report" in lower) and name.endswith((".html", ".json"))


def _is_identity_json(name: str) -> bool:
    lower = name.lower()
    return name.endswith(".json") and any(
        kw in lower for kw in ("user", "group", "application", "service", "principal",
                                "entra", "azure_ad", "identity")
    )


def _is_cloud_json(name: str) -> bool:
    lower = name.lower()
    return name.endswith(".json") and any(
        kw in lower for kw in ("vm", "storage", "nsg", "vnet", "vault", "subscription",
                                "cloud", "resource")
    )


DISPATCH_TABLE: list[tuple] = [
    (_is_auth_log,      "modules.logs"),
    (_is_nmap_xml,      "modules.nmap"),
    (_is_zap_report,    "modules.zap"),
    (_is_identity_json, "modules.identity"),
    (_is_cloud_json,    "modules.cloud"),
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ModuleResult:
    """Holds the raw contract returned by one module call.
    
    Contract: Every module returns exactly:
        {
            "metadata": {},
            "summary": {},
            "details": {},
            "artifacts": {},
            "errors": []
        }
    
    No top-level "findings". Findings are stored inside details.
    """
    module_name: str
    file_path: str
    metadata: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)
    artifacts: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    success: bool = True


@dataclass
class UnifiedReport:
    """The single output document THRAGG returns to its caller."""
    metadata: dict = field(default_factory=dict)
    modules: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)
    artifacts: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "metadata": self.metadata,
            "modules": self.modules,
            "summary": self.summary,
            "details": self.details,
            "artifacts": self.artifacts,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

class FileDiscovery:
    """Recursively discovers evidence files inside the input folder."""

    @staticmethod
    def discover(folder: str) -> list[str]:
        """Return absolute paths of all regular files in *folder*.

        Args:
            folder: Path to the evidence directory.

        Returns:
            Sorted list of absolute file paths.

        Raises:
            ValueError: If *folder* does not exist or is not a directory.
        """
        if not os.path.isdir(folder):
            raise ValueError(f"Input folder not found or not a directory: {folder}")

        paths = []

        for root, _, files in os.walk(folder):
            for filename in files:
                full_path = os.path.abspath(os.path.join(root, filename))
                paths.append(full_path)

        return sorted(paths)


# ---------------------------------------------------------------------------
# Module dispatcher
# ---------------------------------------------------------------------------

class ModuleDispatcher:
    """Maps each file path to a module name using the dispatch table."""

    @staticmethod
    def resolve(file_path: str) -> str | None:
        """Return the dotted module name for *file_path*, or None if unknown.

        Args:
            file_path: Absolute path to an evidence file.

        Returns:
            Module name string (e.g. 'modules.logs') or None.
        """
        name = os.path.basename(file_path)
        for predicate, module_name in DISPATCH_TABLE:
            if predicate(name):
                return module_name
        return None


# ---------------------------------------------------------------------------
# Module runner
# ---------------------------------------------------------------------------

class ModuleRunner:
    """Dynamically imports and executes a THRAGG module."""

    @staticmethod
    def run(module_name: str, file_path: str) -> ModuleResult:
        """Import *module_name* and call its ``run(file_path)`` function.

        The module contract guarantees a dict with keys:
        metadata, summary, details, artifacts, errors.

        Any exception raised by the module is caught and stored as an
        error so the orchestrator never crashes.

        Args:
            module_name: Dotted module path (e.g. 'modules.zap').
            file_path:   Absolute path to the evidence file.

        Returns:
            A populated ModuleResult.
        """
        result = ModuleResult(module_name=module_name, file_path=file_path)

        try:
            mod = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            result.success = False
            result.errors.append(f"Could not import module '{module_name}': {exc}")
            return result

        try:
            raw: dict = mod.run(file_path)
        except Exception as exc:  # noqa: BLE001
            result.success = False
            result.errors.append(f"Module '{module_name}' raised an exception: {exc}")
            return result

        if not isinstance(raw, dict):
            result.success = False
            result.errors.append(
                f"Module '{module_name}' returned {type(raw).__name__} instead of dict."
            )
            return result

        contract_errors = _validate_module_contract(module_name, raw)
        if contract_errors:
            result.success = False
            result.errors.extend(contract_errors)
            return result

        # Extract standard contract fields
        result.metadata  = raw.get("metadata",  {})
        result.summary   = raw.get("summary",   {})
        result.details   = raw.get("details",   {})
        result.artifacts = raw.get("artifacts", {})
        result.errors    = raw.get("errors",    [])
        result.warnings  = result.metadata.get("warnings", [])
        result.warnings += [e for e in result.errors if _is_warning(e)]
        result.errors    = [e for e in result.errors if not _is_warning(e)]

        # Check for failure indicators
        module_status = result.metadata.get("status", "")
        if module_status == "failed" or result.errors:
            result.success = False

        return result


def _is_warning(message: Any) -> bool:
    """Return True when a module message is informational."""
    return isinstance(message, str) and message.strip().upper().startswith("WARNING:")


def _validate_module_contract(module_name: str, raw: dict) -> list[str]:
    """Validate the structural THRAGG module contract."""
    required = {
        "metadata": dict,
        "summary": dict,
        "details": dict,
        "artifacts": dict,
        "errors": list,
    }
    errors = []

    for key, expected_type in required.items():
        if key not in raw:
            errors.append(f"Module '{module_name}' missing required contract key: {key}")
            continue
        if not isinstance(raw[key], expected_type):
            errors.append(
                f"Module '{module_name}' contract key '{key}' must be "
                f"{expected_type.__name__}, got {type(raw[key]).__name__}."
            )

    return errors


def _module_status(result: ModuleResult) -> str:
    """Return the execution status label for a module result."""
    if not result.success:
        return "failed"
    if result.warnings:
        return "completed_with_warnings"
    return "completed"


# ---------------------------------------------------------------------------
# Result merger
# ---------------------------------------------------------------------------

class ResultMerger:
    """Collapses a list of ModuleResults into one UnifiedReport."""

    def merge(
        self,
        results: list[ModuleResult],
        input_folder: str,
        start_time: float,
    ) -> UnifiedReport:
        """Build the unified report from all collected module results.

        Args:
            results:      All ModuleResult objects collected by the pipeline.
            input_folder: The evidence directory the user supplied.
            start_time:   Unix timestamp from before any module was run.

        Returns:
            A populated UnifiedReport.
        """
        report = UnifiedReport()
        report.metadata   = self._build_metadata(results, input_folder, start_time)
        report.modules    = self._build_modules_section(results)
        report.summary    = self._build_summary(results)
        report.details    = self._build_details(results)
        report.artifacts  = self._build_artifacts(results)
        report.errors     = self._collect_errors(results)
        return report

    # -- metadata ------------------------------------------------------------

    @staticmethod
    def _build_metadata(
        results: list[ModuleResult],
        input_folder: str,
        start_time: float,
    ) -> dict:
        executed = [r.module_name for r in results]
        failed   = [r.module_name for r in results if not r.success]
        completed = [r.module_name for r in results if r.success and not r.warnings]
        completed_with_warnings = [
            r.module_name for r in results if r.success and r.warnings
        ]
        return {
            "framework":        "THRAGG",
            "version":          "1.0.0",
            "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "execution_time":   round(time.time() - start_time, 4),
            "input_folder":     input_folder,
            "modules_executed": executed,
            "modules_completed": completed,
            "modules_completed_with_warnings": completed_with_warnings,
            "modules_failed":   failed,
            "files_analyzed":   len(results),
        }

    # -- modules section -----------------------------------------------------

    @staticmethod
    def _build_modules_section(results: list[ModuleResult]) -> list[dict]:
        modules = []
        for r in results:
            metadata = dict(r.metadata)
            if r.warnings:
                metadata["warnings"] = r.warnings

            modules.append({
                "module":    r.module_name,
                "file":      r.file_path,
                "status":    _module_status(r),
                "metadata":  metadata,
            })

        return modules

    # -- summary -------------------------------------------------------------

    @staticmethod
    def _build_summary(results: list[ModuleResult]) -> dict:
        """Aggregate numeric summary fields from every module.

        Unknown keys are passed through; known numeric keys are summed.
        """
        combined: dict[str, Any] = {
            "total_files_analyzed": len(results),
            "modules_executed":     len(results),
            "modules_completed":    sum(1 for r in results if r.success and not r.warnings),
            "modules_completed_with_warnings": sum(
                1 for r in results if r.success and r.warnings
            ),
            "modules_succeeded":    sum(1 for r in results if r.success),
            "modules_failed":       sum(1 for r in results if not r.success),
        }

        # Accumulate every numeric field from every module summary.
        for r in results:
            prefix = r.module_name.split(".")[-1]  # e.g. 'zap'
            for key, value in r.summary.items():
                namespaced = f"{prefix}.{key}"
                if isinstance(value, (int, float)):
                    combined[namespaced] = combined.get(namespaced, 0) + value
                else:
                    combined[namespaced] = value

        return combined

    # -- details -------------------------------------------------------------

    @staticmethod
    def _build_details(results: list[ModuleResult]) -> dict:
        """Each module gets its own key in details so nothing is lost.
        
        Module details already contain categorized findings.
        No need to extract a separate top-level findings list.
        """
        details: dict[str, Any] = {}
        for r in results:
            module_key = r.module_name.split(".")[-1]
            file_key   = os.path.basename(r.file_path)
            entry_key  = f"{module_key}::{file_key}"

            # details from the module already contains findings in their
            # categorized structure (users, groups, compute, storage, etc.)
            details[entry_key] = r.details

        return details

    # -- artifacts -----------------------------------------------------------

    @staticmethod
    def _build_artifacts(results: list[ModuleResult]) -> dict:
        """Merge artifact dicts; namespace by module to avoid key collisions."""
        artifacts: dict[str, Any] = {}
        for r in results:
            module_key = r.module_name.split(".")[-1]
            file_key   = os.path.basename(r.file_path)
            entry_key  = f"{module_key}::{file_key}"
            artifacts[entry_key] = r.artifacts
        return artifacts

    # -- errors --------------------------------------------------------------

    @staticmethod
    def _collect_errors(results: list[ModuleResult]) -> list[dict]:
        """Flatten all module errors into one list with source metadata."""
        all_errors = []
        for r in results:
            for err in r.errors:
                all_errors.append({
                    "module": r.module_name,
                    "file":   r.file_path,
                    "error":  err,
                })
        return all_errors


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------

class ReportWriter:
    """Persists the unified report to disk."""

    OUTPUT_DIR = "thragg_results"

    def write(self, report: UnifiedReport) -> str:
        """Serialise *report* to a timestamped JSON file.

        Args:
            report: The completed UnifiedReport.

        Returns:
            Absolute path of the written file.
        """
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        filename  = f"thragg_report_{timestamp}.json"
        out_path  = os.path.join(self.OUTPUT_DIR, filename)

        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2, default=str)

        return os.path.abspath(out_path)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class THRAGGOrchestrator:
    """Top-level coordinator.

    Wires together FileDiscovery → ModuleDispatcher → ModuleRunner
    → ResultMerger → ReportWriter in a single linear pipeline.

    Usage::

        orchestrator = THRAGGOrchestrator()
        report       = orchestrator.run("/path/to/evidence/")
        print(report)
    """

    def __init__(self) -> None:
        self._discovery   = FileDiscovery()
        self._dispatcher  = ModuleDispatcher()
        self._runner      = ModuleRunner()
        self._merger      = ResultMerger()
        self._writer      = ReportWriter()

    def run(self, input_folder: str) -> dict:
        """Execute the full THRAGG pipeline.

        Args:
            input_folder: Path to the directory containing evidence files.

        Returns:
            The unified report as a plain dict (also written to disk).
        """
        start_time = time.time()

        files   = self._discover(input_folder)
        results = self._dispatch_and_run(files)
        report  = self._merger.merge(results, input_folder, start_time)
        out     = self._writer.write(report)

        report.artifacts["thragg_report"] = out
        return report.to_dict()

    # -- private helpers -----------------------------------------------------

    def _discover(self, folder: str) -> list[str]:
        """Discover files, returning an empty list on error (logged to stderr)."""
        try:
            return self._discovery.discover(folder)
        except ValueError as exc:
            print(f"[THRAGG] Discovery error: {exc}")
            return []

    def _dispatch_and_run(self, files: list[str]) -> list[ModuleResult]:
        """For each file, resolve the module and execute it."""
        results = []
        for file_path in files:
            module_name = self._dispatcher.resolve(file_path)
            if module_name is None:
                print(f"[THRAGG] No module matched: {os.path.basename(file_path)} — skipped")
                continue
            print(f"[THRAGG] Running {module_name} on {os.path.basename(file_path)}")
            result = self._runner.run(module_name, file_path)
            results.append(result)
        return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point: python thragg.py <evidence_folder>"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python thragg.py <evidence_folder>")
        sys.exit(1)

    folder = sys.argv[1]
    print(f"[THRAGG] Starting pipeline on: {folder}")

    orchestrator = THRAGGOrchestrator()
    report       = orchestrator.run(folder)

    print("\n[THRAGG] Pipeline complete.")
    print(f"  Files analyzed : {report['metadata']['files_analyzed']}")
    print(f"  Modules run    : {len(report['metadata']['modules_executed'])}")
    print(f"  Modules failed : {len(report['metadata']['modules_failed'])}")
    print(f"  Execution time : {report['metadata']['execution_time']}s")
    print(f"  Report saved   : {report['artifacts'].get('thragg_report', 'N/A')}")

    if report["errors"]:
        print(f"\n[THRAGG] {len(report['errors'])} error(s) recorded — see report for details.")


if __name__ == "__main__":
    main()
