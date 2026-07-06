"""
thragg.py
THRAGG Orchestrator v1.0

Threat Hunting, Recon & Automated Gap Analysis Gateway

Responsibilities:
  1. Discover evidence files in an input folder.
  2. Dispatch each file to the correct analysis module.
  3. Execute modules and collect their results.
  4. Run the intelligence pipeline from Foundation through Dashboard.
  5. Merge results into one unified security report.

This orchestrator does not scan or parse evidence directly.
Modules own raw evidence parsing; higher layers consume structured objects.

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
from datetime import UTC, datetime
from typing import Any, Callable

from core.attack_chain import AttackChainEngine
from core.correlation import CorrelationEngine, RuleRegistry
from core.dashboard import DashboardGenerator
from core.executive import ExecutiveAssessmentBuilder, FrameworkSnapshot
from core.reporting import HtmlRenderer, JsonRenderer, MarkdownRenderer, ReportEngine, ReportType
from core.risk import (
    ChainLengthFactor,
    ConfidenceFactor,
    CriticalAssetFactor,
    ExposureFactor,
    MITREFactor,
    RiskEngine,
    ScoringPolicy,
    SeverityFactor,
)
from core.shared.configuration import DEFAULT_REPORT_OUTPUT_DIR, MODULE_CONTRACT_KEYS
from core.shared.errors import ErrorSeverity, FrameworkError, coerce_error
from core.shared.logging import get_logger, logged_operation
from core.shared.version import FRAMEWORK_VERSION

__path__ = [os.path.dirname(__file__)]
LOGGER = get_logger("orchestrator")


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


@dataclass(frozen=True)
class ModuleRegistration:
    """Registered module resolver entry."""

    name: str
    module_name: str
    predicate: Callable[[str], bool]
    description: str = ""

    def matches(self, filename: str) -> bool:
        """Return True when this registration accepts a filename."""
        if not isinstance(filename, str) or not filename:
            raise ValueError("filename must be a non-empty string")
        return self.predicate(filename)


class ModuleRegistry:
    """Registry for pluggable THRAGG modules."""

    def __init__(
        self,
        registrations: tuple[ModuleRegistration, ...] | None = None,
    ) -> None:
        self._registrations: list[ModuleRegistration] = []
        for registration in registrations or ():
            self.register(registration)

    def register(self, registration: ModuleRegistration) -> None:
        """Register one module resolver entry."""
        if not isinstance(registration, ModuleRegistration):
            raise TypeError("registration must be a ModuleRegistration")
        if not isinstance(registration.name, str) or not registration.name.strip():
            raise ValueError("module registration name must be non-empty")
        if (
            not isinstance(registration.module_name, str)
            or not registration.module_name.strip()
        ):
            raise ValueError("module registration module_name must be non-empty")
        if not callable(registration.predicate):
            raise TypeError("module registration predicate must be callable")
        if any(item.name == registration.name for item in self._registrations):
            raise ValueError(f"Duplicate module registration: {registration.name}")
        self._registrations.append(registration)

    def resolve(self, file_path: str) -> ModuleRegistration | None:
        """Return the first module registration matching a file path."""
        if not isinstance(file_path, str) or not file_path.strip():
            raise ValueError("file_path must be a non-empty string")
        filename = os.path.basename(file_path)
        for registration in self._registrations:
            try:
                if registration.matches(filename):
                    return registration
            except Exception as exc:  # noqa: BLE001
                raise ValueError(
                    f"Module registration '{registration.name}' failed to match "
                    f"{filename!r}: {exc}"
                ) from exc
        return None

    def metadata(self) -> list[dict[str, str]]:
        """Return module metadata for diagnostics and future integrations."""
        return [
            {
                "name": item.name,
                "module": item.module_name,
                "description": item.description,
            }
            for item in self._registrations
        ]

    def validate_contract(
        self,
        module_name: str,
        raw: object,
    ) -> list[FrameworkError]:
        """Validate one module result against the THRAGG contract."""
        return _validate_module_contract(module_name, raw)


DEFAULT_MODULE_REGISTRY = ModuleRegistry(
    (
        ModuleRegistration("logs", "modules.logs", _is_auth_log, "Authentication logs"),
        ModuleRegistration("nmap", "modules.nmap", _is_nmap_xml, "Nmap XML"),
        ModuleRegistration("zap", "modules.zap", _is_zap_report, "ZAP reports"),
        ModuleRegistration(
            "identity",
            "modules.identity",
            _is_identity_json,
            "Identity exports",
        ),
        ModuleRegistration("cloud", "modules.cloud", _is_cloud_json, "Cloud exports"),
    )
)

DISPATCH_TABLE: list[tuple] = [
    (registration.predicate, registration.module_name)
    for registration in DEFAULT_MODULE_REGISTRY._registrations
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

    def __init__(self, registry: ModuleRegistry | None = None) -> None:
        self.registry = registry or DEFAULT_MODULE_REGISTRY

    def resolve(self, file_path: str) -> str | None:
        """Return the dotted module name for *file_path*, or None if unknown.

        Args:
            file_path: Absolute path to an evidence file.

        Returns:
            Module name string (e.g. 'modules.logs') or None.
        """
        registration = self.registry.resolve(file_path)
        return registration.module_name if registration else None


# ---------------------------------------------------------------------------
# Module runner
# ---------------------------------------------------------------------------

class ModuleRunner:
    """Dynamically imports and executes a THRAGG module."""

    def __init__(self, registry: ModuleRegistry | None = None) -> None:
        self.registry = registry or DEFAULT_MODULE_REGISTRY

    def run(self, module_name: str, file_path: str) -> ModuleResult:
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
        if not isinstance(module_name, str) or not module_name.strip():
            raise ValueError("module_name must be a non-empty string")
        if not isinstance(file_path, str) or not file_path.strip():
            raise ValueError("file_path must be a non-empty string")

        result = ModuleResult(module_name=module_name, file_path=file_path)

        try:
            mod = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            result.success = False
            result.errors.append(
                FrameworkError(
                    code="THRAGG-MODULE-IMPORT",
                    message=f"Could not import module '{module_name}': {exc}",
                    layer="module_runner",
                    recoverable=True,
                    source=module_name,
                )
            )
            return result

        try:
            with logged_operation(LOGGER, f"module {module_name}"):
                raw: dict = mod.run(file_path)
        except Exception as exc:  # noqa: BLE001
            result.success = False
            result.errors.append(
                FrameworkError(
                    code="THRAGG-MODULE-RUNTIME",
                    message=f"Module '{module_name}' raised an exception: {exc}",
                    layer="module_runner",
                    recoverable=True,
                    source=module_name,
                )
            )
            return result

        contract_errors = self.registry.validate_contract(module_name, raw)
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
    if isinstance(message, FrameworkError):
        return message.severity is ErrorSeverity.WARNING
    return isinstance(message, str) and message.strip().upper().startswith("WARNING:")


def _validate_module_contract(module_name: str, raw: object) -> list[FrameworkError]:
    """Validate the structural THRAGG module contract."""
    if not isinstance(raw, dict):
        return [
            FrameworkError(
                code="THRAGG-MODULE-CONTRACT-TYPE",
                message=(
                    f"Module '{module_name}' returned {type(raw).__name__} "
                    "instead of dict."
                ),
                layer="module_contract",
                recoverable=True,
                source=module_name,
            )
        ]
    errors: list[FrameworkError] = []

    for key, expected_type in MODULE_CONTRACT_KEYS.items():
        if key not in raw:
            errors.append(
                FrameworkError(
                    code="THRAGG-MODULE-CONTRACT-MISSING-KEY",
                    message=(
                        f"Module '{module_name}' missing required contract key: {key}"
                    ),
                    layer="module_contract",
                    recoverable=True,
                    source=module_name,
                )
            )
            continue
        if not isinstance(raw[key], expected_type):
            errors.append(
                FrameworkError(
                    code="THRAGG-MODULE-CONTRACT-BAD-TYPE",
                    message=(
                        f"Module '{module_name}' contract key '{key}' must be "
                        f"{expected_type.__name__}, got {type(raw[key]).__name__}."
                    ),
                    layer="module_contract",
                    recoverable=True,
                    source=module_name,
                )
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
            "version":          FRAMEWORK_VERSION,
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
                structured = coerce_error(
                    err,
                    layer="module",
                    source=r.module_name,
                ).to_dict()
                all_errors.append({
                    "module": r.module_name,
                    "file":   r.file_path,
                    "error":  str(err),
                    **structured,
                })
        return all_errors


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------

class ReportWriter:
    """Persists the unified report to disk."""

    OUTPUT_DIR = DEFAULT_REPORT_OUTPUT_DIR

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

    Wires together Modules → Foundation → Correlation → Attack Chain
    → Risk Engine → Executive Assessment → Reporting → Dashboard.

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
        self._correlation = CorrelationEngine(RuleRegistry().get_rules())
        self._attack_chain = AttackChainEngine()
        self._risk = RiskEngine()
        self._executive = ExecutiveAssessmentBuilder()
        self._dashboard = DashboardGenerator()
        self._reporting = ReportEngine(
            (MarkdownRenderer(), JsonRenderer(), HtmlRenderer())
        )

    def run(self, input_folder: str) -> dict:
        """Execute the full THRAGG pipeline.

        Args:
            input_folder: Path to the directory containing evidence files.

        Returns:
            The unified report as a plain dict (also written to disk).
        """
        if not isinstance(input_folder, str) or not input_folder.strip():
            raise ValueError("input_folder must be a non-empty string")
        start_time = time.time()

        with logged_operation(LOGGER, "orchestrator pipeline"):
            files   = self._discover(input_folder)
            results = self._dispatch_and_run(files)
            report  = self._merger.merge(results, input_folder, start_time)
            self._run_intelligence(report, results)
            out     = self._writer.write(report)

        report.artifacts["thragg_report"] = out
        return report.to_dict()

    # -- private helpers -----------------------------------------------------

    def _discover(self, folder: str) -> list[str]:
        """Discover files, returning an empty list on error (logged to stderr)."""
        try:
            return self._discovery.discover(folder)
        except ValueError as exc:
            LOGGER.warning("Discovery error: %s", exc)
            return []

    def _dispatch_and_run(self, files: list[str]) -> list[ModuleResult]:
        """For each file, resolve the module and execute it."""
        results = []
        for file_path in files:
            module_name = self._dispatcher.resolve(file_path)
            if module_name is None:
                LOGGER.warning("No module matched: %s", os.path.basename(file_path))
                continue
            LOGGER.info("Running %s on %s", module_name, os.path.basename(file_path))
            result = self._runner.run(module_name, file_path)
            results.append(result)
        return results

    def _run_intelligence(
        self,
        report: UnifiedReport,
        results: list[ModuleResult],
    ) -> None:
        """Run Foundation -> Correlation -> Attack Chain -> Risk -> Executive."""
        generated_at = datetime.now(UTC).replace(microsecond=0).isoformat()
        contracts = tuple(_contract_from_result(result) for result in results)

        correlations = self._correlation.run_contracts(contracts)
        graph = self._correlation.graph
        resolved = self._correlation.entity_registry.repository.list()
        relationships = self._correlation.relationship_repository.list()

        chains = self._attack_chain.run(
            self._correlation.repository,
            graph,
            self._correlation.entity_registry.repository.as_dict(),
        )
        risks = self._risk.run(chains, _default_risk_policy())
        environment = self._risk.assess_environment(risks, chains, generated_at)
        snapshot = FrameworkSnapshot(
            risk_assessments=risks,
            attack_chains=chains,
            correlations=correlations,
            finding_count=_finding_count(contracts),
            entity_count=len(resolved),
            resolved_entity_count=len(resolved),
            relationship_count=len(relationships),
            snapshot_version=FRAMEWORK_VERSION,
            generated_at=generated_at,
        )
        executive = self._executive.build(snapshot, generated_at)
        report_model = self._reporting.generate(
            executive,
            ReportType.EXECUTIVE,
            executive.id,
            generated_at=generated_at,
        )

        report.details["intelligence"] = {
            "framework_snapshot": snapshot.to_dict(),
            "environment_risk": environment.to_dict(),
            "executive_assessment": executive.to_dict(),
            "report_model": report_model.to_dict(),
        }

        package = self._reporting.publish(
            executive,
            snapshot,
            os.path.join(DEFAULT_REPORT_OUTPUT_DIR, "evidence_package"),
            generated_at,
        )
        dashboard = self._dashboard.generate(
            report_model,
            os.path.join(DEFAULT_REPORT_OUTPUT_DIR, "dashboard.html"),
            relationships=relationships,
            resolved_entities=resolved,
            findings=(),
            generated_at=generated_at,
        )
        report.artifacts["reporting_package"] = package.to_dict()
        report.artifacts["dashboard"] = dashboard.to_dict()


def _contract_from_result(result: ModuleResult) -> dict[str, Any]:
    metadata = dict(result.metadata)
    metadata.setdefault("module", result.module_name)
    metadata.setdefault("file", result.file_path)
    return {
        "metadata": metadata,
        "summary": result.summary,
        "details": result.details,
        "artifacts": result.artifacts,
        "errors": result.errors,
    }


def _default_risk_policy() -> ScoringPolicy:
    return ScoringPolicy(
        (
            SeverityFactor(),
            ConfidenceFactor(),
            ExposureFactor(),
            CriticalAssetFactor(),
            MITREFactor(),
            ChainLengthFactor(),
        )
    )


def _finding_count(contracts: tuple[dict[str, Any], ...]) -> int:
    return sum(len(contract["details"].get("findings", ())) for contract in contracts)


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
