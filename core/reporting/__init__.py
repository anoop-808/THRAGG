"""core.reporting - Reporting Layer for THRAGG."""

from ..shared.errors import ReportValidationError
from .evidence_package import EvidencePackage, EvidencePackageManifest
from .evidence_package_schema import EvidencePackageSchema, EvidencePackageSchemaError
from .html_renderer import HtmlRenderer
from .json_renderer import JsonRenderer
from .markdown_renderer import MarkdownRenderer
from .report import Report, ReportModel, ReportType, TraceabilityEntry
from .report_artifact import ArtifactType, ReportArtifact
from .report_builder import ReportBuilder
from .report_engine import ReportEngine
from .report_metadata import ReportMetadata
from .report_renderer import ReportRenderer
from .report_repository import ReportRepository
from .report_validator import ReportValidator
from .renderers import ConsoleRenderer, HTMLRenderer, JSONRenderer
from .section import Section, ContentType
from .section_builder import SectionBuilder
from .template_registry import TemplateRegistry, SectionTemplate

__all__ = [
    "ArtifactType",
    "ConsoleRenderer",
    "ContentType",
    "EvidencePackage",
    "EvidencePackageManifest",
    "EvidencePackageSchema",
    "EvidencePackageSchemaError",
    "HTMLRenderer",
    "HtmlRenderer",
    "JSONRenderer",
    "JsonRenderer",
    "MarkdownRenderer",
    "Report",
    "ReportArtifact",
    "ReportBuilder",
    "ReportEngine",
    "ReportMetadata",
    "ReportModel",
    "ReportRenderer",
    "ReportRepository",
    "ReportType",
    "ReportValidationError",
    "ReportValidator",
    "Section",
    "SectionBuilder",
    "SectionTemplate",
    "TemplateRegistry",
    "TraceabilityEntry",
]
