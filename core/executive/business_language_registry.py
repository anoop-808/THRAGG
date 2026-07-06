"""
core.executive.business_language_registry
=========================================

Reusable technical-to-business terminology registry.
"""

from __future__ import annotations

import re

__all__ = ["BusinessLanguageRegistry"]


class BusinessLanguageRegistry:
    """Translate known technical terms into executive-safe language."""

    TERMS: dict[str, str] = {
        "ssh": "Remote Administrative Access",
        "azure key vault": "Secrets Management Infrastructure",
        "key vault": "Secrets Management Infrastructure",
        "admin account": "Privileged Identity",
        "administrator": "Privileged Identity",
        "storage account": "Business Data Repository",
        "public cloud": "Cloud-hosted Business Service",
        "cloud exposure": "Cloud Service Exposure",
        "identity compromise": "Identity Compromise",
        "authentication": "Authentication Service",
        "privilege": "Privileged Access",
    }

    IMPACTS: dict[str, str] = {
        "identity compromise": "Authentication services may be affected.",
        "admin account": "Privileged identities may be exposed.",
        "administrator": "Privileged identities may be exposed.",
        "public cloud": "Business services may become externally accessible.",
        "cloud exposure": "Business services may become externally accessible.",
        "ssh": "Remote administrative access is exposed.",
        "storage account": "Business data repositories may be exposed.",
        "azure key vault": "Secrets management infrastructure may be affected.",
        "key vault": "Secrets management infrastructure may be affected.",
    }

    def business_term(self, technical_term: str) -> str:
        """Return a business term for known technical terminology."""
        return self.TERMS.get(technical_term.strip().lower(), technical_term)

    def impact_for_text(self, text: str) -> str:
        """Return the first deterministic business impact matching text."""
        lowered = text.lower()
        for term, impact in self.IMPACTS.items():
            if term in lowered:
                return impact
        return "Business operations may require security review."

    def translate_text(self, text: str) -> str:
        """Replace known technical terms with business terminology."""
        translated = text
        for technical, business in sorted(
            self.TERMS.items(),
            key=lambda item: len(item[0]),
            reverse=True,
        ):
            pattern = re.compile(
                rf"(?<!\w){re.escape(technical)}(?!\w)",
                re.IGNORECASE,
            )
            translated = pattern.sub(business, translated)
        return translated
