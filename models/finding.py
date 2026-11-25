"""
Finding data model.

This module defines the finding structure used by analysis modules.

Analysis engines should generate Finding objects rather than producing
report content directly. Findings can then be exported to JSON, XML,
Markdown reports, or other output formats.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FindingDefinition:
    """Static finding metadata loaded from the packaged YAML catalogue."""

    id: str
    title: str
    category: str
    severity: str
    description: str
    recommendation: str
    impact: str = ""
    sureformat_id: str | None = None
    executive_summary: str = ""
    references: tuple[tuple[str, str], ...] = ()


@dataclass
class Finding:
    """
    Represents a security finding identified during analysis.

    Findings contain enough information for reporting modules to generate
    report-ready content without needing access to vendor-specific data.
    """

    id: str

    title: str

    severity: str

    description: str

    category: str = "general"

    recommendation: str = ""
    impact: str = ""

    affected_objects: list[str] = field(default_factory=list)

    data: dict[str, Any] = field(default_factory=dict)

    sureformat_id: str | None = None
