"""
Rich table helpers.

This module provides reusable table generation functions used
throughout firewall-audit.
"""

from rich.table import Table
from rich.text import Text

from models.finding import Finding
from models.firewall import FirewallConfig


def _plain(value: object) -> Text:
    """Render configuration-derived values as text, not Rich markup."""
    return Text(str(value) if value not in (None, "") else "N/A")


def build_configuration_summary_table(config: FirewallConfig) -> Table:
    """
    Build a configuration summary table.

    Args:
        config: Parsed firewall configuration.

    Returns:
        Rich table containing configuration statistics.
    """

    table = Table(title="Configuration Summary", show_lines=False)

    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Details")

    table.add_row("Vendor", _plain(config.vendor))
    table.add_row("Hostname", _plain(config.hostname))
    table.add_row("Version", _plain(config.version))
    table.add_row("Model", _plain(config.model))
    table.add_row("Interfaces", _plain(len(config.interfaces)))
    table.add_row("Zones", _plain(len(config.zones)))
    table.add_row("Address objects", _plain(len(config.objects)))
    table.add_row("Object groups", _plain(len(config.object_groups)))
    table.add_row("Rules", _plain(len(config.rules)))
    table.add_row("Enabled rules", _plain(sum(rule.enabled for rule in config.rules)))

    return table


def build_findings_table(findings: list[Finding]) -> Table:
    """Build a compact findings table for terminal output."""
    table = Table(title="Findings", show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Finding")
    table.add_column("Affected objects")

    for finding in findings:
        severity_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }.get(finding.severity.lower(), "white")
        table.add_row(
            Text(finding.severity.upper(), style=severity_style),
            _plain(finding.id),
            _plain(finding.title),
            _plain(", ".join(finding.affected_objects) or "N/A"),
        )

    if not findings:
        table.add_row("N/A", "N/A", "No findings identified", "N/A")

    return table
