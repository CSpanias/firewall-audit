"""Human-readable Markdown report export."""

from pathlib import Path
from typing import Any


def _cell(value: object) -> str:
    return str(value if value not in (None, "") else "N/A").replace("|", "\\|").replace("\n", " ")


def _format_evidence(evidence: dict[str, object]) -> str:
    parts = []
    for key, value in evidence.items():
        rendered = ", ".join(str(item) for item in value) if isinstance(value, list) else str(value)
        parts.append(f"{key}: {_cell(rendered)}")
    return "; ".join(parts) or "N/A"


def export_markdown(report: dict[str, Any], filepath: Path) -> Path:
    """Write a Markdown summary of a structured report."""
    device = report["device"]
    inventory = report["inventory"]
    lines = [
        "# Firewall audit",
        "",
        f"- **Source:** {_cell(report['source'])}",
        f"- **Generated:** {_cell(report['generated_at'])}",
        "",
        "## Device",
        "",
        "| Property | Value |",
        "| --- | --- |",
    ]
    for label, key in (
        ("Vendor", "vendor"),
        ("Hostname", "hostname"),
        ("Version", "version"),
    ):
        lines.append(f"| {label} | {_cell(device[key])} |")
    if device.get("platform"):
        lines.append(f"| Platform | {_cell(device['platform'])} |")
    elif device.get("platform_identifier"):
        lines.append(f"| Platform identifier | {_cell(device['platform_identifier'])} |")
    else:
        lines.append(f"| Model | {_cell(device['model'])} |")

    lines.extend(
        [
            "",
            "## Inventory",
            "",
            "| Category | Count |",
            "| --- | ---: |",
        ]
    )
    for key, count in inventory.items():
        lines.append(f"| {_cell(key.replace('_', ' ').title())} | {_cell(count)} |")

    lines.extend(["", "## Findings", ""])
    findings = report["findings"]
    if not findings:
        lines.append("No findings were identified by the enabled checks.")
    for finding in findings:
        lines.extend(
            [
                f"### [{_cell(finding['severity']).upper()}] {_cell(finding['title'])}",
                "",
                f"- **ID:** {_cell(finding['id'])}",
                f"- **Affected:** {_cell(', '.join(finding['affected_objects']) or 'N/A')}",
                f"- **Evidence:** {_format_evidence(finding['evidence'])}",
                "",
                _cell(finding["description"]),
                "",
                f"**Recommendation:** {_cell(finding['recommendation'])}",
                "",
            ]
        )

    filepath.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return filepath
