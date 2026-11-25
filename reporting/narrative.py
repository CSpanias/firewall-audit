"""Build report-ready Markdown from the structured assessment evidence."""

import json
import re
from collections import Counter
from typing import Any

from common.text import number_as_words

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _text(value: object) -> str:
    if value is None or value == "":
        return "Not specified"
    if isinstance(value, list):
        return ", ".join(_text(item) for item in value) or "None"
    if isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return re.sub(r"([\\`*_{}\[\]<>|])", r"\\\1", str(value)).replace("\n", " ")


def _table(headers: list[str], rows: list[list[object]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(_text(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def _evidence_table(evidence: dict[str, Any]) -> str:
    for key in ("rules", "interfaces"):
        entries = evidence.get(key)
        if (
            isinstance(entries, list)
            and entries
            and all(isinstance(item, dict) for item in entries)
        ):
            columns = [
                (name, label)
                for name, label in (
                    ("id", "Rule"),
                    ("name", "Interface"),
                    ("address", "Address"),
                    ("source_interfaces", "Source interfaces"),
                    ("destination_interfaces", "Destination interfaces"),
                    ("source_addresses", "Source"),
                    ("destination_addresses", "Destination"),
                    ("services", "Services"),
                )
                if any(name in item for item in entries)
            ]
            if columns:
                return _table(
                    [label for _, label in columns],
                    [[item.get(name) for name, _ in columns] for item in entries],
                )
    rows = [[key.replace("_", " ").title(), value] for key, value in evidence.items()]
    return _table(["Evidence", "Observed configuration"], rows) if rows else ""


def build_narratives(report: dict[str, Any]) -> dict[str, str]:
    """Create distinct executive, technical, and remediation Markdown sections."""
    device = report.get("device", {})
    inventory = report.get("inventory", {})
    findings = report.get("findings", [])
    hostname = _text(device.get("hostname") or "the supplied firewall")
    vendor = _text(device.get("vendor") or "Unknown vendor")
    count = len(findings)
    severity = Counter(str(item.get("severity", "info")).lower() for item in findings)
    severity_text = ", ".join(
        f"{number_as_words(severity[level])} {level}"
        for level in ("critical", "high", "medium", "low", "info")
        if severity[level]
    )
    summary = [
        (
            f"A configuration review was performed against **{hostname}** ({vendor})."
            if report.get("checks_run", True)
            else f"A configuration inventory was generated for **{hostname}** ({vendor})."
        )
    ]
    if report.get("checks_run", True):
        summary.append(
            f"The automated checks identified {number_as_words(count)} review "
            f"indicator{'s' if count != 1 else ''}"
            + (f" ({severity_text})." if severity_text else ".")
        )
    else:
        summary.append("No automated security checks were run for this input.")
    if findings:
        titles = list(dict.fromkeys(_text(item.get("title")) for item in findings))
        summary.append("The identified areas include " + "; ".join(titles) + ".")
    elif report.get("checks_run", True):
        summary.append("No indicators were identified by the checks applicable to this input.")
    summary.append(
        "The review is based on a static configuration and does not establish reachability, "
        "runtime enforcement, or business justification. Validate the observations with the "
        "device owner."
    )
    if report.get("parse_warnings"):
        summary.append("The input has parsing limitations described in the technical commentary.")

    commentary = [
        "The following observations are based on the supplied configuration. "
        "Affected entries and evidence should be validated before reporting.",
        "### Configuration overview",
        _table(
            ["Property", "Observed value"],
            [
                ["Vendor", device.get("vendor")],
                ["Hostname", device.get("hostname")],
                ["Model", device.get("model")],
                ["Version", device.get("version")],
                ["Interfaces", inventory.get("interfaces", 0)],
                ["Policies", inventory.get("rules", 0)],
                ["Enabled policies", inventory.get("enabled_rules", 0)],
            ],
        ),
    ]
    if report.get("parse_warnings"):
        commentary.append(
            "### Parsing limitations\n\n"
            + "\n".join(f"- {_text(warning)}" for warning in report["parse_warnings"])
        )
    if not findings and report.get("checks_run", True):
        commentary.append("No review indicators were identified by the applicable checks.")
    for finding in findings:
        sections = [
            f"### {_text(finding.get('title'))} ({_text(finding.get('severity', 'info')).title()})",
            _text(finding.get("description")),
        ]
        if finding.get("impact"):
            sections.append("**Impact:** " + _text(finding["impact"]))
        if finding.get("affected_objects"):
            sections.append("**Affected:** " + _text(finding["affected_objects"]))
        evidence = _evidence_table(finding.get("evidence") or {})
        if evidence:
            sections.append("**Supporting evidence:**\n\n" + evidence)
        commentary.append("\n\n".join(sections))

    recommendations = []
    seen = set()
    for finding in sorted(
        findings,
        key=lambda item: _SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 5),
    ):
        key = finding.get("id")
        if key in seen or not finding.get("recommendation"):
            continue
        seen.add(key)
        recommendations.append(
            f"### {_text(finding.get('title'))}\n\n{_text(finding['recommendation'])}"
        )
    if not recommendations:
        recommendations.append(
            "Review the configuration and validate the assessment scope; the absence of "
            "automated indicators does not establish that all controls are effective."
        )
    return {
        "executive_summary": "\n\n".join(summary),
        "technical_commentary": "\n\n".join(commentary),
        "remediation_guidance": "\n\n".join(recommendations),
    }
