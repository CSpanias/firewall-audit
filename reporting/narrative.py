"""Build report-ready Markdown from the structured assessment evidence."""

import json
import re
from typing import Any

from common.finding_definitions import load_finding_definitions

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


def _executive_summary(report: dict[str, Any]) -> str:
    device = report.get("device", {})
    hostname = _text(device.get("hostname") or "the supplied firewall")
    vendor = _text(device.get("vendor") or "Unknown vendor")
    if not report.get("checks_run", True):
        return "\n\n".join(
            [
                f"A configuration inventory was generated for **{hostname}** ({vendor}). "
                "The supplied report was not assessed using automated security checks.",
                "The inventory is limited to the information described in the technical "
                "commentary and cannot be used to conclude whether the firewall controls "
                "are effective. A separate configuration review is required to assess "
                "security weaknesses.",
            ]
        )

    summary = [
        f"A firewall configuration review was performed against **{hostname}** ({vendor}) "
        "to identify settings that may increase the organisation's exposure to "
        "unauthorised access or hinder security monitoring."
    ]
    destinations = report.get("logging", {}).get("destinations", {})
    if str(device.get("vendor", "")).lower() == "fortinet" and any(
        fields.get("status", "").lower() == "enable" and fields.get("server")
        for fields in destinations.values()
    ):
        summary.append(
            "Centralised logging destinations were configured, providing a basis for "
            "security monitoring. Log delivery, coverage and retention were not verified."
        )
    findings = report.get("findings", [])
    if findings:
        definitions = load_finding_definitions()
        ordered = sorted(
            findings,
            key=lambda item: _SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 5),
        )
        observations = []
        seen = set()
        for finding in ordered:
            finding_id = finding.get("id")
            if finding_id and finding_id in seen:
                continue
            if finding_id:
                seen.add(finding_id)
            definition = definitions.get(finding_id)
            if definition:
                observations.append(_text(definition.executive_summary.strip()))
            else:
                title = _text(finding.get("title") or "An additional security issue")
                impact = _text(finding.get("impact")) if finding.get("impact") else ""
                observations.append(f"{title} was identified." + (f" {impact}" if impact else ""))
        summary.append("The review identified areas requiring attention. " + " ".join(observations))
        summary.append(
            "Overall, the identified settings should be reviewed with the device owner and "
            "prioritised for remediation according to severity, exposure and business need. "
            "Reassessing the affected controls after changes will help verify that the "
            "intended restrictions and monitoring are in place."
        )
    else:
        summary.append(
            "The applicable automated checks did not identify findings in the "
            "supplied configuration. This does not establish that the firewall is secure "
            "or that all controls have been assessed."
        )
        summary.append(
            "Continue to review the configuration against operational requirements and "
            "reassess controls periodically."
        )

    summary.append(
        "This was a static configuration review; reachability, runtime enforcement and "
        "business justification were not established."
        + (
            " The scope and parsing limitations are described in the technical commentary."
            if report.get("parse_warnings")
            else ""
        )
    )
    return "\n\n".join(summary)


def build_narratives(report: dict[str, Any]) -> dict[str, str]:
    """Create distinct executive, technical, and remediation Markdown sections."""
    device = report.get("device", {})
    inventory = report.get("inventory", {})
    findings = report.get("findings", [])
    commentary = [
        "The following observations are based on the supplied configuration.",
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
        commentary.append("No findings were identified by the applicable checks.")
    for finding in findings:
        sections = [
            f"### {_text(finding.get('title'))}",
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
    references: dict[str, str] = {}
    definitions = load_finding_definitions() if findings else {}
    seen = set()
    for finding in sorted(
        findings,
        key=lambda item: _SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 5),
    ):
        key = finding.get("id")
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        if finding.get("recommendation"):
            recommendations.append(f"- {_text(finding['recommendation'])}")
        if key in definitions:
            for title, url in definitions[key].references:
                references.setdefault(url, title)
    if recommendations:
        remediation = [
            "The following actions should be prioritised according to exposure, "
            "business requirements and the severity of the identified issues:",
            "\n".join(recommendations),
            "Test changes before deployment, document any approved exceptions, and "
            "reassess the affected controls to confirm that the changes are effective.",
        ]
    elif not report.get("checks_run", True):
        remediation = [
            "A configuration review is required to identify security issues and "
            "establish appropriate remediation actions."
        ]
    else:
        remediation = [
            "Continue to review the configuration against operational requirements. "
            "The absence of automated findings does not establish that all controls are effective."
        ]
    if references:
        remediation.append(
            "### References\n\n"
            + "\n".join(f"- [{_text(title)}]({url})" for url, title in references.items())
        )
    return {
        "executive_summary": _executive_summary(report),
        "technical_commentary": "\n\n".join(commentary),
        "remediation_guidance": "\n\n".join(remediation),
    }
