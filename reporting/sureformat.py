"""CSA Cyber SureFormat XML export."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def export_sureformat(report: dict[str, Any], filepath: Path) -> tuple[Path, int, int]:
    """Write the firewall review and findings with explicit SureFormat mappings."""
    root = ET.Element("items", source="SureFormat", version="1.0.0")
    device = report.get("device", {})
    item = ET.SubElement(
        root,
        "item",
        ipaddress="",
        hostname=str(device.get("hostname") or "firewall"),
    )
    services = ET.SubElement(item, "services")
    service = ET.SubElement(
        services, "service", name="Firewall configuration", port="", protocol="tcp"
    )
    vulnerabilities = ET.SubElement(service, "vulnerabilities")

    review = ET.SubElement(vulnerabilities, "vulnerability", id="SC-3393")
    review_information = ET.SubElement(review, "information")
    sections = ["Firewall Configuration Review"]
    for key, title in (
        ("executive_summary", "Executive Summary"),
        ("technical_commentary", "Technical Commentary"),
        ("remediation_guidance", "Remediation Guidance"),
    ):
        if report.get(key):
            sections.append(f"{title}\n\n{report[key]}")
    review_information.text = "\n\n".join(sections)
    mapped = {"SC-3393": review_information}
    unmapped = 0
    for finding in report.get("findings", []):
        vulnerability_id = finding.get("sureformat_id")
        if not vulnerability_id:
            unmapped += 1
            continue
        details = [
            finding.get("title", ""),
            finding.get("description", ""),
            f"Severity: {finding.get('severity', 'info')}",
            f"Affected: {', '.join(finding.get('affected_objects', []))}",
            f"Recommendation: {finding.get('recommendation', '')}",
        ]
        text = "\n\n".join(detail for detail in details if detail)
        if vulnerability_id in mapped:
            information = mapped[vulnerability_id]
            information.text = f"{information.text or ''}\n\n{text}"
        else:
            vulnerability = ET.SubElement(vulnerabilities, "vulnerability", id=vulnerability_id)
            information = ET.SubElement(vulnerability, "information")
            information.text = text
            mapped[vulnerability_id] = information

    tree = ET.ElementTree(root)
    ET.indent(tree, space="    ")
    tree.write(filepath, encoding="utf-8", xml_declaration=True)
    return filepath, len(mapped), unmapped
