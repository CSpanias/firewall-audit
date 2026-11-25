"""CSA Cyber SureFormat XML export."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def export_sureformat(report: dict[str, Any], filepath: Path) -> tuple[Path, int, int]:
    """Write findings that have an explicit SureFormat vulnerability mapping."""
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

    exported = 0
    unmapped = 0
    for finding in report.get("findings", []):
        vulnerability_id = finding.get("sureformat_id")
        if not vulnerability_id:
            unmapped += 1
            continue
        vulnerability = ET.SubElement(vulnerabilities, "vulnerability", id=vulnerability_id)
        details = [
            finding.get("title", ""),
            finding.get("description", ""),
            f"Severity: {finding.get('severity', 'info')}",
            f"Affected: {', '.join(finding.get('affected_objects', []))}",
            f"Recommendation: {finding.get('recommendation', '')}",
        ]
        ET.SubElement(vulnerability, "information").text = "\n\n".join(
            detail for detail in details if detail
        )
        exported += 1

    tree = ET.ElementTree(root)
    ET.indent(tree, space="    ")
    tree.write(filepath, encoding="utf-8", xml_declaration=True)
    return filepath, exported, unmapped
