"""CSA Cyber SureFormat XML export."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from analysis.services import service_matches
from models.firewall import FirewallConfig
from reporting.narrative import format_review_indicators


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

    def add_mapping(vulnerability_id: str, text: str) -> None:
        if vulnerability_id in mapped:
            information = mapped[vulnerability_id]
            information.text = f"{information.text or ''}\n\n{text}"
        else:
            vulnerability = ET.SubElement(vulnerabilities, "vulnerability", id=vulnerability_id)
            information = ET.SubElement(vulnerability, "information")
            information.text = text
            mapped[vulnerability_id] = information

    service_config = FirewallConfig(
        service_groups=report.get("access_control", {}).get("service_groups", {})
    )
    unmapped = 0
    for finding in report.get("findings", []):
        vulnerability_id = finding.get("sureformat_id")
        if finding.get("id") == "legacy-service-policy":
            rules = [
                rule for rule in (finding.get("evidence") or {}).get("rules", [])
                if isinstance(rule, dict) and any(
                    service_matches(service, service_config, {"all"}, set())
                    for service in rule.get("services", [])
                )
            ]
            if rules:
                rule_label = (
                    "Rule" if str(device.get("vendor", "")).lower() == "cisco" else "Policy"
                )
                affected = ", ".join(f"{rule_label} {rule['id']}" for rule in rules)
                evidence = []
                for rule in rules:
                    fields = []
                    for side in ("source", "destination"):
                        addresses = rule.get(f"{side}_addresses")
                        if addresses:
                            prefix = (
                                "Except: "
                                if str(rule.get(f"{side}_negated", "")).lower() == "yes"
                                else ""
                            )
                            fields.append(f"{side.capitalize()}: {prefix}{', '.join(addresses)}")
                    if rule.get("services"):
                        fields.append(f"Services: {', '.join(rule['services'])}")
                    if fields:
                        evidence.append(f"{rule_label} {rule['id']}: {'; '.join(fields)}")
                evidence_text = "Evidence:\n" + "\n".join(evidence) + "\n\n" if evidence else ""
                add_mapping(
                    "SC-1831",
                    "Broad service definitions require review\n\n"
                    "The following enabled rules reference ALL directly or through a service "
                    "group. This may permit more protocols than required, but the effective "
                    "access also depends on the service definition, address scopes, VIP "
                    "mappings, and other controls. The business requirement and actual "
                    "traffic have not been established.\n\n"
                    f"Severity: {finding.get('severity', 'info')}\n\n"
                    f"Affected: {affected}\n\n"
                    f"{evidence_text}"
                    "Recommendation: Verify the permitted services and business need, and "
                    "restrict access where appropriate.",
                )
                if not vulnerability_id:
                    continue
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
        if finding.get("id") == "temporary-access-review":
            indicators = [
                f"{rule.get('rule_type', 'Rule')} {rule['id']}: "
                + format_review_indicators(rule["indicators"])
                for rule in (finding.get("evidence") or {}).get("rules", [])
                if isinstance(rule, dict) and rule.get("indicators")
            ]
            if indicators:
                details.append("Review indicators:\n" + "\n".join(indicators))
        text = "\n\n".join(detail for detail in details if detail)
        add_mapping(vulnerability_id, text)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="    ")
    tree.write(filepath, encoding="utf-8", xml_declaration=True)
    return filepath, len(mapped), unmapped
