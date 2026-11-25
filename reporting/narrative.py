"""Build report-ready Markdown from the structured assessment evidence."""

import json
import re
from typing import Any

from common.finding_definitions import load_finding_definitions
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


def _code(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(_code(item) for item in value) or "None"
    if value is None or value == "":
        return "Not specified"
    if not isinstance(value, str):
        return _text(value)
    text = value.replace("\n", " ").replace("\r", " ")
    runs = re.findall(r"`+", text)
    fence = "`" * (max((len(run) for run in runs), default=0) + 1)
    if text.startswith(("`", " ")) or text.endswith(("`", " ")):
        text = f" {text} "
    return f"{fence}{text}{fence}"


def _table(headers: list[str], rows: list[list[object]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        cells = [_text(value) for value in row]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _evidence_table(evidence: dict[str, Any]) -> str:
    if len(evidence) == 1 and isinstance(evidence.get("ntp"), dict):
        labels = {"ntpsync": "NTP synchronisation", "syncinterval": "Sync interval"}
        return _table(
            ["Setting", "Observed value"],
            [
                [labels.get(key, key.replace("_", " ").title()), value]
                for key, value in evidence["ntp"].items()
            ],
        )
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
                    ("rule_type", "Rule type"),
                    ("name", "Rule name" if key == "rules" else "Interface"),
                    ("address", "Address"),
                    ("source_interfaces", "Source interfaces"),
                    ("destination_interfaces", "Destination interfaces"),
                    ("source_addresses", "Source"),
                    ("source_address_scopes", "Resolved source scopes"),
                    ("unresolved_source_references", "Unresolved source references"),
                    ("source_negated", "Source negated"),
                    ("destination_addresses", "Destination"),
                    ("destination_negated", "Destination negated"),
                    ("services", "Services"),
                    ("schedule", "Schedule"),
                    ("indicators", "Review indicators"),
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


def _prose_list(values: list[str]) -> str:
    items = [_code(value) for value in values]
    return ", ".join(items[:-1]) + " and " + items[-1] if len(items) > 1 else items[0]


def _executive_summary(report: dict[str, Any]) -> str:
    device = report.get("device", {})
    hostname = _text(device.get("hostname") or "the supplied firewall")
    if not report.get("checks_run", True):
        return "\n\n".join(
            [
                f"A configuration inventory was generated for {hostname}. "
                "The supplied report was not assessed using automated security checks.",
                "The inventory is limited to the information described in the technical "
                "commentary and cannot be used to conclude whether the firewall controls "
                "are effective. A separate configuration review is required to assess "
                "security weaknesses.",
            ]
        )

    summary = [
        f"A firewall configuration review was performed against {hostname} "
        "to identify settings that could increase exposure to unauthorised access, "
        "weaken network segmentation or reduce the effectiveness of security controls. "
        "This review was limited to a static assessment of the firewall configuration. "
        "Reachability of exposed services, operational effectiveness of controls and "
        "the business justification for individual rules were not independently validated."
        + (
            " The scope and parsing limitations are described in the technical commentary."
            if report.get("parse_warnings")
            else ""
        )
    ]
    destinations = report.get("logging", {}).get("destinations", {})
    logging_configured = str(device.get("vendor", "")).lower() == "fortinet" and any(
        fields.get("status", "").lower() == "enable" and fields.get("server")
        for fields in destinations.values()
    )
    logging_observation = (
        "While centralised logging destinations were configured, log collection, coverage "
        "and retention could not be independently verified."
    )
    ntp = report.get("monitoring", {}).get("ntp", {})
    time_source_configured = (
        str(device.get("vendor", "")).lower() == "fortinet"
        and str(ntp.get("ntpsync", "")).lower() == "enable"
        and bool(ntp.get("servers"))
    )
    positive_observations = int(logging_configured) + int(time_source_configured)
    findings = report.get("findings", [])
    if findings:
        if positive_observations:
            subject = (
                "a positive observation was"
                if positive_observations == 1
                else "a number of positive observations were"
            )
            summary[0] += (
                f" Although {subject} identified, the assessment highlighted areas "
                "requiring further review."
            )
        else:
            summary[0] += " The assessment highlighted areas requiring further review."
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
            if finding_id == "ntp-server-review" and logging_configured:
                observations.append(logging_observation)
                logging_configured = False
            definition = definitions.get(finding_id)
            if definition:
                observations.append(_text(definition.executive_summary.strip()))
            else:
                title = _text(finding.get("title") or "An additional security issue")
                impact = _text(finding.get("impact")) if finding.get("impact") else ""
                observations.append(
                    f"The following issue was identified: {title}."
                    + (f" {impact}" if impact else "")
                )
        if logging_configured:
            observations.append(logging_observation)
        transitions = ("Additionally", "Furthermore", "Moreover", "In addition")
        for index in range(1, len(observations)):
            transition = (
                "Finally"
                if index == len(observations) - 1
                else transitions[(index - 1) % len(transitions)]
            )
            text = observations[index]
            observations[index] = f"{transition}, {text[0].lower()}{text[1:]}"
        summary.append(" ".join(observations))
        improvements = []
        if seen & {
            "broad-allow-rule",
            "admin-service-vip-policy",
            "legacy-service-policy",
            "temporary-access-review",
        }:
            improvements.append("strengthen access controls")
        if seen & {"admin-services-on-wan", "admin-service-vip-policy", "local-admin-auth"}:
            improvements.append("improve administrative security")
        if seen & {"logging-coverage-gap", "policy-logging-gap", "ntp-server-review"}:
            improvements.append("enhance monitoring assurance")
        if len(improvements) > 1:
            areas = ", ".join(improvements[:-1]) + " and " + improvements[-1]
        else:
            areas = improvements[0] if improvements else "strengthen firewall security"
        summary.append(
            f"Overall, the review identified opportunities to {areas}. Remediation activities "
            "should be prioritised according to exposure, business requirements and the "
            "potential impact of the affected services. Following implementation, the affected "
            "controls should be reassessed to confirm that the intended restrictions and "
            "monitoring capabilities are operating as expected."
        )
    else:
        no_findings = (
            "The applicable automated checks did not identify findings in the "
            "supplied configuration. This does not establish that the firewall is secure "
            "or that all controls have been assessed."
        )
        summary.append((logging_observation + " " if logging_configured else "") + no_findings)
        summary.append(
            "Continue to review the configuration against operational requirements and "
            "reassess controls periodically."
        )

    return "\n\n".join(summary)


def _commentary_observation(finding_id: str, findings: list[dict[str, Any]], vendor: str) -> str:
    evidence = [finding.get("evidence") or {} for finding in findings]
    objects = list(
        dict.fromkeys(
            str(item) for finding in findings for item in finding.get("affected_objects", [])
        )
    )
    count = len(objects)
    noun = "rule" if vendor.lower() == "cisco" else "policy"
    plural = "rules" if noun == "rule" else "policies"
    subject = f"{number_as_words(count).capitalize()} enabled {plural if count != 1 else noun}"
    services = list(
        dict.fromkeys(
            str(service)
            for entry in evidence
            for rule in entry.get("rules", [])
            if isinstance(rule, dict)
            for service in rule.get("services", [])
        )
    )
    if finding_id == "broad-allow-rule" and count:
        return f"{subject} permitted traffic with unrestricted source and destination addresses."
    if finding_id == "admin-service-vip-policy" and count:
        return (
            f"{subject} permitted traffic to systems behind public or WAN-facing virtual IPs "
            "using service definitions"
            + (f" including {_prose_list(services)}." if services else ".")
            + " These definitions include or may permit services commonly used for administration."
        )
    if finding_id == "legacy-service-policy" and count:
        return f"{subject} referenced legacy or broadly defined service definitions" + (
            f", including {_prose_list(services)}." if services else "."
        )
    if finding_id == "policy-logging-gap" and count:
        return f"Traffic logging was explicitly disabled on {subject.lower()}."
    if finding_id == "temporary-access-review":
        return (
            "Enabled allow rules explicitly referenced supplied assessment hosts or contained "
            "terms suggesting temporary or testing-related access."
        )
    if finding_id == "admin-services-on-wan":
        return (
            "Administrative services were enabled on interfaces identified as WAN-facing "
            "in the supplied configuration."
        )
    if finding_id == "logging-coverage-gap":
        return "No enabled Syslog or FortiAnalyzer destination was identified in the configuration."
    if finding_id == "local-admin-auth":
        count = evidence[0].get("administrator_accounts")
        if isinstance(count, int) and count > 0:
            accounts = (
                f"{number_as_words(count).capitalize()} administrator "
                f"account{'s' if count != 1 else ''} {'were' if count != 1 else 'was'} identified"
            )
        else:
            accounts = "Administrator accounts were identified"
        return (
            f"{accounts}; however, no Remote Authentication Dial-In User Service (RADIUS), "
            "Lightweight Directory Access Protocol (LDAP) or Terminal Access Controller "
            "Access-Control System Plus (TACACS+) server was found in the supplied configuration."
        )
    if finding_id == "ntp-server-review":
        state = (evidence[0].get("ntp") or {}).get("ntpsync", "").lower()
        if state == "enable":
            prefix = "Network Time Protocol (NTP) synchronisation was enabled"
        elif state == "disable":
            prefix = "Network Time Protocol (NTP) synchronisation was disabled"
        else:
            prefix = "The Network Time Protocol (NTP) synchronisation state was not confirmed"
        return f"{prefix}; however, no explicit NTP server entries were identified."
    return "\n\n".join(_text(finding.get("description")) for finding in findings)


def build_narratives(report: dict[str, Any]) -> dict[str, str]:
    """Create distinct executive, technical, and remediation Markdown sections."""
    device = report.get("device", {})
    inventory = report.get("inventory", {})
    findings = report.get("findings", [])
    vendor = str(device.get("vendor") or "Unknown vendor")
    hostname = _code(device["hostname"]) if device.get("hostname") else "the supplied firewall"
    if not report.get("checks_run", True):
        introduction = (
            f"A configuration inventory was generated for {hostname}. "
            "The supplied report was not assessed using automated security checks."
        )
    elif vendor.lower() == "cisco":
        introduction = (
            f"A firewall configuration review was performed against {hostname}. "
            "The automated checks considered bound access-control "
            "entries for unrestricted endpoints and legacy or broadly defined services."
        )
    elif vendor.lower() == "fortinet":
        introduction = (
            f"A firewall configuration review was performed against {hostname} "
            "to identify settings that could increase exposure to "
            "unauthorised access, weaken network segmentation or reduce the effectiveness "
            "of security controls. The review considered firewall policies, administrative "
            "access controls, logging configuration and supporting infrastructure services."
        )
    else:
        introduction = (
            f"A firewall configuration review was performed against {hostname} "
            "using the available automated checks."
        )
    if device.get("platform"):
        platform_label, platform_value = "Platform", device["platform"]
    elif device.get("platform_identifier"):
        platform_label, platform_value = "Platform identifier", device["platform_identifier"]
    else:
        platform_label, platform_value = "Model", device.get("model")
    commentary = [
        introduction,
        "The table below summarises the available characteristics of the reviewed configuration.",
        "### Configuration overview",
        _table(
            ["Property", "Observed value"],
            [
                ["Vendor", device.get("vendor")],
                ["Hostname", device.get("hostname")],
                [platform_label, platform_value],
                ["Version", device.get("version")],
                ["Interfaces", inventory.get("interfaces", 0)],
                ["Policies", inventory.get("rules", 0)],
                ["Enabled policies", inventory.get("enabled_rules", 0)],
            ],
        ),
    ]
    context = report.get("assessment_context")
    if context:
        hosts = []
        for address in context["addresses"]:
            names = context.get("host_objects", {}).get(address, [])
            hosts.append(f"{_prose_list(names)} ({_code(address)})" if names else _code(address))
        host_list = ", ".join(hosts[:-1]) + " and " + hosts[-1] if len(hosts) > 1 else hosts[0]
        note = f"**Note:** The following assessment hosts were supplied: {host_list}. "
        if not report.get("checks_run", True) or not context["addresses_available"]:
            note += "Dedicated rules could not be evaluated for exclusion."
        elif context["excluded_rules"]:
            note += (
                "Rules dedicated to these hosts were excluded from automated findings; "
                "shared and subnet rules remained in scope."
            )
        else:
            note += (
                "No dedicated rules were identified for exclusion; "
                "shared and subnet rules remained in scope."
            )
        commentary.append(note)
    if report.get("parse_warnings"):
        commentary.append(
            "### Parsing limitations\n\n"
            + "\n".join(f"- {_text(warning)}" for warning in report["parse_warnings"])
        )
    if not findings and report.get("checks_run", True):
        commentary.append("No findings were identified by the applicable checks.")
    grouped: dict[str, list[dict[str, Any]]] = {}
    for index, finding in enumerate(findings):
        key = finding.get("id") or f"unnamed-{index}"
        grouped.setdefault(key, []).append(finding)
    definitions = load_finding_definitions() if findings else {}
    for key, group in sorted(
        grouped.items(),
        key=lambda item: min(
            _SEVERITY_ORDER.get(str(finding.get("severity", "info")).lower(), 5)
            for finding in item[1]
        ),
    ):
        finding = group[0]
        definition = definitions.get(key)
        sections = [
            f"### {_text(definition.commentary_title if definition else finding.get('title'))}",
            _commentary_observation(key, group, vendor),
        ]
        impact = definition.commentary_impact if definition else finding.get("impact")
        if impact:
            sections.append(_text(impact))
        affected = list(
            dict.fromkeys(item for entry in group for item in entry.get("affected_objects", []))
        )
        if key == "broad-allow-rule":
            entries = []
            for entry in group:
                details = entry.get("evidence") or {}
                identifier = details.get("rule_id")
                objects = entry.get("affected_objects") or []
                if not identifier and len(objects) == 1:
                    identifier = re.sub(r"^(Policy|Rule) ", "", objects[0])
                entries.append({"id": identifier, **details})
            evidence_tables = [_evidence_table({"rules": entries})]
        else:
            evidence_tables = [_evidence_table(entry.get("evidence") or {}) for entry in group]
        evidence_tables = [table for table in evidence_tables if table]
        if not evidence_tables and affected:
            evidence_tables = [_table(["Affected objects"], [[item] for item in affected])]
        if evidence_tables:
            introduction = (
                "The table below provides further details of the observed configuration."
                if len(evidence_tables) == 1
                else "The tables below provide further details of the observed configuration."
            )
            sections.append(introduction + "\n\n" + "\n\n".join(evidence_tables))
        commentary.append("\n\n".join(sections))

    recommendations = []
    references: dict[str, str] = {}
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
