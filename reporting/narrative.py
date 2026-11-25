"""Build report-ready Markdown from the structured assessment evidence."""

import json
import re
from typing import Any

from common.finding_definitions import load_finding_definitions
from common.text import number_as_words

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_LEGACY_SERVICE_CONTEXT = (
    ({"http"}, "HTTP: HTTP does not encrypt application traffic. Sensitive data may be "
     "intercepted or modified by someone with access to the traffic path; the business "
     "purpose and data exchanged should be verified."),
    ({"syslog"}, "Syslog: Traditional Syslog over UDP or TCP is generally unencrypted, "
     "so log messages may be exposed or altered in transit. Syslog can also use TLS; "
     "the service name alone does not establish the transport or encryption in use."),
    ({"samba", "netbios-ns", "netbios-ssn"}, "SMB and NetBIOS: These services may "
     "expose file-sharing or name-service traffic. Confirm the protocols and versions in "
     "use and whether appropriate authentication, signing and encryption are enforced."),
    ({"all"}, "ALL: A broad service definition may permit more protocols than needed "
     "between the specified endpoints. It does not establish which protocols are in use; "
     "review the business requirement and restrict the permitted services where feasible."),
    ({"ftp", "ftp-get", "ftp-put"}, "FTP: Traditional FTP can transmit credentials "
     "and data without encryption. Confirm the protocol and whether a secure alternative "
     "or other protection is used."),
    ({"telnet", "rsh", "rlogin"}, "Telnet, RSH and Rlogin: These legacy remote-access "
     "protocols can expose credentials or commands in transit. Confirm whether they are "
     "used and replace them with secured alternatives where feasible."),
    ({"snmp", "snmptrap"}, "SNMP: Earlier SNMP versions do not provide encryption "
     "and may expose management information or community strings. Verify the version "
     "and security settings; SNMPv3 supports authentication and encryption."),
    ({"tftp"}, "TFTP: TFTP does not provide built-in authentication or encryption, "
     "so transferred data may be exposed or modified. Confirm its use and protect or "
     "replace it where appropriate."),
)


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


def _address_value(entry: dict[str, Any], side: str) -> object:
    value = entry.get(f"{side}_addresses")
    if str(entry.get(f"{side}_negated", "")).lower() != "yes":
        return value
    addresses = ", ".join(str(item) for item in value) if isinstance(value, list) else value
    return f"Except: {addresses or 'Not specified'}"


def _interface_path(entry: dict[str, Any]) -> str:
    def label(value: object) -> str:
        if isinstance(value, list):
            return ", ".join(str(item) for item in value) or "Not specified"
        return str(value) if value else "Not specified"

    return f"{label(entry.get('source_interfaces'))} → {label(entry.get('destination_interfaces'))}"


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
            if key == "rules" and all(
                isinstance(item.get("vip_details"), list) for item in entries
            ):
                rows = []
                for item in entries:
                    for vip in item["vip_details"]:
                        destination = vip["name"]
                        groups = [
                            reference for reference in vip["references"]
                            if reference.casefold() != destination.casefold()
                        ]
                        if groups:
                            destination += f" (via {', '.join(groups)})"
                        rows.append([
                            item.get("id"), _address_value(item, "source"), destination,
                            vip["services"], vip["port_mapping"],
                        ])
                return _table(["Rule", "Source", "Destination", "Services", "Port mapping"], rows)
            has_interfaces = any(
                "source_interfaces" in item or "destination_interfaces" in item for item in entries
            )
            columns = [
                (name, label)
                for name, label in (
                    ("id", "Rule"),
                    ("rule_type", "Rule type"),
                    ("name", "Rule name" if key == "rules" else "Interface"),
                    ("address", "Address"),
                    ("interface_path", "Interfaces (from → to)"),
                    ("source_addresses", "Source addresses"),
                    ("source_address_scopes", "Resolved source scopes"),
                    ("unresolved_source_references", "Unresolved source references"),
                    ("destination_addresses", "Destination addresses"),
                    ("services", "Services"),
                    ("vip_port_mapping", "VIP port mapping"),
                    ("schedule", "Schedule"),
                    ("indicators", "Review indicators"),
                )
                if (
                    has_interfaces
                    if name == "interface_path"
                    else any(name in item for item in entries)
                )
            ]
            if columns:
                def cell(item: dict[str, Any], name: str) -> object:
                    if name in {"source_addresses", "destination_addresses"}:
                        return _address_value(item, name.removesuffix("_addresses"))
                    if name == "interface_path":
                        return _interface_path(item)
                    return item.get(name)

                return _table(
                    [label for _, label in columns],
                    [[cell(item, name) for name, _ in columns] for item in entries],
                )
    rows = [[key.replace("_", " ").title(), value] for key, value in evidence.items()]
    return _table(["Evidence", "Observed configuration"], rows) if rows else ""


def _temporary_access_evidence(evidence: dict[str, Any]) -> str:
    rules = evidence.get("rules")
    if not isinstance(rules, list) or not rules or not all(
        isinstance(rule, dict) for rule in rules
    ):
        return _evidence_table(evidence)
    columns = [
        (name, label)
        for name, label in (
            ("id", "Rule"),
            ("name", "Rule name"),
            ("source_addresses", "Source addresses"),
            ("destination_addresses", "Destination addresses"),
            ("services", "Services"),
        )
        if any(name in rule for rule in rules)
    ]
    if not columns:
        return _evidence_table(evidence)
    table = _table(
        [label for _, label in columns],
        [
            [
                _address_value(rule, name.removesuffix("_addresses"))
                if name in {"source_addresses", "destination_addresses"}
                else rule.get(name)
                for name, _ in columns
            ]
            for rule in rules
        ],
    )
    details = []
    for rule in rules:
        fields = [
            (label, rule.get(name))
            for name, label in (
                ("rule_type", "Rule type"),
                ("schedule", "Schedule"),
                ("indicators", "Review indicators"),
                ("source_address_scopes", "Resolved source scopes"),
                ("unresolved_source_references", "Unresolved source references"),
            )
            if rule.get(name)
        ]
        if fields:
            details.append(
                f"Rule {_text(rule.get('id'))}:\n\n"
                + "\n".join(f"- {label}: {_text(value)}" for label, value in fields)
            )
    return table + ("\n\n" + "\n\n".join(details) if details else "")


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
            f"{subject} referenced public or WAN-facing virtual IPs and "
            "service definitions"
            + (f" including {_prose_list(services)}." if services else ".")
            + " The configurations may permit SSH, Telnet or RDP access. "
            "Source restrictions, the mapped service and reachability require verification."
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
        return (
            "No explicitly enabled destination with a server was identified in the parsed "
            "Syslog or FortiAnalyzer settings. Other collection methods were not assessed."
        )
    if finding_id == "local-admin-auth":
        count = evidence[0].get("administrator_accounts")
        if isinstance(count, int) and count > 0:
            accounts = (
                f"{number_as_words(count).capitalize()} administrator "
                f"account{'s' if count != 1 else ''} {'were' if count != 1 else 'was'} identified"
            )
        else:
            accounts = "Administrator accounts were identified"
        if evidence[0].get("central_authentication_servers") == 0:
            observation = (
                "no RADIUS, LDAP or TACACS+ server was identified in the parsed configuration"
            )
        else:
            observation = (
                "no administrator account was explicitly configured for remote authentication"
            )
        return (
            f"{accounts}; however, {observation}. "
            "Other authentication mechanisms were not assessed."
        )
    if finding_id == "ntp-server-review":
        ntp = evidence[0].get("ntp") or {}
        state = ntp.get("ntpsync", "").lower()
        if state == "enable":
            prefix = "Network Time Protocol (NTP) synchronisation was enabled"
        elif state == "disable":
            prefix = "Network Time Protocol (NTP) synchronisation was disabled"
        else:
            prefix = "The Network Time Protocol (NTP) synchronisation state was not confirmed"
        if ntp.get("servers"):
            return f"{prefix}, despite configured NTP server entries."
        return f"{prefix}; however, no explicit NTP server entries were identified."
    return "\n\n".join(_text(finding.get("description")) for finding in findings)


def _legacy_service_context(findings: list[dict[str, Any]], report: dict[str, Any]) -> str:
    services = {
        str(service).casefold()
        for finding in findings
        for rule in (finding.get("evidence") or {}).get("rules", [])
        if isinstance(rule, dict)
        for service in rule.get("services", [])
    }
    groups = {
        name.casefold(): members
        for name, members in report.get("access_control", {}).get("service_groups", {}).items()
    }
    pending = list(services)
    while pending:
        for member in groups.get(pending.pop(), []):
            name = member.casefold()
            if name not in services:
                services.add(name)
                pending.append(name)
    explanations = [text for names, text in _LEGACY_SERVICE_CONTEXT if names & services]
    if not explanations:
        return ""
    return (
        "The following considerations apply to the referenced service definitions:\n\n"
        + "\n".join(f"- {text}" for text in explanations)
    )


def _management_service_context(finding_id: str, findings: list[dict[str, Any]]) -> str:
    if finding_id == "admin-services-on-wan":
        services = sorted({
            str(service).lower()
            for finding in findings
            for interface in (finding.get("evidence") or {}).get("interfaces", [])
            if isinstance(interface, dict)
            for service in interface.get("services", [])
            if str(service).lower() in {"http", "telnet"}
        })
        if services:
            return (
                f"Management access includes {_prose_list(services)}. These services can "
                "transmit credentials or management traffic without encryption; verify "
                "their use and whether they can be disabled or protected."
            )
    if finding_id == "admin-service-vip-policy":
        rules = [
            rule
            for finding in findings
            for rule in (finding.get("evidence") or {}).get("rules", [])
            if isinstance(rule, dict)
        ]
        forwarded_vips = [
            vip
            for rule in rules
            for vip in rule.get("vip_details", [])
            if isinstance(vip, dict)
            and vip.get("port_mapping")
            and vip["port_mapping"] != "No explicit port forwarding"
        ]
        if forwarded_vips:
            context = (
                "For a port-forwarding VIP, the policy service controls permitted traffic "
                "and the VIP maps an external port to a port on the destination."
            )
            if any(
                str(service).casefold() == "all"
                for vip in forwarded_vips for service in vip.get("services", [])
            ):
                context += (
                    " An ALL policy service does not override the VIP's configured port "
                    "forwarding for traffic to that VIP; other access paths require review."
                )
            return context
    return ""


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
        host_noun = "host was" if len(hosts) == 1 else "hosts were"
        note = f"**Note:** The {host_list} {host_noun} used for testing"
        if not report.get("checks_run", True) or not context["addresses_available"]:
            note += ", but dedicated rules could not be evaluated for exclusion."
        else:
            note += (
                ", therefore, any dedicated rules were identified for exclusion. "
                "Shared and subnet rules remained in scope."
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
        if key == "legacy-service-policy":
            service_context = _legacy_service_context(group, report)
            if service_context:
                sections.append(service_context)
        if key in {"admin-services-on-wan", "admin-service-vip-policy"}:
            management_context = _management_service_context(key, group)
            if management_context:
                sections.append(management_context)
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
        elif key == "temporary-access-review":
            evidence_tables = [
                _temporary_access_evidence(entry.get("evidence") or {}) for entry in group
            ]
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
