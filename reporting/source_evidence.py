"""Select original configuration lines relevant to individual findings."""

import re
import unicodedata
from dataclasses import dataclass

from models.finding import Finding
from models.firewall import FirewallConfig
from models.rule import FirewallRule
from parsers.fortigate import _configs, _edits, _Node, _parse_document

_POLICY_FIELDS = {
    "srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr-negate", "dstaddr-negate",
    "service", "action", "status", "schedule", "logtraffic", "nat",
}
_OBJECT_FIELDS = {
    ("firewall", "address"): {"type", "subnet", "start-ip", "end-ip", "fqdn"},
    ("firewall", "addrgrp"): {"member", "exclude", "exclude-member"},
    ("firewall", "vip"): {
        "extip", "mappedip", "extintf", "portforward", "extport", "mappedport", "protocol",
    },
    ("firewall", "service", "custom"): {
        "protocol", "tcp-portrange", "udp-portrange", "sctp-portrange",
    },
    ("firewall", "service", "group"): {"member"},
}
_ABSENCE_FINDINGS = {"logging-coverage-gap", "local-admin-auth", "ntp-server-review"}
_SAMPLE_LINE_LIMIT = 24
_SENSITIVE_CISCO = re.compile(
    r"\b(?:password|passwd|secret|community|private-key|pre-shared-key|token)\b", re.IGNORECASE
)


@dataclass
class SourceEvidence:
    """Source lines and limitations for a single finding."""

    finding: Finding
    lines: list[tuple[int, str]]
    notes: list[str]


def _safe_line(line: str) -> str:
    return "".join(
        char if char == "\t" or unicodedata.category(char) not in {"Cc", "Cf"} else "?"
        for char in line
    )


def _selected_lines(lines: list[str], node: _Node, fields: set[str]) -> list[tuple[int, str]]:
    selected = [(node.line, _safe_line(lines[node.line - 1]))]
    depth = 1
    for index in range(node.line, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith(("config ", "edit ")):
            depth += 1
        elif stripped in {"next", "end"}:
            depth -= 1
            if depth == 0:
                selected.append((index + 1, _safe_line(lines[index])))
                break
        elif depth == 1:
            match = re.match(r"(?:set|unset|append|select)\s+(\S+)(?:\s|$)", stripped)
            if match and match.group(1).lower() in fields:
                selected.append((index + 1, _safe_line(lines[index])))
    return selected


def _expand_references(references: list[str], groups: dict[str, list[str]]) -> set[str]:
    names: set[str] = set()
    pending = list(references)
    while pending:
        name = pending.pop()
        key = name.casefold()
        if key in names:
            continue
        names.add(key)
        members = next((value for group, value in groups.items() if group.casefold() == key), [])
        pending.extend(members)
    return names


def _affected_rules(config: FirewallConfig, finding: Finding) -> list[tuple[str, FirewallRule]]:
    rules = [("Policy", rule) for rule in config.rules] + [
        ("Local-in policy", rule) for rule in config.local_in_rules
    ]
    return [(kind, rule) for kind, rule in rules if f"{kind} {rule.id}" in finding.affected_objects]


def _fortigate_evidence(
    lines: list[str], roots: list[_Node], config: FirewallConfig, finding: Finding,
    sample: bool = False,
) -> SourceEvidence:
    selected: dict[int, str] = {}
    notes: list[str] = []

    def add(block: _Node, item: _Node | None, fields: set[str]) -> None:
        selected[block.line] = _safe_line(lines[block.line - 1])
        selected.update(_selected_lines(lines, item or block, fields))

    rules = _affected_rules(config, finding)
    if sample:
        rules = rules[:1]
    for kind, rule in rules:
        path = ("firewall", "local-in-policy") if kind == "Local-in policy" else (
            "firewall", "policy"
        )
        for block in _configs(roots, *path):
            for item in _edits(block):
                if " ".join(item.name) == rule.id:
                    fields = _POLICY_FIELDS
                    if sample and finding.id == "admin-service-vip-policy":
                        fields = {
                            "srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr-negate",
                            "dstaddr-negate", "service", "action",
                        }
                    add(block, item, fields)

    addresses = _expand_references(
        [
            reference
            for _, rule in rules
            for reference in (
                rule.destination_addresses
                if sample
                else rule.source_addresses + rule.destination_addresses
            )
        ],
        config.address_groups,
    )
    services = _expand_references(
        [service for _, rule in rules for service in rule.services], config.service_groups
    )
    for path, fields in _OBJECT_FIELDS.items():
        if sample and path[:2] not in {("firewall", "vip"), ("firewall", "service")}:
            continue
        names = services if path[:2] == ("firewall", "service") else addresses
        if sample and finding.id == "admin-service-vip-policy" and path == ("firewall", "vip"):
            names = names & {
                name.casefold() for name in finding.data.get("virtual_ips", [])
                if isinstance(name, str)
            }
        for block in _configs(roots, *path):
            for item in _edits(block):
                if " ".join(item.name).casefold() in names:
                    add(block, item, fields)

    if finding.id == "admin-services-on-wan":
        names = {
            entry["name"].casefold()
            for entry in finding.data.get("interfaces", [])
            if isinstance(entry, dict) and isinstance(entry.get("name"), str)
        }
        for block in _configs(roots, "system", "interface"):
            for item in _edits(block):
                if " ".join(item.name).casefold() in names:
                    add(block, item, {"ip", "role", "status", "allowaccess"})
    elif finding.id == "local-admin-auth":
        for block in _configs(roots, "system", "admin"):
            for item in _edits(block):
                add(block, item, {"remote-auth"})
    elif finding.id == "logging-coverage-gap":
        for kind in ("syslogd", "fortianalyzer", "fortianalyzer2"):
            for block in _configs(roots, "log", kind, "setting"):
                add(block, None, {"status", "server", "server2", "port", "mode"})
    elif finding.id == "ntp-server-review":
        for block in _configs(roots, "system", "ntp"):
            add(block, None, {"ntpsync", "type", "syncinterval"})

    if finding.id in _ABSENCE_FINDINGS:
        notes.append(
            "This is an absence-based observation: excerpts alone cannot prove absence. "
            "The finding reflects the parsed configuration."
        )
    if finding.id == "temporary-access-review":
        notes.append("Rule names and comments are omitted because free text may be sensitive.")
        for rule in finding.data.get("rules", []):
            if isinstance(rule, dict):
                if sample and rules and str(rule.get("id")) != rules[0][1].id:
                    continue
                for indicator in rule.get("indicators", []):
                    rule_id = _safe_line(str(rule.get("id")))
                    notes.append(f"Parsed indicator for rule {rule_id}: {indicator}")
    if not selected:
        notes.append("No selected source lines were available for this finding.")
    ordered = list(selected.items()) if sample else sorted(selected.items())
    return SourceEvidence(finding, ordered, notes)


def _cisco_evidence(lines: list[str], finding: Finding) -> SourceEvidence:
    selected = []
    notes = [
        "Referenced object and service definitions are not included in these ACL excerpts.",
        "ACL lines are shown verbatim; review them for sensitive values before sharing.",
    ]
    for affected in finding.affected_objects:
        match = re.search(r" / line (\d+)$", affected)
        if not affected.startswith("Rule ") or not match:
            continue
        number = int(match.group(1))
        if not 1 <= number <= len(lines) or not lines[number - 1].lstrip().startswith(
            "access-list "
        ):
            notes.append(f"Could not locate the expected ACL entry at line {number}.")
            continue
        line = lines[number - 1]
        if _SENSITIVE_CISCO.search(line):
            notes.append(f"Line {number} was omitted because it may contain sensitive material.")
        else:
            selected.append((number, _safe_line(line)))
    if not selected:
        notes.append("No selected source lines were available for this finding.")
    return SourceEvidence(finding, sorted(set(selected)), notes)


def build_source_evidence(
    source: str, config: FirewallConfig, findings: list[Finding], *, sample: bool = False
) -> list[SourceEvidence]:
    """Return original selected lines without retaining unrelated configuration fields."""
    lines = source.splitlines()
    if config.vendor.lower() == "fortinet":
        roots = _parse_document(lines)
        complete = [_fortigate_evidence(lines, roots, config, finding) for finding in findings]
        selected = (
            [
                _fortigate_evidence(lines, roots, config, finding, sample=True)
                for finding in findings
            ]
            if sample
            else complete
        )
    elif config.vendor.lower() == "cisco":
        complete = [_cisco_evidence(lines, finding) for finding in findings]
        selected = (
            [SourceEvidence(item.finding, item.lines[:1], item.notes.copy()) for item in complete]
            if sample else complete
        )
    else:
        return [
            SourceEvidence(finding, [], ["Source excerpts are not available for this vendor."])
            for finding in findings
        ]
    if sample:
        for item, full in zip(selected, complete):
            item.lines = item.lines[:_SAMPLE_LINE_LIMIT]
            omitted = len(full.lines) - len(item.lines)
            if omitted:
                item.notes.append(
                    f"Sample only: {omitted} selected source line(s) omitted. "
                    "Use --evidence-full to show all selected lines."
                )
    return selected
