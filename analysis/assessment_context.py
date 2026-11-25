"""Identify explicitly configured address scopes containing assessment IPs."""

import ipaddress
import re
from typing import Any

from common.finding_definitions import load_finding_definitions
from models.finding import Finding
from models.firewall import FirewallConfig

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
AddressRange = tuple[Address, Address, str]
_WILDCARDS = {"any", "any4", "any6", "all", "*"}
_TESTING_TERMS = re.compile(
    r"\b(?:temp(?:orary)?|test(?:ing)?|pentest(?:ing)?|pen\s+test(?:ing)?|"
    r"penetration\s+test(?:ing)?|security\s+assessment|vulnerability\s+assessment)\b",
    re.IGNORECASE,
)


def _expression(value: str) -> AddressRange | None:
    parts = value.split()
    if len(parts) == 2 and parts[0].lower() == "host":
        parts = parts[1:]
    if len(parts) == 2:
        value = f"{parts[0]}/{parts[1]}"
    elif len(parts) == 1:
        value = parts[0]
    else:
        return None
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if network.prefixlen == 0:
        return None
    kind = "host" if network.prefixlen == network.max_prefixlen else "subnet"
    return network.network_address, network.broadcast_address, kind


def _range(start: str, end: str) -> AddressRange | None:
    try:
        first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
    except ValueError:
        return None
    if first.version != last.version or first > last:
        return None
    return first, last, "host" if first == last else "range"


def _resolve(
    reference: str, config: FirewallConfig, visited: set[str]
) -> tuple[list[AddressRange], set[str]]:
    key = reference.casefold()
    if key in _WILDCARDS or reference in {"0.0.0.0/0", "::/0"}:
        return [], set()
    if key in visited:
        return [], {reference}
    visited = visited | {key}
    group = next((name for name in config.address_groups if name.casefold() == key), None)
    if group is not None:
        if group in config.excluded_address_groups:
            return [], {group}
        ranges: list[AddressRange] = []
        unresolved: set[str] = set()
        for member in config.address_groups[group]:
            member_ranges, member_unresolved = _resolve(member, config, visited)
            ranges.extend(member_ranges)
            unresolved.update(member_unresolved)
        return ranges, unresolved
    definition = next(
        (fields for name, fields in config.address_definitions.items() if name.casefold() == key),
        None,
    )
    if definition is not None:
        kind = definition.get("type", "").lower()
        if kind not in {"", "ipmask", "iprange"}:
            return [], {reference}
        if kind == "iprange":
            result = _range(definition.get("start-ip", ""), definition.get("end-ip", ""))
        elif definition.get("host") or definition.get("subnet"):
            result = _expression(definition.get("host") or definition["subnet"])
        elif definition.get("start-ip") and definition.get("end-ip"):
            result = _range(definition["start-ip"], definition["end-ip"])
        elif definition.get("range") and len(definition["range"].split()) == 2:
            result = _range(*definition["range"].split())
        else:
            result = None
        return ([result], set()) if result else ([], {reference})
    result = _expression(reference)
    return ([result], set()) if result else ([], {reference})


def build_assessment_context(config: FirewallConfig, addresses: list[str]) -> dict[str, Any]:
    """Record possible explicit policy matches without changing any findings."""
    ips = list(dict.fromkeys(ipaddress.ip_address(value) for value in addresses))
    if any(isinstance(ip, ipaddress.IPv6Address) and ip.scope_id is not None for ip in ips):
        raise ValueError("Assessment IPv6 addresses cannot include a scope ID.")
    matches: list[dict[str, Any]] = []
    unresolved: list[dict[str, str]] = []
    rules = [("Firewall policy", rule) for rule in config.rules] + [
        ("Local-in policy", rule) for rule in config.local_in_rules
    ]
    for rule_type, rule in rules:
        if config.vendor.lower() == "cisco" and rule_type == "Firewall policy":
            rule_type = "ACL entry"
        for direction, references, negate_key in (
            ("Source", rule.source_addresses, "srcaddr-negate"),
            ("Destination", rule.destination_addresses, "dstaddr-negate"),
        ):
            for reference in references:
                if str(rule.metadata.get(negate_key, "")).lower() == "enable":
                    ranges, unsupported = [], {reference}
                else:
                    ranges, unsupported = _resolve(reference, config, set())
                for item in sorted(unsupported):
                    unresolved.append(
                        {
                            "rule_type": rule_type,
                            "rule_id": rule.id,
                            "direction": direction,
                            "reference": item,
                        }
                    )
                for address in ips:
                    kinds = sorted(
                        {
                            kind
                            for first, last, kind in ranges
                            if address.version == first.version and first <= address <= last
                        }
                    )
                    if kinds:
                        matches.append(
                            {
                                "address": str(address),
                                "rule_type": rule_type,
                                "rule_id": rule.id,
                                "direction": direction,
                                "reference": reference,
                                "match_types": kinds,
                                "enabled": rule.enabled,
                                "action": rule.action,
                            }
                        )
    return {
        "addresses": [str(address) for address in ips],
        "matches": matches,
        "unresolved_references": unresolved,
        "addresses_available": "address_objects" not in config.unavailable_inventory,
    }


def _scope_text(first: Address, last: Address, kind: str) -> str:
    if kind == "host":
        return str(first)
    if kind == "subnet":
        return str(next(ipaddress.summarize_address_range(first, last)))
    return f"{first}-{last}"


def find_temporary_access(
    config: FirewallConfig, assessment_ips: list[str] | None = None
) -> list[Finding]:
    """Flag potential temporary access for review without asserting it is obsolete."""
    context = build_assessment_context(config, assessment_ips) if assessment_ips else None
    matches = context["matches"] if context else []
    rule_type = "ACL entry" if config.vendor.lower() == "cisco" else "Firewall policy"
    rules = [(rule_type, rule) for rule in config.rules] + [
        ("Local-in policy", rule) for rule in config.local_in_rules
    ]
    affected: list[str] = []
    evidence: list[dict[str, Any]] = []
    for kind, rule in rules:
        if not rule.enabled or rule.action.lower() not in {"accept", "allow", "permit", "trust"}:
            continue
        name_match = _TESTING_TERMS.search((rule.name or "").replace("_", " ").replace("-", " "))
        comment_match = _TESTING_TERMS.search(
            (rule.comments or "").replace("_", " ").replace("-", " ")
        )
        hosts = sorted(
            {
                match["address"]
                for match in matches
                if match["rule_type"] == kind
                and match["rule_id"] == rule.id
                and "host" in match["match_types"]
            }
        )
        if not name_match and not comment_match and not hosts:
            continue
        indicators = []
        if name_match:
            indicators.append(f"Rule name contains: {name_match.group()}")
        if comment_match:
            indicators.append(f"Rule comment contains: {comment_match.group()}")
        if hosts:
            indicators.append("Explicit assessment host: " + ", ".join(hosts))
        source_scopes = []
        unresolved_sources = []
        source_negated = str(rule.metadata.get("srcaddr-negate", "")).lower() == "enable"
        destination_negated = str(rule.metadata.get("dstaddr-negate", "")).lower() == "enable"
        if not source_negated:
            for reference in rule.source_addresses:
                ranges, unresolved = _resolve(reference, config, set())
                for first, last, scope_kind in ranges:
                    source_scopes.append(f"{reference}: {_scope_text(first, last, scope_kind)}")
                unresolved_sources.extend(f"{reference}: {item}" for item in sorted(unresolved))
        label = {"ACL entry": "Rule", "Local-in policy": "Local-in policy"}.get(kind, "Policy")
        affected.append(f"{label} {rule.id}")
        evidence.append(
            {
                "id": rule.id,
                "rule_type": kind,
                "name": rule.name,
                "source_addresses": rule.source_addresses,
                "source_address_scopes": list(dict.fromkeys(source_scopes)),
                "unresolved_source_references": list(dict.fromkeys(unresolved_sources)),
                "source_negated": "Yes" if source_negated else "No",
                "destination_addresses": rule.destination_addresses,
                "destination_negated": "Yes" if destination_negated else "No",
                "services": rule.services,
                "schedule": rule.schedule,
                "indicators": indicators,
            }
        )
    if not evidence:
        return []
    definition = load_finding_definitions()["temporary-access-review"]
    return [
        Finding(
            id=definition.id,
            title=definition.title,
            category=definition.category,
            severity=definition.severity,
            description=definition.description.format(
                rule_ids=", ".join(item["id"] for item in evidence)
            ),
            impact=definition.impact,
            recommendation=definition.recommendation,
            affected_objects=affected,
            data={"rules": evidence},
        )
    ]
