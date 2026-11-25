"""Checks for enabled allow rules with unrestricted endpoints."""

from common.finding_definitions import load_finding_definitions
from models.finding import Finding
from models.firewall import FirewallConfig

_WILDCARDS = {"any", "any4", "any6", "all", "*", "0.0.0.0/0", "::/0"}
_ALLOW_ACTIONS = {"accept", "allow", "permit", "trust"}


def find_unrestricted_allow_rules(config: FirewallConfig) -> list[Finding]:
    """Return findings for enabled allow rules with any/all on both endpoints."""
    definition = load_finding_definitions()["broad-allow-rule"]
    findings: list[Finding] = []

    for rule in config.rules:
        if not rule.enabled or rule.action.strip().lower() not in _ALLOW_ACTIONS:
            continue

        source_is_open = any(
            address.strip().lower() in _WILDCARDS for address in rule.source_addresses
        )
        destination_is_open = any(
            address.strip().lower() in _WILDCARDS for address in rule.destination_addresses
        )
        if not (source_is_open and destination_is_open):
            continue
        source_families = {
            family for value in rule.source_addresses for family in _wildcard_families(value)
        }
        destination_families = {
            family for value in rule.destination_addresses for family in _wildcard_families(value)
        }
        if not source_families.intersection(destination_families):
            continue

        rule_id = rule.id or "(unnamed)"
        findings.append(
            Finding(
                id=definition.id,
                title=definition.title,
                category=definition.category,
                severity=definition.severity,
                description=definition.description.format(rule_id=rule_id),
                impact=definition.impact,
                recommendation=definition.recommendation,
                affected_objects=[f"Rule {rule_id}"],
                data={
                    "rule_id": rule_id,
                    "action": rule.action,
                    "source_addresses": rule.source_addresses,
                    "destination_addresses": rule.destination_addresses,
                    "services": rule.services,
                },
                sureformat_id=definition.sureformat_id,
            )
        )

    return findings


def _wildcard_families(value: str) -> set[int]:
    normalized = value.strip().lower()
    if normalized in {"any4", "0.0.0.0/0"}:
        return {4}
    if normalized in {"any6", "::/0"}:
        return {6}
    return {4, 6} if normalized in _WILDCARDS else set()
