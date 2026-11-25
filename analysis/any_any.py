"""Checks for enabled allow rules with unrestricted endpoints."""

from common.finding_definitions import load_finding_definitions
from models.finding import Finding
from models.firewall import FirewallConfig

_WILDCARDS = {"any", "all", "*", "0.0.0.0/0", "::/0"}
_ALLOW_ACTIONS = {"accept", "allow", "permit"}


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

        rule_id = rule.id or "(unnamed)"
        findings.append(
            Finding(
                id=definition.id,
                title=definition.title,
                category=definition.category,
                severity=definition.severity,
                description=definition.description.format(rule_id=rule_id),
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
