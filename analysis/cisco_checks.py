"""Checks applicable to bound Cisco access lists."""

from dataclasses import replace

from analysis.any_any import find_unrestricted_allow_rules
from analysis.assessment_context import find_temporary_access
from analysis.services import LEGACY_NAMES, LEGACY_PORTS, matching_rule_services
from common.finding_definitions import load_finding_definitions
from models.finding import Finding
from models.firewall import FirewallConfig


def run_cisco_checks(
    config: FirewallConfig, assessment_ips: list[str] | None = None
) -> list[Finding]:
    """Review enabled, bound ACL entries without claiming runtime reachability."""
    bound = [rule for rule in config.rules if rule.metadata.get("bindings")]
    findings = find_unrestricted_allow_rules(replace(config, rules=bound))
    legacy = [
        (rule, matching_rule_services(rule, config, LEGACY_NAMES, LEGACY_PORTS))
        for rule in bound
        if rule.enabled and rule.action in {"permit", "trust"}
    ]
    legacy = [(rule, services) for rule, services in legacy if services]
    if legacy:
        definition = load_finding_definitions()["legacy-service-policy"]
        rule_ids = [rule.id for rule, _ in legacy]
        services = sorted({service for _, matched in legacy for service in matched})
        findings.append(
            Finding(
                id=definition.id,
                title=definition.title,
                category=definition.category,
                severity=definition.severity,
                description=definition.description.format(
                    rule_ids=", ".join(rule_ids), services=", ".join(services)
                ),
                impact=definition.impact,
                recommendation=definition.recommendation,
                affected_objects=[f"Rule {rule_id}" for rule_id in rule_ids],
                data={
                    "rules": [
                        {
                            "id": rule.id,
                            "source_addresses": rule.source_addresses,
                            "destination_addresses": rule.destination_addresses,
                            "source_interfaces": rule.source_zones,
                            "destination_interfaces": rule.destination_zones,
                            "services": matched,
                        }
                        for rule, matched in legacy
                    ]
                },
                sureformat_id=definition.sureformat_id,
            )
        )
    findings.extend(find_temporary_access(replace(config, rules=bound), assessment_ips))
    return findings
