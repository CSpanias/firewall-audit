"""Configuration-only review checks for FortiGate data."""

import ipaddress

from analysis.services import LEGACY_NAMES, LEGACY_PORTS, matching_rule_services
from common.finding_definitions import load_finding_definitions
from common.text import number_as_words
from models.finding import Finding, FindingDefinition
from models.firewall import FirewallConfig
from models.rule import FirewallRule

_WILDCARDS = {"any", "all", "*", "0.0.0.0/0", "::/0"}
_ALLOW_ACTIONS = {"accept", "allow", "permit"}
_ADMIN_SERVICES = {"all", "http", "https", "ssh", "telnet", "rdp", "ms-rdp"}
_ADMIN_PORTS = {22, 23, 80, 443, 3389}


def _finding(
    definition: FindingDefinition,
    description_values: dict[str, str],
    affected_objects: list[str],
    evidence: dict[str, object],
) -> Finding:
    return Finding(
        id=definition.id,
        title=definition.title,
        category=definition.category,
        severity=definition.severity,
        description=definition.description.format(**description_values),
        impact=definition.impact,
        recommendation=definition.recommendation,
        affected_objects=affected_objects,
        data=evidence,
        sureformat_id=definition.sureformat_id,
    )


def _is_wildcard(value: str) -> bool:
    return value.strip().lower() in _WILDCARDS


def _is_open(rule: FirewallRule) -> bool:
    return any(map(_is_wildcard, rule.source_addresses)) and any(
        map(_is_wildcard, rule.destination_addresses)
    )


def _expand_address_group(
    name: str, config: FirewallConfig, visited: set[str] | None = None
) -> set[str]:
    visited = visited or set()
    if name in visited:
        return set()
    visited.add(name)
    members = next(
        (value for group, value in config.address_groups.items() if group.lower() == name.lower()),
        None,
    )
    if members is None:
        return {name}
    return set().union(
        *(_expand_address_group(member, config, visited.copy()) for member in members)
    )


def _public_vip(vip: dict[str, str]) -> bool:
    external_ip = vip.get("extip", "")
    try:
        address = ipaddress.ip_address(
            external_ip.split("-", maxsplit=1)[0].split("/", maxsplit=1)[0]
        )
    except ValueError:
        return False
    return not (
        address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified
    )


def _wan_interfaces(config: FirewallConfig) -> set[str]:
    return {
        interface.name.lower()
        for interface in config.interface_details
        if interface.enabled and interface.internet_facing
    }


def _admin_vips(config: FirewallConfig) -> set[str]:
    wan = _wan_interfaces(config)
    return {
        vip["name"]
        for vip in config.virtual_ips
        if _public_vip(vip)
        or any(interface.lower() in wan for interface in vip.get("extintf", "").split())
    }


def run_fortigate_checks(config: FirewallConfig) -> list[Finding]:
    """Run the currently supported FortiGate review checks."""
    definitions = load_finding_definitions()
    findings: list[Finding] = []
    enabled_rules = [
        rule for rule in config.rules if rule.enabled and rule.action.lower() in _ALLOW_ACTIONS
    ]

    unrestricted = [rule for rule in enabled_rules if _is_open(rule)]
    if unrestricted:
        definition = definitions["broad-allow-rule"]
        for rule in unrestricted:
            rule_id = rule.id or "(unnamed)"
            findings.append(
                _finding(
                    definition,
                    {"rule_id": rule_id},
                    [f"Policy {rule_id}"],
                    {
                        "rule_id": rule_id,
                        "source_interfaces": rule.source_zones,
                        "destination_interfaces": rule.destination_zones,
                        "source_addresses": rule.source_addresses,
                        "destination_addresses": rule.destination_addresses,
                        "services": rule.services,
                    },
                )
            )

    exposed_interfaces = [
        interface
        for interface in config.interface_details
        if interface.enabled and interface.internet_facing and interface.management_services
    ]
    if exposed_interfaces:
        definition = definitions["admin-services-on-wan"]
        interface_names = [interface.name for interface in exposed_interfaces]
        services = sorted(
            {
                service
                for interface in exposed_interfaces
                for service in interface.management_services
            }
        )
        findings.append(
            _finding(
                definition,
                {
                    "interfaces": ", ".join(interface_names),
                    "services": ", ".join(services),
                },
                [f"Interface {name}" for name in interface_names],
                {
                    "interfaces": [
                        {
                            "name": interface.name,
                            "address": interface.address,
                            "services": interface.management_services,
                        }
                        for interface in exposed_interfaces
                    ]
                },
            )
        )

    published_vips = _admin_vips(config)
    admin_vip_rules: list[tuple[FirewallRule, list[str]]] = []
    for rule in enabled_rules:
        services = matching_rule_services(rule, config, _ADMIN_SERVICES, _ADMIN_PORTS)
        destinations = set()
        for destination in rule.destination_addresses:
            destinations.update(_expand_address_group(destination, config))
        matches = sorted(destinations & published_vips)
        if matches and services:
            admin_vip_rules.append((rule, services))
    if admin_vip_rules:
        definition = definitions["admin-service-vip-policy"]
        rule_ids = [rule.id for rule, _ in admin_vip_rules]
        services = sorted({service for _, matched in admin_vip_rules for service in matched})
        findings.append(
            _finding(
                definition,
                {"rule_ids": ", ".join(rule_ids), "services": ", ".join(services)},
                [f"Policy {rule_id}" for rule_id in rule_ids],
                {
                    "rules": [
                        {
                            "id": rule.id,
                            "source_addresses": rule.source_addresses,
                            "destination_addresses": rule.destination_addresses,
                            "services": services_for_rule,
                        }
                        for rule, services_for_rule in admin_vip_rules
                    ],
                    "virtual_ips": sorted(published_vips),
                },
            )
        )

    legacy_rules: list[tuple[FirewallRule, list[str]]] = []
    for rule in enabled_rules:
        matched = matching_rule_services(rule, config, LEGACY_NAMES, LEGACY_PORTS)
        if matched:
            legacy_rules.append((rule, matched))
    if legacy_rules:
        admin_vip_ids = {rule.id for rule, _ in admin_vip_rules}
        legacy_rules = [
            (rule, matched)
            for rule, matched in legacy_rules
            if not (rule.id in admin_vip_ids and "all" in {name.lower() for name in matched})
        ]
    if legacy_rules:
        definition = definitions["legacy-service-policy"]
        rule_ids = [rule.id for rule, _ in legacy_rules]
        services = sorted({service for _, matched in legacy_rules for service in matched})
        findings.append(
            _finding(
                definition,
                {"rule_ids": ", ".join(rule_ids), "services": ", ".join(services)},
                [f"Policy {rule_id}" for rule_id in rule_ids],
                {
                    "rules": [
                        {
                            "id": rule.id,
                            "source_interfaces": rule.source_zones,
                            "destination_interfaces": rule.destination_zones,
                            "source_addresses": rule.source_addresses,
                            "destination_addresses": rule.destination_addresses,
                            "services": services_for_rule,
                        }
                        for rule, services_for_rule in legacy_rules
                    ]
                },
            )
        )

    enabled_logging = [
        name
        for name, fields in config.logging.items()
        if fields.get("status", "").lower() == "enable" and fields.get("server")
    ]
    if not enabled_logging:
        definition = definitions["logging-coverage-gap"]
        findings.append(_finding(definition, {}, ["Remote logging configuration"], {}))

    unlogged_rules = [
        rule
        for rule in enabled_rules
        if rule.logging and rule.logging.lower() in {"disable", "off"}
    ]
    if unlogged_rules:
        definition = definitions["policy-logging-gap"]
        rule_ids = [rule.id for rule in unlogged_rules]
        findings.append(
            _finding(
                definition,
                {"rule_ids": ", ".join(rule_ids)},
                [f"Policy {rule_id}" for rule_id in rule_ids],
                {"rules": rule_ids, "logging_values": [rule.logging for rule in unlogged_rules]},
            )
        )

    if config.admin_account_count and not config.aaa_servers:
        definition = definitions["local-admin-auth"]
        findings.append(
            _finding(
                definition,
                {"admin_count": number_as_words(config.admin_account_count)},
                ["Administrator authentication"],
                {
                    "administrator_accounts": config.admin_account_count,
                    "remote_auth_accounts": config.remote_auth_admin_count,
                    "central_authentication_servers": 0,
                },
            )
        )

    if not config.ntp.get("servers"):
        definition = definitions["ntp-server-review"]
        sync_state = config.ntp.get("ntpsync", "not configured")
        findings.append(
            _finding(
                definition,
                {"sync_state": sync_state},
                ["NTP configuration"],
                {"ntp": config.ntp},
            )
        )

    return findings
