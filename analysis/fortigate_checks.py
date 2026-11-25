"""Configuration-only review checks for FortiGate data."""

import ipaddress
import re

from analysis.assessment_context import exclude_assessment_rules, find_temporary_access
from analysis.services import LEGACY_NAMES, LEGACY_PORTS, matching_rule_services, port_ranges_match
from common.finding_definitions import load_finding_definitions
from common.text import number_as_words
from models.finding import Finding, FindingDefinition
from models.firewall import FirewallConfig
from models.rule import FirewallRule

_WILDCARDS = {"any", "all", "*", "0.0.0.0/0", "::/0"}
_ALLOW_ACTIONS = {"accept", "allow", "permit"}
_ADMIN_SERVICES = {"all", "ssh", "telnet", "rdp", "ms-rdp"}
_ADMIN_PORTS = {22, 23, 3389}


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
    if any(
        str(rule.metadata.get(key, "")).lower() == "enable"
        for key in ("srcaddr-negate", "dstaddr-negate")
    ):
        return False
    return any(map(_is_wildcard, rule.source_addresses)) and any(
        map(_is_wildcard, rule.destination_addresses)
    )


def _expand_address_group(
    name: str, config: FirewallConfig, visited: set[str] | None = None
) -> set[str]:
    visited = visited or set()
    key = name.casefold()
    if key in visited:
        return set()
    visited.add(key)
    members = next(
        (value for group, value in config.address_groups.items() if group.lower() == name.lower()),
        None,
    )
    if members is None:
        return {name}
    if any(group.lower() == name.lower() for group in config.excluded_address_groups):
        return set()
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


def _vip_may_publish_admin(vip: dict[str, str]) -> bool:
    if vip.get("portforward", "").lower() != "enable":
        return True
    if vip.get("protocol", "tcp").lower() != "tcp":
        return False
    return port_ranges_match([vip.get("mappedport", "")], _ADMIN_PORTS)


def _vip_ports_exclude_legacy(rule: FirewallRule, config: FirewallConfig) -> bool:
    if str(rule.metadata.get("dstaddr-negate", "")).lower() == "enable":
        return False
    vips = {vip["name"].casefold(): vip for vip in config.virtual_ips}
    if not rule.destination_addresses:
        return False
    for destination in rule.destination_addresses:
        vip = vips.get(destination.casefold())
        if not vip or vip.get("portforward", "").lower() != "enable":
            return False
        ports = [vip.get("extport", ""), vip.get("mappedport", "")]
        if not all(re.fullmatch(r"\d+(?:-\d+)?", port) for port in ports):
            return False
        for port in ports:
            parts = [int(value) for value in port.split("-")]
            if not (0 <= parts[0] <= parts[-1] <= 65535):
                return False
        if port_ranges_match(ports, LEGACY_PORTS):
            return False
    return True


def run_fortigate_checks(
    config: FirewallConfig, assessment_ips: list[str] | None = None
) -> list[Finding]:
    """Run the currently supported FortiGate review checks."""
    config, _ = exclude_assessment_rules(config, assessment_ips)
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
    admin_vips = {
        vip["name"] for vip in config.virtual_ips
        if vip["name"] in published_vips and _vip_may_publish_admin(vip)
    }
    admin_vip_rules: list[tuple[FirewallRule, dict[str, list[str]]]] = []
    for rule in enabled_rules:
        if str(rule.metadata.get("dstaddr-negate", "")).lower() == "enable":
            continue
        destinations = set()
        for destination in rule.destination_addresses:
            destinations.update(_expand_address_group(destination, config))
        destination_names = {destination.casefold() for destination in destinations}
        matches: dict[str, list[str]] = {}
        for vip in config.virtual_ips:
            if vip["name"] not in admin_vips or vip["name"].casefold() not in destination_names:
                continue
            ports = set(_ADMIN_PORTS)
            extport = vip.get("extport", "")
            if vip.get("portforward", "").lower() == "enable":
                if extport.isdecimal() and int(extport) <= 65535:
                    ports.add(int(extport))
                ports.update(port for port in (80, 443) if port_ranges_match([extport], {port}))
            names = _ADMIN_SERVICES | ({"http"} if 80 in ports else set()) | (
                {"https"} if 443 in ports else set()
            )
            matching_services = matching_rule_services(
                rule, config, names, ports, protocols={"tcp"}
            )
            if matching_services:
                matches[vip["name"]] = matching_services
        if matches:
            admin_vip_rules.append((rule, matches))
    if admin_vip_rules:
        definition = definitions["admin-service-vip-policy"]
        rule_ids = [rule.id for rule, _ in admin_vip_rules]
        services = sorted({
            service for _, matches in admin_vip_rules
            for matched_services in matches.values() for service in matched_services
        })
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
                            "source_negated": (
                                "Yes"
                                if str(rule.metadata.get("srcaddr-negate", "")).lower() == "enable"
                                else "No"
                            ),
                            "destination_addresses": rule.destination_addresses,
                            "services": sorted({
                                service for matched_services in matches.values()
                                for service in matched_services
                            }),
                            "vip_port_mapping": [
                                (
                                    f"{vip['name']}: {vip.get('extport', 'not specified')} -> "
                                    f"{vip.get('mappedport', 'not specified')}"
                                )
                                if vip.get("portforward", "").lower() == "enable"
                                else f"{vip['name']}: no explicit port forwarding"
                                for vip in config.virtual_ips if vip["name"] in matches
                            ],
                            "vip_details": [
                                {
                                    "name": vip["name"],
                                    "references": [
                                        reference for reference in rule.destination_addresses
                                        if vip["name"].casefold() in {
                                            name.casefold()
                                            for name in _expand_address_group(reference, config)
                                        }
                                    ],
                                    "services": matches[vip["name"]],
                                    "port_mapping": (
                                        f"{vip.get('extport', 'not specified')} -> "
                                        f"{vip.get('mappedport', 'not specified')}"
                                        if vip.get("portforward", "").lower() == "enable"
                                        else "No explicit port forwarding"
                                    ),
                                }
                                for vip in config.virtual_ips if vip["name"] in matches
                            ],
                        }
                        for rule, matches in admin_vip_rules
                    ],
                    "virtual_ips": sorted(admin_vips),
                },
            )
        )

    legacy_rules: list[tuple[FirewallRule, list[str]]] = []
    for rule in enabled_rules:
        matched = matching_rule_services(rule, config, LEGACY_NAMES, LEGACY_PORTS)
        if matched and not _vip_ports_exclude_legacy(rule, config):
            legacy_rules.append((rule, matched))
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
                            "source_negated": (
                                "Yes"
                                if str(rule.metadata.get("srcaddr-negate", "")).lower() == "enable"
                                else "No"
                            ),
                            "destination_addresses": rule.destination_addresses,
                            "destination_negated": (
                                "Yes"
                                if str(rule.metadata.get("dstaddr-negate", "")).lower() == "enable"
                                else "No"
                            ),
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
        for rule in config.rules
        if rule.enabled and rule.action.lower() in _ALLOW_ACTIONS | {"deny"}
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

    if config.admin_account_count and (
        not config.aaa_servers or not config.remote_auth_admin_count
    ):
        definition = definitions["local-admin-auth"]
        auth_observation = (
            "No configured RADIUS, LDAP or TACACS+ server was identified."
            if not config.aaa_servers
            else "No administrator account was explicitly configured for remote authentication."
        )
        findings.append(
            _finding(
                definition,
                {
                    "admin_count": number_as_words(config.admin_account_count),
                    "auth_observation": auth_observation,
                },
                ["Administrator authentication"],
                {
                    "administrator_accounts": config.admin_account_count,
                    "remote_auth_accounts": config.remote_auth_admin_count,
                    "central_authentication_servers": len(config.aaa_servers),
                },
            )
        )

    sync_state = config.ntp.get("ntpsync", "not configured")
    if sync_state.lower() == "disable" or not config.ntp.get("servers"):
        definition = definitions["ntp-server-review"]
        findings.append(
            _finding(
                definition,
                {
                    "time_observation": (
                        "NTP synchronisation is explicitly disabled."
                        if sync_state.lower() == "disable"
                        else "No explicit NTP server entry was found."
                    )
                },
                ["NTP configuration"],
                {"ntp": config.ntp},
            )
        )

    findings.extend(find_temporary_access(config, assessment_ips))
    return findings
