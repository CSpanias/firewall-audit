"""Service-name, group, and port matching shared by firewall checks."""

import re
from typing import Iterable

from models.firewall import FirewallConfig
from models.rule import FirewallRule

LEGACY_NAMES = {
    "all",
    "ftp",
    "ftp-get",
    "ftp-put",
    "http",
    "netbios-ns",
    "netbios-ssn",
    "rlogin",
    "rsh",
    "snmp",
    "snmptrap",
    "telnet",
    "tftp",
}
LEGACY_PORTS = {20, 21, 23, 69, 80, 137, 138, 139, 161, 162, 512, 513, 514}


def port_ranges_match(values: Iterable[str], target_ports: set[int]) -> bool:
    for value in values:
        for token in value.split():
            destination = token.split(":", maxsplit=1)[0]
            match = re.fullmatch(r"(\d+)(?:-(\d+))?", destination)
            if not match:
                continue
            low = int(match.group(1))
            high = int(match.group(2) or low)
            if 0 <= low <= high <= 65535 and any(low <= port <= high for port in target_ports):
                return True
    return False


def service_matches(
    name: str,
    config: FirewallConfig,
    target_names: set[str],
    target_ports: set[int],
    visited: set[str] | None = None,
    *,
    protocols: set[str] | None = None,
) -> bool:
    normalized = name.strip().lower()
    if normalized in target_names:
        return True

    visited = visited or set()
    if normalized in visited:
        return False
    visited.add(normalized)
    members = next(
        (values for group, values in config.service_groups.items() if group.lower() == normalized),
        None,
    )
    if members is not None:
        return any(
            service_matches(
                member, config, target_names, target_ports, visited.copy(), protocols=protocols
            )
            for member in members
        )
    definition = next(
        (
            fields
            for service, fields in config.service_definitions.items()
            if service.lower() == normalized
        ),
        None,
    )
    if definition is None:
        return False
    return port_ranges_match(
        (
            value
            for key in ("tcp-portrange", "udp-portrange", "sctp-portrange")
            if protocols is None or key.split("-", maxsplit=1)[0] in protocols
            for value in definition.get(key, [])
        ),
        target_ports,
    )


def matching_rule_services(
    rule: FirewallRule,
    config: FirewallConfig,
    names: set[str],
    ports: set[int],
    *,
    protocols: set[str] | None = None,
) -> list[str]:
    return [
        service for service in rule.services
        if service_matches(service, config, names, ports, protocols=protocols)
    ]
