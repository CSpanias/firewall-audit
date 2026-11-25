"""Parser for Cisco ASA and Firepower Threat Defense text exports."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from models.firewall import FirewallConfig
from models.interface import Interface
from models.rule import FirewallRule
from models.vpn import VPN

_PORTS = {
    "ftp": 21,
    "ftp-data": 20,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "tacacs": 49,
    "domain": 53,
    "tftp": 69,
    "www": 80,
    "http": 80,
    "ntp": 123,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "netbios-ssn": 139,
    "imap4": 143,
    "snmp": 161,
    "snmptrap": 162,
    "ldap": 389,
    "https": 443,
    "isakmp": 500,
    "syslog": 514,
    "rtsp": 554,
    "ldaps": 636,
    "citrix-ica": 1494,
    "sip": 5060,
    "pop3": 110,
}
_PORT_OPERATORS = {"eq", "neq", "lt", "gt", "range"}
_ADDRESS_TYPES = {"object", "object-group", "host", "interface"}
_INTERFACE_TYPES = {"ifc", "object-group-ifc"}


def _port_number(value: str) -> int | None:
    if value.isdecimal():
        number = int(value)
        return number if 0 <= number <= 65535 else None
    return _PORTS.get(value.lower())


def _consume_port(tokens: list[str], position: int) -> tuple[str | None, int]:
    if position >= len(tokens) or tokens[position].lower() not in _PORT_OPERATORS:
        return None, position
    operator = tokens[position].lower()
    count = 2 if operator == "range" else 1
    values = tokens[position + 1 : position + 1 + count]
    if len(values) != count:
        raise ValueError("incomplete port expression")
    numbers = [_port_number(value) for value in values]
    if any(value is None for value in numbers):
        return None, position + 1 + count
    first = numbers[0]
    assert first is not None
    if operator == "eq":
        return str(first), position + 2
    if operator == "range":
        return f"{first}-{numbers[1]}", position + 3
    if operator == "lt":
        return (f"0-{first - 1}" if first else None), position + 2
    if operator == "gt":
        return (f"{first + 1}-65535" if first < 65535 else None), position + 2
    return None, position + 2


def _consume_interface(tokens: list[str], position: int) -> tuple[list[str], int]:
    if position < len(tokens) and tokens[position].lower() in _INTERFACE_TYPES:
        if position + 1 >= len(tokens):
            raise ValueError("incomplete interface qualifier")
        return [tokens[position + 1]], position + 2
    return [], position


def _consume_address(tokens: list[str], position: int) -> tuple[str, int]:
    if position >= len(tokens):
        raise ValueError("missing address")
    token = tokens[position]
    lower = token.lower()
    if lower in {"any", "any4", "any6"}:
        return lower, position + 1
    if lower in _ADDRESS_TYPES:
        if position + 1 >= len(tokens):
            raise ValueError("incomplete address object")
        return tokens[position + 1], position + 2
    try:
        ipaddress.ip_network(token, strict=False)
    except ValueError as exc:
        raise ValueError("unsupported address expression") from exc
    if position + 1 < len(tokens):
        try:
            mask = ipaddress.IPv4Address(tokens[position + 1])
            return str(ipaddress.IPv4Network(f"{token}/{mask}", strict=False)), position + 2
        except (ValueError, ipaddress.AddressValueError):
            pass
    return token, position + 1


def _parse_acl(
    tokens: list[str],
    line_number: int,
    bindings: dict[str, list[str]],
    config: FirewallConfig,
) -> FirewallRule:
    acl = tokens[1]
    position = 2
    if tokens[position].lower() == "line":
        position += 2
    style = tokens[position].lower()
    if style not in {"advanced", "extended"}:
        raise ValueError("unsupported ACL type")
    position += 1
    action = tokens[position].lower()
    if action not in {"permit", "deny", "trust"}:
        raise ValueError("unsupported ACL action")
    position += 1
    protocol = tokens[position]
    position += 1
    if protocol.lower() in {"object", "object-group"}:
        protocol = tokens[position]
        position += 1

    source_zones, position = _consume_interface(tokens, position)
    source, position = _consume_address(tokens, position)
    _, position = _consume_port(tokens, position)
    if (
        position + 1 < len(tokens)
        and tokens[position].lower() == "object-group"
        and tokens[position + 1] in config.service_groups
        and tokens[position + 1] not in config.address_groups
    ):
        position += 2
    destination_zones, position = _consume_interface(tokens, position)
    destination, position = _consume_address(tokens, position)

    service = "ALL" if protocol.lower() in {"ip", "any"} else protocol
    destination_port_specified = False
    if position + 1 < len(tokens) and tokens[position].lower() in {"object", "object-group"}:
        service = tokens[position + 1]
        destination_port_specified = True
        position += 2
    elif position < len(tokens) and tokens[position].lower() in _PORT_OPERATORS:
        start = position
        port, position = _consume_port(tokens, position)
        destination_port_specified = True
        if port:
            service = f"{protocol}/{port}"
            config.service_definitions[service] = {f"{protocol.lower()}-portrange": [port]}
        else:
            service = f"{protocol}/{' '.join(tokens[start:position])}"
            config.parse_warnings.append(
                f"Could not resolve the destination port expression on ACL line {line_number}."
            )
    if protocol.lower() in {"tcp", "udp"} and not destination_port_specified:
        service = f"{protocol.lower()}/*"
        config.service_definitions[service] = {f"{protocol.lower()}-portrange": ["0-65535"]}

    remaining = [token.lower() for token in tokens[position:]]
    rule_id = ""
    if "rule-id" in remaining:
        index = position + remaining.index("rule-id") + 1
        if index < len(tokens):
            rule_id = tokens[index]
    identifier = (
        f"{acl} / rule-id {rule_id} / line {line_number}"
        if rule_id
        else f"{acl} / line {line_number}"
    )
    logging = None
    if "log" in remaining:
        index = remaining.index("log")
        logging = "disable" if remaining[index + 1 : index + 2] == ["disable"] else "enable"
    return FirewallRule(
        id=identifier,
        name=acl,
        source_zones=source_zones,
        destination_zones=destination_zones,
        source_addresses=[source],
        destination_addresses=[destination],
        services=[service],
        action=action,
        enabled="inactive" not in remaining,
        logging=logging,
        metadata={"acl": acl, "rule_id": rule_id, "bindings": bindings.get(acl, [])},
    )


class CiscoParser:
    """Extract inventory and executable ACL entries from ASA/FTD exports."""

    def parse(self, filepath: str) -> FirewallConfig:
        lines = Path(filepath).read_text(encoding="utf-8", errors="replace").splitlines()
        config = FirewallConfig(vendor="Cisco")
        blocks: list[tuple[list[str], list[list[str]]]] = []
        current: tuple[list[str], list[list[str]]] | None = None
        bindings: dict[str, list[str]] = {}
        acl_lines: list[tuple[int, list[str]]] = []

        for number, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith(("!", ":", "#")):
                continue
            tokens = line.split()
            if raw[:1].isspace():
                if current is not None:
                    current[1].append(tokens)
                continue
            current = None
            if tokens[0] == "hostname" and len(tokens) > 1:
                config.hostname = tokens[1]
            elif line.startswith(("NGFW Version ", "ASA Version ")):
                config.version = line.split("Version ", 1)[1].split()[0]
            elif "Cisco Firepower" in line and "Threat Defense" in line:
                config.model = line
            elif tokens[0] in {"interface", "object", "object-group"}:
                current = (tokens, [])
                blocks.append(current)
            elif tokens[0] == "access-group" and len(tokens) >= 3:
                bindings.setdefault(tokens[1], []).append(" ".join(tokens[2:]))
            elif tokens[0] == "access-list" and len(tokens) >= 3:
                acl_lines.append((number, tokens))
            elif tokens[:2] == ["logging", "host"] and len(tokens) >= 4:
                config.logging[f"syslog-{len(config.logging) + 1}"] = {
                    "status": "configured",
                    "server": tokens[3],
                    "interface": tokens[2],
                }
            elif tokens[:2] == ["ntp", "server"] and len(tokens) >= 3:
                servers = config.ntp.get("servers", "")
                config.ntp["servers"] = ", ".join(filter(None, (servers, tokens[2])))
            elif tokens[:2] == ["snmp-server", "community"]:
                config.snmp["communities"] = int(config.snmp.get("communities", 0)) + 1
            elif tokens[:2] == ["snmp-server", "user"]:
                config.snmp["snmpv3_users"] = int(config.snmp.get("snmpv3_users", 0)) + 1
            elif tokens[:2] == ["webvpn", "enable"] and len(tokens) >= 3:
                config.vpns.append(
                    VPN(name="SSL VPN", kind="ssl", remote_access=True, interface=tokens[2])
                )

        for header, body in blocks:
            self._parse_block(header, body, config)
        unsupported: list[int] = []
        standard = 0
        for number, tokens in acl_lines:
            position = 4 if tokens[2].lower() == "line" else 2
            if position >= len(tokens) or tokens[position].lower() == "remark":
                continue
            if tokens[position].lower() == "standard":
                standard += 1
                continue
            try:
                config.rules.append(_parse_acl(tokens, number, bindings, config))
            except (ValueError, IndexError):
                unsupported.append(number)
        if unsupported:
            config.parse_warnings.append(
                f"Could not parse {len(unsupported)} ACL entries; inspect source lines "
                + ", ".join(map(str, unsupported[:20]))
                + (" and subsequent entries." if len(unsupported) > 20 else ".")
            )
        if standard:
            config.parse_warnings.append(
                f"Excluded {standard} standard ACL entries; these may be used "
                "for non-firewall controls."
            )
        if not bindings:
            config.parse_warnings.append(
                "No ACL bindings were identified; access-list applicability "
                "could not be established."
            )
        config.parse_warnings.append(
            "Cisco checks cover bound ACL entries only and do not evaluate policy order, routing, "
            "dynamic objects, NAT reachability, or effective management access."
        )
        if not blocks and not acl_lines:
            raise ValueError("No Cisco configuration blocks or access lists were found.")
        return config

    @staticmethod
    def _parse_block(header: list[str], body: list[list[str]], config: FirewallConfig) -> None:
        if header[0] == "interface" and len(header) >= 2:
            physical = header[1]
            name = next((row[1] for row in body if row[0] == "nameif" and len(row) > 1), physical)
            address = next(
                (
                    " ".join(row[2:4])
                    for row in body
                    if row[:2] == ["ip", "address"] and len(row) >= 3
                ),
                None,
            )
            config.interfaces.append(name)
            config.interface_details.append(
                Interface(
                    name=name,
                    address=address,
                    description=next(
                        (" ".join(row[1:]) for row in body if row[0] == "description"), None
                    ),
                    internet_facing=any(
                        word in name.lower() for word in ("outside", "internet", "wan")
                    ),
                    enabled=not any(row[0] == "shutdown" for row in body),
                )
            )
        elif header[:2] == ["object", "network"] and len(header) >= 3:
            name = header[2]
            config.objects.append(name)
            config.address_definitions[name] = {
                row[0]: " ".join(row[1:])
                for row in body
                if row[0] in {"host", "subnet", "range", "fqdn"}
            }
        elif header[:2] == ["object-group", "interface"] and len(header) >= 3:
            config.zones[header[2]] = [
                row[2]
                for row in body
                if row[:2] == ["interface-object", "interface-name"] and len(row) >= 3
            ]
        elif header[:2] == ["object-group", "network"] and len(header) >= 3:
            name = header[2]
            config.object_groups.append(name)
            config.address_groups[name] = [
                " ".join(row[2:]) if row[:2] == ["network-object", "object"] else " ".join(row[1:])
                for row in body
                if row[0] in {"network-object", "group-object"}
            ]
        elif (
            header[:2] in (["object-group", "service"], ["object", "service"]) and len(header) >= 3
        ):
            name = header[2]
            protocol = header[3].lower() if len(header) >= 4 else ""
            ports: dict[str, list[str]] = {}
            members: list[str] = []
            for row in body:
                if row[0] == "group-object" and len(row) >= 2:
                    members.append(row[1])
                elif row[0] == "port-object":
                    port, _ = _consume_port(row, 1)
                    if port and protocol in {"tcp", "udp"}:
                        ports.setdefault(f"{protocol}-portrange", []).append(port)
                    else:
                        config.parse_warnings.append(
                            f"Could not resolve a port expression in service group {name}."
                        )
                elif row[0] in {"service", "service-object"} and len(row) >= 2:
                    transport = row[1].lower()
                    if transport == "object" and len(row) >= 3:
                        members.append(row[2])
                    elif transport == "ip":
                        members.append("ALL")
                    elif "destination" in row:
                        port, _ = _consume_port(row, row.index("destination") + 1)
                        if port and transport in {"tcp", "udp"}:
                            ports.setdefault(f"{transport}-portrange", []).append(port)
                        else:
                            config.parse_warnings.append(
                                f"Could not resolve a port expression in service definition {name}."
                            )
                    elif transport in {"tcp", "udp"} and len(row) == 2:
                        members.append("ALL")
            if ports:
                inline = f"{name}#ports" if members else name
                config.service_definitions[inline] = ports
                if members:
                    members.append(inline)
            if members:
                config.service_groups[name] = members
