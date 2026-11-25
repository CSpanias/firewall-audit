"""Parser for FortiOS text configuration backups."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from models.firewall import FirewallConfig
from models.interface import Interface
from models.rule import FirewallRule
from models.vpn import VPN

_TOKEN = re.compile(r'"((?:\\.|[^"\\])*)"|([^\s"]+)')
_VERSION = re.compile(r"^#config-version=(.+?)-(\d+\.\d+\.\d+)-FW-build(\d+)")


@dataclass
class _Node:
    kind: str
    name: tuple[str, ...]
    line: int
    settings: dict[str, list[str]] = field(default_factory=dict)
    children: list[_Node] = field(default_factory=list)


def _tokens(value: str) -> list[str]:
    return [
        match.group(1).replace('\\"', '"') if match.group(1) is not None else match.group(2)
        for match in _TOKEN.finditer(value)
    ]


def _parse_document(lines: list[str]) -> list[_Node]:
    roots: list[_Node] = []
    stack: list[_Node] = []

    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("config "):
            node = _Node("config", tuple(_tokens(line[7:])), line_number)
        elif line.startswith("edit "):
            node = _Node("edit", tuple(_tokens(line[5:])), line_number)
        else:
            command = re.match(r"(set|unset|append|select)\s+(\S+)(?:\s+(.*))?$", line)
            if command and stack:
                operation, key, value = command.groups()
                stack[-1].settings[key] = _tokens(value or "") if operation != "unset" else []
                continue
            if line == "next":
                edit_index = next(
                    (i for i in range(len(stack) - 1, -1, -1) if stack[i].kind == "edit"),
                    None,
                )
                if edit_index is not None:
                    del stack[edit_index:]
                continue
            if line == "end":
                config_index = next(
                    (i for i in range(len(stack) - 1, -1, -1) if stack[i].kind == "config"),
                    None,
                )
                if config_index is not None:
                    del stack[config_index:]
                continue
            continue

        if stack:
            stack[-1].children.append(node)
        else:
            roots.append(node)
        stack.append(node)

    return roots


def _configs(roots: list[_Node], *path: str) -> list[_Node]:
    return [node for node in roots if node.kind == "config" and node.name == path]


def _edits(node: _Node | None) -> list[_Node]:
    if node is None:
        return []
    return [child for child in node.children if child.kind == "edit"]


def _first_config(roots: list[_Node], *path: str) -> _Node | None:
    matches = _configs(roots, *path)
    return matches[0] if matches else None


def _values(node: _Node, key: str) -> list[str]:
    return node.settings.get(key, [])


def _text(node: _Node, key: str, default: str = "") -> str:
    return " ".join(_values(node, key)) or default


def _text_fields(node: _Node, keys: tuple[str, ...]) -> dict[str, str]:
    return {key: _text(node, key) for key in keys if _values(node, key)}


def _is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("-", maxsplit=1)[0].split("/", maxsplit=1)[0])
    except ValueError:
        return False
    return not (
        address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified
    )


def _interface_address(values: list[str]) -> str | None:
    if not values:
        return None
    if values[0].lower() in {"dhcp", "pppoe", "0.0.0.0"}:
        return values[0].lower()
    if len(values) > 1:
        try:
            return str(ipaddress.IPv4Interface(f"{values[0]}/{values[1]}"))
        except ValueError:
            pass
    try:
        return str(ipaddress.ip_interface(values[0]))
    except ValueError:
        return " ".join(values)


def _rule(node: _Node) -> FirewallRule:
    status = _text(node, "status", "enable").lower()
    return FirewallRule(
        id=" ".join(node.name),
        name=_text(node, "name") or None,
        source_zones=_values(node, "srcintf"),
        destination_zones=_values(node, "dstintf"),
        source_addresses=_values(node, "srcaddr"),
        destination_addresses=_values(node, "dstaddr"),
        services=_values(node, "service"),
        action=_text(node, "action").lower(),
        enabled=status != "disable",
        schedule=_text(node, "schedule") or None,
        logging=_text(node, "logtraffic") or None,
        nat=_text(node, "nat").lower() == "enable" if _values(node, "nat") else None,
        comments=_text(node, "comments") or None,
        metadata=_text_fields(
            node,
            (
                "policyid",
                "ippool",
                "poolname",
                "utm-status",
                "inspection-mode",
                "groups",
                "srcaddr-negate",
                "dstaddr-negate",
            ),
        ),
    )


class FortigateParser:
    """Convert FortiOS configuration exports to a vendor-neutral model."""

    def parse(self, filepath: str) -> FirewallConfig:
        """Parse a FortiOS configuration file without retaining credential fields."""
        source = Path(filepath)
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
        roots = _parse_document(lines)
        config = FirewallConfig(vendor="Fortinet")

        for line in lines:
            match = _VERSION.match(line.strip())
            if match:
                config.platform_identifier = match.group(1)
                if config.platform_identifier.upper() == "FGVMAZ":
                    config.platform = "FortiGate-VM (Azure)"
                config.version = match.group(2)
                config.config_build = match.group(3)
                break

        global_settings = _first_config(roots, "system", "global")
        if global_settings:
            config.hostname = _text(global_settings, "hostname") or None

        self._parse_interfaces(roots, config)
        self._parse_zones(roots, config)
        self._parse_addresses(roots, config)
        self._parse_services(roots, config)
        self._parse_rules(roots, config)
        self._parse_vips(roots, config)
        self._parse_vpns(roots, config)
        self._parse_administration(roots, config)
        self._parse_logging(roots, config)
        self._parse_monitoring(roots, config)
        self._parse_session_helpers(roots, config)
        return config

    @staticmethod
    def _parse_interfaces(roots: list[_Node], config: FirewallConfig) -> None:
        block = _first_config(roots, "system", "interface")
        for item in _edits(block):
            name = " ".join(item.name)
            address = _interface_address(_values(item, "ip"))
            services = _values(item, "allowaccess")
            role = _text(item, "role").lower() or None
            enabled = _text(item, "status", "up").lower() not in {"down", "disable"}
            public = bool(address and _is_public_address(address))
            management_services = [
                service
                for service in services
                if service.lower() in {"http", "https", "ssh", "telnet"}
            ]
            config.interfaces.append(name)
            config.interface_details.append(
                Interface(
                    name=name,
                    address=address,
                    role=role,
                    description=_text(item, "description") or None,
                    internet_facing=role == "wan" or public,
                    management=bool(management_services),
                    management_services=management_services,
                    enabled=enabled,
                )
            )

    @staticmethod
    def _parse_zones(roots: list[_Node], config: FirewallConfig) -> None:
        for block in _configs(roots, "system", "zone"):
            for item in _edits(block):
                config.zones[" ".join(item.name)] = _values(item, "interface")

    @staticmethod
    def _parse_addresses(roots: list[_Node], config: FirewallConfig) -> None:
        block = _first_config(roots, "firewall", "address")
        if block:
            for item in _edits(block):
                name = " ".join(item.name)
                config.objects.append(name)
                config.address_definitions[name] = _text_fields(
                    item, ("type", "subnet", "start-ip", "end-ip", "fqdn", "associated-interface")
                )

        for block in _configs(roots, "firewall", "addrgrp"):
            for item in _edits(block):
                name = " ".join(item.name)
                config.object_groups.append(name)
                config.address_groups[name] = _values(item, "member")
                if _text(item, "exclude").lower() == "enable":
                    config.excluded_address_groups.add(name)

    @staticmethod
    def _parse_services(roots: list[_Node], config: FirewallConfig) -> None:
        block = _first_config(roots, "firewall", "service", "custom")
        if block:
            for item in _edits(block):
                config.service_definitions[" ".join(item.name)] = {
                    key: _values(item, key)
                    for key in ("protocol", "tcp-portrange", "udp-portrange", "sctp-portrange")
                    if _values(item, key)
                }

        for block in _configs(roots, "firewall", "service", "group"):
            for item in _edits(block):
                config.service_groups[" ".join(item.name)] = _values(item, "member")

    @staticmethod
    def _parse_rules(roots: list[_Node], config: FirewallConfig) -> None:
        for block in _configs(roots, "firewall", "policy"):
            config.rules.extend(_rule(item) for item in _edits(block))
        for block in _configs(roots, "firewall", "local-in-policy"):
            config.local_in_rules.extend(_rule(item) for item in _edits(block))

    @staticmethod
    def _parse_vips(roots: list[_Node], config: FirewallConfig) -> None:
        for block in _configs(roots, "firewall", "vip"):
            for item in _edits(block):
                fields = _text_fields(
                    item,
                    (
                        "extip",
                        "mappedip",
                        "extport",
                        "mappedport",
                        "protocol",
                        "extintf",
                        "portforward",
                    ),
                )
                fields["name"] = " ".join(item.name)
                config.virtual_ips.append(fields)

    @staticmethod
    def _parse_vpns(roots: list[_Node], config: FirewallConfig) -> None:
        for block in _configs(roots, "vpn", "ipsec", "phase1-interface"):
            for item in _edits(block):
                config.vpns.append(
                    VPN(
                        name=" ".join(item.name),
                        enabled=_text(item, "status", "enable").lower() != "disable",
                        interface=_text(item, "interface") or None,
                        remote_gateway=_text(item, "remote-gw") or None,
                    )
                )

        ssl_block = _first_config(roots, "vpn", "ssl", "settings")
        if ssl_block:
            config.ssl_vpn = _text_fields(
                ssl_block, ("status", "port", "source-interface", "source-address", "servercert")
            )
            if config.ssl_vpn.get("status", "enable").lower() != "disable":
                config.vpns.append(
                    VPN(
                        name="SSL VPN",
                        enabled=True,
                        remote_access=True,
                        kind="ssl",
                    )
                )

    @staticmethod
    def _parse_administration(roots: list[_Node], config: FirewallConfig) -> None:
        admins = _first_config(roots, "system", "admin")
        if admins:
            admin_items = _edits(admins)
            config.admin_account_count = len(admin_items)
            config.remote_auth_admin_count = sum(
                _text(item, "remote-auth").lower() == "enable" for item in admin_items
            )

        for auth_type in ("radius", "ldap", "tacacs+"):
            for block in _configs(roots, "user", auth_type):
                for item in _edits(block):
                    server = _text(item, "server") or _text(item, "primary-server")
                    if server:
                        config.aaa_servers.append(
                            {
                                "type": auth_type.upper(),
                                "name": " ".join(item.name),
                                "server": server,
                            }
                        )

    @staticmethod
    def _parse_logging(roots: list[_Node], config: FirewallConfig) -> None:
        for kind in (
            "syslogd", "syslogd2", "syslogd3", "syslogd4", "fortianalyzer", "fortianalyzer2"
        ):
            for block in _configs(roots, "log", kind, "setting"):
                fields = _text_fields(
                    block,
                    ("status", "server", "server2", "port", "mode", "reliable", "upload-option"),
                )
                config.logging[kind] = fields

    @staticmethod
    def _parse_monitoring(roots: list[_Node], config: FirewallConfig) -> None:
        ntp = _first_config(roots, "system", "ntp")
        if ntp:
            config.ntp = _text_fields(ntp, ("ntpsync", "type", "syncinterval"))
            servers = []
            for child in ntp.children:
                if child.kind == "config" and child.name == ("ntpserver",):
                    servers.extend(
                        _text(item, "server") for item in _edits(child) if _text(item, "server")
                    )
            if servers:
                config.ntp["servers"] = ", ".join(servers)

        snmp_info = _first_config(roots, "system", "snmp", "sysinfo")
        communities = [
            item
            for block in _configs(roots, "system", "snmp", "community")
            for item in _edits(block)
        ]
        snmp_users = [
            item for block in _configs(roots, "system", "snmp", "user") for item in _edits(block)
        ]
        config.snmp = {
            "status": _text(snmp_info, "status", "configured") if snmp_info else "unknown",
            "communities": len(communities),
            "snmpv3_users": len(snmp_users),
        }

    @staticmethod
    def _parse_session_helpers(roots: list[_Node], config: FirewallConfig) -> None:
        for block in _configs(roots, "system", "session-helper"):
            for item in _edits(block):
                config.session_helpers.append(_text_fields(item, ("name", "protocol", "port")))
