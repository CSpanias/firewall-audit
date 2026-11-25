"""
Firewall configuration model.

This module defines the top-level FirewallConfig object used by
firewall-audit.

Vendor parsers populate this structure with normalised firewall data,
which is then consumed by analysis and reporting components.
"""

from dataclasses import dataclass, field

from .interface import Interface
from .rule import FirewallRule
from .vpn import VPN


@dataclass
class FirewallConfig:
    """
    Represents a parsed firewall configuration.

    This object contains the inventory and policy information extracted
    from a firewall configuration file. It serves as the common data
    exchange format between parsing, analysis, and reporting modules.
    """

    # ---------------------------------------------------------------------------
    # Device Information
    # ---------------------------------------------------------------------------
    vendor: str = "Unknown"
    hostname: str | None = None
    version: str | None = None
    model: str | None = None

    # ---------------------------------------------------------------------------
    # Network Architecture
    # ---------------------------------------------------------------------------
    interfaces: list[str] = field(default_factory=list)
    interface_details: list[Interface] = field(default_factory=list)
    zones: dict[str, list[str]] = field(default_factory=dict)

    # ---------------------------------------------------------------------------
    # Access Control
    # ---------------------------------------------------------------------------
    objects: list[str] = field(default_factory=list)
    object_groups: list[str] = field(default_factory=list)
    rules: list[FirewallRule] = field(default_factory=list)
    local_in_rules: list[FirewallRule] = field(default_factory=list)
    address_definitions: dict[str, dict[str, str]] = field(default_factory=dict)
    address_groups: dict[str, list[str]] = field(default_factory=dict)
    service_definitions: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    service_groups: dict[str, list[str]] = field(default_factory=dict)
    virtual_ips: list[dict[str, str]] = field(default_factory=list)
    aaa_servers: list[dict[str, str]] = field(default_factory=list)
    logging: dict[str, dict[str, str]] = field(default_factory=dict)
    ntp: dict[str, str] = field(default_factory=dict)
    snmp: dict[str, int | str] = field(default_factory=dict)
    admin_account_count: int = 0
    remote_auth_admin_count: int = 0
    session_helpers: list[dict[str, str]] = field(default_factory=list)
    ssl_vpn: dict[str, str] = field(default_factory=dict)
    config_build: str | None = None
    parse_warnings: list[str] = field(default_factory=list)
    unavailable_inventory: set[str] = field(default_factory=set)
    checks_supported: bool = True

    # ---------------------------------------------------------------------------
    # VPN Security
    # ---------------------------------------------------------------------------
    vpns: list[VPN] = field(default_factory=list)
