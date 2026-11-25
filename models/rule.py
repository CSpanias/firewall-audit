"""
Firewall rule data model.

This module defines the vendor-independent firewall rule object used
throughout firewall-audit.

All vendor parsers should normalise native firewall policies and ACLs
into FirewallRule objects so that analysis modules can operate without
vendor-specific logic.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FirewallRule:
    """
    Represents a normalised firewall rule.

    Vendor-specific policy definitions are converted into this structure
    during parsing, allowing security checks to be performed consistently
    across multiple firewall platforms.
    """

    id: str

    name: str | None = None

    source_zones: list[str] = field(default_factory=list)
    destination_zones: list[str] = field(default_factory=list)

    source_addresses: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)

    services: list[str] = field(default_factory=list)

    action: str = ""
    enabled: bool = True
    schedule: str | None = None
    logging: str | None = None
    nat: bool | None = None
    comments: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
