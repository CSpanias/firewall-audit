"""
Interface data model.

This module defines the normalised firewall interface object.
"""

from dataclasses import dataclass, field


@dataclass
class Interface:
    """
    Represents a firewall interface.

    Vendor-specific interface definitions are normalised into
    this structure during parsing.
    """

    name: str

    address: str | None = None

    role: str | None = None

    description: str | None = None

    internet_facing: bool = False

    management: bool = False

    management_services: list[str] = field(default_factory=list)

    enabled: bool = True
