"""
VPN data model.

This module defines the normalised VPN object used by
firewall-audit.
"""

from dataclasses import dataclass


@dataclass
class VPN:
    """
    Represents a VPN definition.
    """

    name: str

    enabled: bool = True

    remote_access: bool = False

    interface: str | None = None

    remote_gateway: str | None = None

    kind: str = "ipsec"
