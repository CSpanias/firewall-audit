"""
Input validation.

This module provides validation functions used by
firewall-audit workflows before processing begins.
"""

from pathlib import Path


def validate_configuration_file(filepath: str) -> tuple[bool, str]:
    """
    Validate a firewall configuration file.

    Args:
        filepath: Path to a firewall configuration file.

    Returns:
        Tuple containing validation status and message.
    """

    if not Path(filepath).is_file():
        return (False, f"Configuration file not found: {filepath}")

    return (True, "Configuration file found")
