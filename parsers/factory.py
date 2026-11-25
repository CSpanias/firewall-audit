"""
Parser factory.

This module selects the appropriate parser based on the
detected firewall vendor.
"""

from parsers.cisco import CiscoParser
from parsers.fortigate import FortigateParser
from parsers.watchguard import WatchGuardParser


class ParserFactory:
    """
    Factory for parser selection.
    """

    @staticmethod
    def get_parser(vendor: str) -> FortigateParser | CiscoParser | WatchGuardParser:
        """
        Return the parser associated with a vendor.

        Args:
            vendor: Detected vendor name.

        Returns:
            Parser instance.

        Raises:
            ValueError: Unsupported vendor.
        """

        if vendor == "fortigate":
            return FortigateParser()
        if vendor == "cisco":
            return CiscoParser()
        if vendor == "watchguard":
            return WatchGuardParser()

        raise ValueError(f"No configuration parser is available for detected vendor: {vendor}.")
