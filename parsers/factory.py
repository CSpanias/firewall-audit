"""
Parser factory.

This module selects the appropriate parser based on the
detected firewall vendor.
"""

from parsers.fortigate import FortigateParser


class ParserFactory:
    """
    Factory for parser selection.
    """

    @staticmethod
    def get_parser(vendor: str) -> FortigateParser:
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

        raise ValueError(f"No configuration parser is available for detected vendor: {vendor}.")
