"""
Firewall vendor detection.

This module contains logic used to identify the firewall vendor from
a configuration file before parsing begins.

The detected vendor is used to select the appropriate parser.
"""

from pathlib import Path


class VendorDetector:
    """
    Detect the firewall vendor from a configuration file.

    Vendor detection is based on known configuration fingerprints
    associated with supported firewall platforms.
    """

    FINGERPRINTS = {
        "fortigate": [
            "config system interface",
            "config firewall policy",
            "config firewall address",
            "config firewall addrgrp",
        ],
        "cisco": [
            "nameif ",
            "access-list ",
            "object network ",
            "object-group ",
            "aaa-server ",
        ],
    }

    @classmethod
    def detect(cls, filepath: str) -> str:
        """
        Detect the firewall vendor.

        Args:
            filepath: Path to the firewall configuration file.

        Returns:
            The detected vendor name.

        Raises:
            ValueError: If no supported vendor is detected.
        """

        content = Path(filepath).read_text(encoding="utf-8", errors="ignore")

        scores = {vendor: 0 for vendor in cls.FINGERPRINTS}

        for vendor, fingerprints in cls.FINGERPRINTS.items():
            for fingerprint in fingerprints:
                if fingerprint in content:
                    scores[vendor] += 1

        vendor = max(scores, key=scores.get)

        if scores[vendor] == 0:
            raise ValueError("Unable to identify firewall vendor.")

        return vendor
