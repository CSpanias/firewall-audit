"""
Firewall vendor detection.

This module contains logic used to identify the firewall vendor from
a configuration file before parsing begins.

The detected vendor is used to select the appropriate parser.
"""

from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import PdfReadError


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

        path = Path(filepath)
        with path.open("rb") as source:
            signature = source.read(5)
        if signature == b"%PDF-":
            try:
                pdf = PdfReader(path)
                if pdf.is_encrypted:
                    raise ValueError("Encrypted PDF reports are not supported.")
                if pdf.pages and "Firebox Configuration Report" in pdf.pages[0].extract_text():
                    return "watchguard"
            except PdfReadError as exc:
                raise ValueError(f"Unable to read PDF report: {exc}") from exc
            raise ValueError("The PDF is not a recognised Firebox Configuration Report.")

        content = path.read_text(encoding="utf-8", errors="ignore")

        scores = {vendor: 0 for vendor in cls.FINGERPRINTS}

        for vendor, fingerprints in cls.FINGERPRINTS.items():
            for fingerprint in fingerprints:
                if fingerprint in content:
                    scores[vendor] += 1

        vendor = max(scores, key=scores.get)

        if scores[vendor] == 0:
            raise ValueError("Unable to identify firewall vendor.")

        return vendor
