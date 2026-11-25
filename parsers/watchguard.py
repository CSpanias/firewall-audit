"""Extract the policy inventory from a WatchGuard Firebox PDF report."""

import re
from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from models.firewall import FirewallConfig
from models.rule import FirewallRule

_HEADER = re.compile(r"\bOrder\s+Status\s+Action\s+Policy Name\s+Log\s+Alarm\b")
_DETAILS = re.compile(r"\bFirewall Policies Details\b")
_ROW = re.compile(r"^\s*\d+\s+(?:Enabled|Disabled)\s+")


def _policy_row(line: str) -> FirewallRule:
    columns = re.split(r"\s{2,}", line.strip())
    if (
        len(columns) < 6
        or not columns[0].isdigit()
        or columns[1] not in {"Enabled", "Disabled"}
        or columns[4] not in {"Enabled", "Disabled"}
        or columns[5] not in {"Enabled", "Disabled"}
    ):
        raise ValueError("unrecognised Firebox policy row")
    return FirewallRule(
        id=columns[0],
        name=columns[3],
        action=columns[2].lower(),
        enabled=columns[1] == "Enabled",
        logging="enable" if columns[4] == "Enabled" else "disable",
    )


class WatchGuardParser:
    """Parse the policy-summary table in Firebox Configuration Report PDFs."""

    def parse(self, filepath: str) -> FirewallConfig:
        try:
            reader = PdfReader(Path(filepath))
            if reader.is_encrypted:
                raise ValueError("Encrypted Firebox PDF reports are not supported.")
            if (
                not reader.pages
                or "Firebox Configuration Report" not in reader.pages[0].extract_text()
            ):
                raise ValueError("The PDF is not a recognised Firebox Configuration Report.")

            config = FirewallConfig(vendor="WatchGuard")
            config.checks_supported = False
            config.unavailable_inventory = {
                "interfaces",
                "zones",
                "address_objects",
                "object_groups",
                "virtual_ips",
                "vpn_tunnels",
                "enabled_vpns",
                "disabled_vpns",
                "administrator_accounts",
                "central_authentication_servers",
            }
            started = False
            finished = False
            malformed = 0
            for page in reader.pages:
                for line in page.extract_text(extraction_mode="layout").splitlines():
                    if not config.model:
                        match = re.match(r"\s*Model:\s*(.+?)\s*$", line)
                        if match:
                            config.model = match.group(1)
                    if _HEADER.search(line):
                        started = True
                        continue
                    if started and _DETAILS.search(line):
                        finished = True
                        break
                    if started and _ROW.match(line):
                        try:
                            config.rules.append(_policy_row(line))
                        except ValueError:
                            malformed += 1
                if finished:
                    break
        except PdfReadError as exc:
            raise ValueError(f"Unable to read PDF report: {exc}") from exc

        if not started:
            raise ValueError("The Firebox policy-summary table was not found in the PDF report.")
        if malformed:
            config.parse_warnings.append(f"Could not parse {malformed} Firebox policy table rows.")
        if not finished:
            config.parse_warnings.append(
                "The end of the Firebox policy-summary table was not found."
            )
        config.parse_warnings.append(
            "The Firebox PDF parser inventories policy order, names, state, action and logging "
            "only. "
            "Source and destination addresses, services, interfaces, and detailed settings are not "
            "parsed; no security checks are run for this report."
        )
        return config
