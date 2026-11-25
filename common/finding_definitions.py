"""Load and validate the packaged finding catalogue."""

import re
from importlib.resources import files
from typing import Any

import yaml

from models.finding import FindingDefinition

_REQUIRED_FIELDS = ("title", "category", "severity", "description", "recommendation")
_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def load_finding_definitions() -> dict[str, FindingDefinition]:
    """Read finding definitions from the packaged YAML catalogue."""
    catalogue = files("common").joinpath("findings.yaml")
    try:
        raw: Any = yaml.safe_load(catalogue.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid finding catalogue: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("findings"), dict):
        raise ValueError("Finding catalogue must contain a 'findings' mapping.")

    definitions: dict[str, FindingDefinition] = {}
    for finding_id, fields in raw["findings"].items():
        if not isinstance(finding_id, str) or not isinstance(fields, dict):
            raise ValueError("Each finding must have a string ID and a mapping of metadata.")
        missing = [field for field in _REQUIRED_FIELDS if not isinstance(fields.get(field), str)]
        if missing:
            raise ValueError(
                f"Finding '{finding_id}' is missing string field(s): {', '.join(missing)}."
            )

        severity = fields["severity"].lower()
        if severity not in _SEVERITIES:
            raise ValueError(f"Finding '{finding_id}' has unsupported severity '{severity}'.")
        sureformat_id = fields.get("sureformat_id")
        if sureformat_id is not None and (
            not isinstance(sureformat_id, str) or not re.fullmatch(r"SC-\d+", sureformat_id)
        ):
            raise ValueError(f"Finding '{finding_id}' has an invalid SureFormat ID.")

        definitions[finding_id] = FindingDefinition(
            id=finding_id,
            title=fields["title"],
            category=fields["category"],
            severity=severity,
            description=fields["description"],
            recommendation=fields["recommendation"],
            sureformat_id=sureformat_id,
        )

    return definitions
