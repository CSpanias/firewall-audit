"""Regression tests for Cisco ACLs and Firebox PDF policy inventory."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from analysis.cisco_checks import run_cisco_checks
from common.vendor_detection import VendorDetector
from models.finding import Finding
from models.firewall import FirewallConfig
from parsers.cisco import CiscoParser
from parsers.watchguard import WatchGuardParser
from reporting.findings import build_report
from reporting.html import render_html
from reporting.source_evidence import build_source_evidence

ROOT = Path(__file__).resolve().parents[1]

CISCO_CONFIG = (
    """\
NGFW Version 7.4.0
hostname fw-example
interface GigabitEthernet0/0
 nameif outside
 ip address 192.0.2.1 255.255.255.0
!
object network server
 host 10.1.1.1
object-group network targets
 network-object object server
object-group interface TRUST security-zone
 interface-object interface-name inside
object-group service legacy tcp
 port-object eq www
object-group service mixed
 group-object legacy
 service-object udp destination eq ntp
"""
    + (
        "access-list EDGE advanced permit tcp object-group-ifc UNTRUST any object-group-ifc TRUST "
        "object-group targets object-group mixed rule-id 42\n"
    )
    + """\
access-list EDGE extended permit ip any4 any4
access-list EDGE extended permit ip any4 any6
access-list UNUSED extended permit ip any any
access-list EDGE extended deny ip any any
access-group EDGE global
username admin password never-export-this-secret
"""
)


class CiscoParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        self.path = Path(self.temp.name) / "cisco.conf"
        self.path.write_text(CISCO_CONFIG, encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_extracts_ftd_zones_services_acls_and_bindings(self) -> None:
        self.assertEqual(VendorDetector.detect(str(self.path)), "cisco")
        config = CiscoParser().parse(str(self.path))
        self.assertEqual(config.hostname, "fw-example")
        self.assertEqual(config.version, "7.4.0")
        self.assertEqual(config.zones, {"TRUST": ["inside"]})
        self.assertEqual(config.address_groups["targets"], ["server"])
        self.assertEqual(config.service_groups["mixed"], ["legacy", "mixed#ports"])
        self.assertEqual(len(config.rules), 5)
        first = config.rules[0]
        self.assertEqual(first.source_zones, ["UNTRUST"])
        self.assertEqual(first.destination_zones, ["TRUST"])
        self.assertEqual(first.destination_addresses, ["targets"])
        self.assertEqual(first.services, ["mixed"])
        self.assertEqual(first.metadata["rule_id"], "42")
        self.assertEqual(first.metadata["bindings"], ["global"])

        findings = run_cisco_checks(config)
        broad = [finding for finding in findings if finding.id == "broad-allow-rule"]
        self.assertEqual(len(broad), 1)
        self.assertIn("EDGE", broad[0].affected_objects[0])
        legacy = next(finding for finding in findings if finding.id == "legacy-service-policy")
        self.assertTrue(any("rule-id 42" in item for item in legacy.affected_objects))
        self.assertNotIn(
            "never-export-this-secret", render_html(build_report(config, findings, "cisco.conf"))
        )

    def test_unsupported_acl_is_reported_instead_of_silently_discarded(self) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("access-list EDGE extended permit ip unsupported-address any\n")
        config = CiscoParser().parse(str(self.path))
        self.assertTrue(
            any("Could not parse 1 ACL entries" in warning for warning in config.parse_warnings)
        )

    def test_cisco_model_remains_in_the_configuration_overview(self) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("Cisco Firepower 1010 Threat Defense\n")
        config = CiscoParser().parse(str(self.path))
        report = build_report(config, [], self.path.name)
        self.assertEqual(config.model, "Cisco Firepower 1010 Threat Defense")
        self.assertIn(
            "| Model | Cisco Firepower 1010 Threat Defense |", report["technical_commentary"]
        )
        self.assertNotIn("`fw-example` (Cisco)", report["technical_commentary"])

    def test_assessment_ip_resolves_nested_cisco_address_objects(self) -> None:
        config = CiscoParser().parse(str(self.path))
        findings = run_cisco_checks(config, ["10.1.1.1"])
        report = build_report(config, findings, self.path.name, ["10.1.1.1"])
        matches = report["assessment_context"]["matches"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule_type"], "ACL entry")
        self.assertEqual(matches[0]["direction"], "Destination")
        self.assertEqual(matches[0]["reference"], "targets")
        unannotated = build_report(config, run_cisco_checks(config), self.path.name)
        self.assertNotIn("assessment_context", unannotated)
        self.assertIn("legacy-service-policy", [item["id"] for item in unannotated["findings"]])
        legacy = next(item for item in findings if item.id == "legacy-service-policy")
        self.assertNotIn(f"Rule {config.rules[0].id}", legacy.affected_objects)
        self.assertEqual(
            report["assessment_context"]["excluded_rules"][0]["rule_type"], "ACL entry"
        )

    def test_temporary_access_only_flags_enabled_bound_cisco_entries(self) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(
                "object-group network shared-test-hosts\n"
                " network-object host 10.1.1.1\n"
                " network-object host 10.1.1.2\n"
                "access-list EDGE extended permit ip host 10.1.1.1 any\n"
                "access-list EDGE extended permit ip object-group shared-test-hosts any\n"
                "access-list UNUSED extended permit ip host 10.1.1.1 any\n"
                "access-list EDGE extended deny ip host 10.1.1.1 any\n"
            )
        config = CiscoParser().parse(str(self.path))
        findings = run_cisco_checks(config, ["10.1.1.1"])
        temporary = next(item for item in findings if item.id == "temporary-access-review")
        self.assertEqual(len(temporary.affected_objects), 1)
        self.assertTrue(all("EDGE" in rule for rule in temporary.affected_objects))
        self.assertEqual(len(temporary.data["rules"]), 1)

    def test_cisco_evidence_uses_the_original_acl_line(self) -> None:
        config = CiscoParser().parse(str(self.path))
        finding = next(
            item for item in run_cisco_checks(config) if item.id == "legacy-service-policy"
        )
        evidence = build_source_evidence(CISCO_CONFIG, config, [finding])[0]
        source_lines = CISCO_CONFIG.splitlines()
        self.assertTrue(evidence.lines)
        for number, line in evidence.lines:
            self.assertEqual(line, source_lines[number - 1])
            self.assertTrue(line.startswith("access-list EDGE"))
        self.assertIn("not included", evidence.notes[0])
        sample = build_source_evidence(CISCO_CONFIG, config, [finding], sample=True)[0]
        self.assertEqual(sample.lines, evidence.lines[:1])
        self.assertTrue(any("Sample only" in note for note in sample.notes))

    def test_cisco_evidence_omits_acl_lines_with_sensitive_fields(self) -> None:
        source = "access-list EDGE extended permit ip any any secret value\n"
        finding = Finding(
            id="test", title="Test", severity="info", description="",
            affected_objects=["Rule EDGE / line 1"],
        )
        evidence = build_source_evidence(source, FirewallConfig(vendor="Cisco"), [finding])[0]
        self.assertFalse(evidence.lines)
        self.assertTrue(any("may contain sensitive material" in note for note in evidence.notes))


class _Page:
    def __init__(self, text: str, layout: str) -> None:
        self.text = text
        self.layout = layout

    def extract_text(self, extraction_mode: str | None = None) -> str:
        return self.layout if extraction_mode == "layout" else self.text


class WatchGuardParserTests(unittest.TestCase):
    def test_policy_inventory_stops_at_details_and_reports_limitations(self) -> None:
        page = _Page(
            "Firebox Configuration Report",
            """\
Model: Firebox Example
Order  Status  Action  Policy Name  Log  Alarm
1  Enabled  Allow  Web Access  Enabled  Disabled  Any
2  Disabled  Deny  Retired Rule  Disabled  Disabled  Any
Firewall Policies Details
3  Enabled  Allow  Not A Summary Row  Enabled  Disabled
""",
        )
        reader = SimpleNamespace(is_encrypted=False, pages=[page])
        with patch("parsers.watchguard.PdfReader", return_value=reader):
            config = WatchGuardParser().parse("report.pdf")
        self.assertEqual(config.model, "Firebox Example")
        report = build_report(config, [], "report.pdf")
        self.assertIn("| Model | Firebox Example |", report["technical_commentary"])
        report_with_context = build_report(config, [], "report.pdf", ["192.0.2.1"])
        self.assertIn(
            "Dedicated rules could not be evaluated for exclusion",
            report_with_context["technical_commentary"],
        )
        self.assertEqual(
            [(r.id, r.name, r.enabled) for r in config.rules],
            [
                ("1", "Web Access", True),
                ("2", "Retired Rule", False),
            ],
        )
        self.assertEqual(config.rules[0].logging, "enable")
        self.assertTrue(any("no security checks" in warning for warning in config.parse_warnings))

    def test_rejects_pdf_without_policy_summary(self) -> None:
        page = _Page("Firebox Configuration Report", "Report without a policy table")
        with patch(
            "parsers.watchguard.PdfReader",
            return_value=SimpleNamespace(is_encrypted=False, pages=[page]),
        ):
            with self.assertRaisesRegex(ValueError, "policy-summary table"):
                WatchGuardParser().parse("report.pdf")
