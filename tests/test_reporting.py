"""Tests for FortiOS parsing, checks, and report generation."""

import io
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from html.parser import HTMLParser
from pathlib import Path

from analysis.fortigate_checks import run_fortigate_checks
from cli.audit import run_audit_workflow
from cli.main import build_parser
from common.finding_definitions import load_finding_definitions
from models.firewall import FirewallConfig
from models.rule import FirewallRule
from parsers.fortigate import FortigateParser
from reporting.findings import build_report, export_json
from reporting.html import export_html, render_html
from reporting.sureformat import export_sureformat

ROOT = Path(__file__).resolve().parents[1]

FORTIOS_CONFIG = """\
#config-version=FGT60F-7.4.11-FW-build2878
config system global
    set hostname "edge-fw"
end
config system interface
    edit "wan1"
        set ip 203.0.113.1 255.255.255.0
        set role wan
        set allowaccess ping https ssh
    next
    edit "internal"
        set ip 10.1.0.1 255.255.255.0
        set role lan
    next
end
config system zone
    edit "INTERNAL"
        set interface "internal"
    next
end
config firewall address
    edit "internal-net"
        set subnet 10.1.0.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "target-group"
        set member "published-admin"
    next
end
config firewall service custom
    edit "legacy-web"
        set protocol TCP/UDP/SCTP
        set tcp-portrange 80
    next
end
config firewall service group
    edit "legacy-services"
        set member "legacy-web"
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set logtraffic all
    next
    edit 2
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "target-group"
        set service "HTTPS"
        set action accept
        set logtraffic disable
    next
    edit 3
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "internal-net"
        set dstaddr "all"
        set service "legacy-services"
        set action accept
    next
    edit 4
        set status disable
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
config firewall vip
    edit "published-admin"
        set extip 198.51.100.10
        set mappedip "10.1.0.20"
        set extintf "wan1"
        set portforward enable
        set extport 443
        set mappedport 443
    next
end
config vpn ipsec phase1-interface
    edit "branch-vpn"
        set interface "wan1"
        set remote-gw 192.0.2.10
    next
    edit "retired-vpn"
        set status disable
        set interface "wan1"
    next
end
config system admin
    edit "local-admin"
        set accprofile "super_admin"
        set password "never-include-this-secret"
    next
    edit "radius-admin"
        set remote-auth enable
    next
end
config user radius
    edit "radius-primary"
        set server "10.1.0.50"
        set secret "never-include-this-secret-either"
    next
end
config log syslogd setting
    set status enable
    set server "10.1.0.60"
    set port 601
    set mode reliable
end
config system ntp
    set ntpsync enable
    set type custom
end
config system snmp sysinfo
    set status enable
end
config system session-helper
    edit 1
        set name ftp
        set protocol 6
        set port 21
    next
end
"""


class FortiOSReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        self.directory = Path(self.temp_dir.name)
        self.config_path = self.directory / "fortigate.conf"
        self.config_path.write_text(FORTIOS_CONFIG, encoding="utf-8")
        self.config = FortigateParser().parse(str(self.config_path))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_parser_extracts_device_topology_policies_and_services(self) -> None:
        self.assertEqual(self.config.hostname, "edge-fw")
        self.assertEqual(self.config.model, "FGT60F")
        self.assertEqual(self.config.version, "7.4.11")
        self.assertEqual(self.config.config_build, "2878")
        self.assertEqual(self.config.zones, {"INTERNAL": ["internal"]})
        self.assertEqual(self.config.rules[0].services, ["ALL"])
        self.assertEqual(self.config.rules[1].destination_addresses, ["target-group"])
        self.assertEqual(self.config.address_groups["target-group"], ["published-admin"])
        self.assertEqual(self.config.service_groups["legacy-services"], ["legacy-web"])
        self.assertTrue(self.config.interface_details[0].internet_facing)
        self.assertEqual(self.config.interface_details[0].management_services, ["https", "ssh"])
        self.assertEqual(len(self.config.vpns), 2)
        self.assertEqual(self.config.remote_auth_admin_count, 1)

    def test_checks_cover_unrestricted_admin_vip_legacy_logging_and_ntp(self) -> None:
        findings = run_fortigate_checks(self.config)
        identifiers = {finding.id for finding in findings}

        self.assertEqual(
            identifiers,
            {
                "broad-allow-rule",
                "admin-services-on-wan",
                "admin-service-vip-policy",
                "legacy-service-policy",
                "policy-logging-gap",
                "ntp-server-review",
            },
        )
        vip_finding = next(item for item in findings if item.id == "admin-service-vip-policy")
        self.assertEqual(vip_finding.affected_objects, ["Policy 2"])
        legacy_finding = next(item for item in findings if item.id == "legacy-service-policy")
        self.assertEqual(legacy_finding.affected_objects, ["Policy 1", "Policy 3"])

    def test_missing_central_authentication_is_reviewed(self) -> None:
        self.config.aaa_servers.clear()

        findings = run_fortigate_checks(self.config)

        auth_finding = next(item for item in findings if item.id == "local-admin-auth")
        self.assertIn("two administrator account(s)", auth_finding.description)

    def test_reports_omit_credentials_and_render_offline_html(self) -> None:
        findings = run_fortigate_checks(self.config)
        report = build_report(self.config, findings, self.config_path.name)
        html_path = export_html(report, self.directory / "report.html")
        json_path = export_json(report, self.directory / "report.json")

        html = html_path.read_text(encoding="utf-8")
        json_report = json_path.read_text(encoding="utf-8")
        self.assertIn("Firewall Audit Report", html)
        self.assertIn("Executive Summary", html)
        self.assertIn("Technical Commentary", html)
        self.assertIn("Remediation Guidance", html)
        self.assertIn("Copy All Markdown", html)
        self.assertEqual(html.count(">Copy Markdown</button>"), 3)
        self.assertIn("Supporting evidence", html)
        self.assertNotIn("never-include-this-secret", html)
        self.assertNotIn("never-include-this-secret", json_report)
        self.assertEqual(json.loads(json_report), report)
        self.assertIn("branch-vpn", json.dumps(report))

    def test_html_escapes_untrusted_report_values_inside_embedded_json(self) -> None:
        html = render_html(
            {
                "device": {"hostname": "</script><script>alert(1)</script>"},
                "findings": [],
                "inventory": {},
            }
        )

        self.assertNotIn("</script><script>alert(1)", html)
        self.assertIn("\\u003c", html)

    def test_markdown_copy_payload_matches_narratives_and_includes_evidence(self) -> None:
        report = build_report(self.config, run_fortigate_checks(self.config), "firewall.conf")
        html = render_html(report)

        class PayloadParser(HTMLParser):
            in_payload = False
            payload = ""

            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                self.in_payload = tag == "script" and dict(attrs).get("id") == "markdown-data"

            def handle_data(self, data: str) -> None:
                if self.in_payload:
                    self.payload += data

            def handle_endtag(self, tag: str) -> None:
                if tag == "script":
                    self.in_payload = False

        parser = PayloadParser()
        parser.feed(html)
        markdown = json.loads(parser.payload)
        self.assertEqual(markdown["executive_summary"], report["executive_summary"])
        self.assertEqual(markdown["technical_commentary"], report["technical_commentary"])
        self.assertEqual(markdown["remediation_guidance"], report["remediation_guidance"])
        self.assertIn("| Rule |", markdown["technical_commentary"])
        self.assertIn("Policy 2", markdown["technical_commentary"])
        self.assertIn("## Executive Summary", markdown["all"])
        self.assertIn("## Remediation Guidance", markdown["all"])

    def test_sureformat_export_only_includes_explicitly_mapped_findings(self) -> None:
        findings = run_fortigate_checks(self.config)
        report = build_report(self.config, findings, self.config_path.name)
        report["findings"][0]["sureformat_id"] = "SC-1234"

        xml_path, exported, unmapped = export_sureformat(report, self.directory / "report.xml")
        root = ET.parse(xml_path).getroot()
        mapped = root.findall(".//vulnerability")

        self.assertEqual(exported, 1)
        self.assertEqual(unmapped, len(findings) - 1)
        self.assertEqual([item.attrib["id"] for item in mapped], ["SC-1234"])

    def test_cli_defaults_to_json_and_html(self) -> None:
        arguments = build_parser().parse_args(
            ["--config", str(self.config_path), "--output-dir", str(self.directory)]
        )
        run_audit_workflow(arguments)

        suffixes = {
            path.suffix for path in self.directory.iterdir() if path.name.startswith("fortigate-")
        }
        self.assertEqual(suffixes, {".json", ".html"})

    def test_cli_accepts_csacyber_and_writes_html_and_xml(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit):
            build_parser().parse_args(["--help"])
        self.assertNotIn("--csacyber", output.getvalue())

        arguments = build_parser().parse_args(
            [
                "--config",
                str(self.config_path),
                "--output-dir",
                str(self.directory),
                "--csacyber",
            ]
        )
        run_audit_workflow(arguments)

        suffixes = {
            path.suffix for path in self.directory.iterdir() if path.name.startswith("fortigate-")
        }
        self.assertEqual(suffixes, {".html", ".xml"})

    def test_structured_report_round_trips_as_json(self) -> None:
        report = build_report(self.config, run_fortigate_checks(self.config), "fortigate.conf")
        json_path = export_json(report, self.directory / "roundtrip.json")

        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), report)


class GenericFindingTests(unittest.TestCase):
    def test_only_enabled_allow_rules_open_on_both_sides_are_flagged(self) -> None:
        from analysis.any_any import find_unrestricted_allow_rules

        config = FirewallConfig(
            rules=[
                FirewallRule(
                    id="1",
                    source_addresses=["all"],
                    destination_addresses=["ANY"],
                    action="accept",
                ),
                FirewallRule(
                    id="2",
                    source_addresses=["all"],
                    destination_addresses=["server-net"],
                    action="accept",
                ),
                FirewallRule(
                    id="3",
                    source_addresses=["all"],
                    destination_addresses=["all"],
                    action="deny",
                ),
                FirewallRule(
                    id="4",
                    source_addresses=["all"],
                    destination_addresses=["all"],
                    action="accept",
                    enabled=False,
                ),
            ]
        )

        findings = find_unrestricted_allow_rules(config)
        self.assertEqual([finding.affected_objects for finding in findings], [["Rule 1"]])

    def test_yaml_catalogue_defines_categories_and_valid_severity(self) -> None:
        definition = load_finding_definitions()["broad-allow-rule"]
        self.assertEqual(definition.severity, "high")
        self.assertEqual(definition.category, "access-control")
        self.assertIn("{rule_id}", definition.description)


if __name__ == "__main__":
    unittest.main()
