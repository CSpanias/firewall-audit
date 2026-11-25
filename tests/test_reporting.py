"""Tests for FortiOS parsing, checks, and report generation."""

import io
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from html.parser import HTMLParser
from pathlib import Path

from rich.console import Console

from analysis.fortigate_checks import run_fortigate_checks
from cli.audit import run_audit_workflow
from cli.main import build_parser
from common.finding_definitions import load_finding_definitions
from common.tables import build_configuration_summary_table
from models.firewall import FirewallConfig
from models.rule import FirewallRule
from parsers.fortigate import FortigateParser
from reporting.findings import build_report, export_json
from reporting.html import export_html, render_html
from reporting.markdown import export_markdown
from reporting.narrative import build_narratives
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
        self.assertIsNone(self.config.model)
        self.assertIsNone(self.config.platform)
        self.assertEqual(self.config.platform_identifier, "FGT60F")
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

    def test_azure_platform_comes_from_the_fortios_header(self) -> None:
        self.config_path.write_text(
            FORTIOS_CONFIG.replace("FGT60F-7.4.11", "FGVMAZ-7.4.11"),
            encoding="utf-8",
        )
        config = FortigateParser().parse(str(self.config_path))
        report = build_report(config, [], self.config_path.name)
        commentary = report["technical_commentary"]

        self.assertIsNone(config.model)
        self.assertEqual(config.platform_identifier, "FGVMAZ")
        self.assertEqual(report["device"]["platform"], "FortiGate-VM (Azure)")
        self.assertEqual(report["device"]["platform_identifier"], "FGVMAZ")
        self.assertIn("| Platform | FortiGate-VM (Azure) |", commentary)
        self.assertIn("against `edge-fw` to identify", commentary)
        self.assertNotIn("`edge-fw` (Fortinet)", commentary)
        self.assertNotIn("FGVMAZ", commentary)
        self.assertIn("FortiGate-VM (Azure)", render_html(report))
        markdown_path = export_markdown(report, self.directory / "report.md")
        self.assertIn("| Platform | FortiGate-VM (Azure) |", markdown_path.read_text())
        output = io.StringIO()
        Console(file=output, width=120, no_color=True).print(
            build_configuration_summary_table(config)
        )
        self.assertIn("FortiGate-VM (Azure)", output.getvalue())
        self.assertNotIn("FGVMAZ", output.getvalue())

    def test_unrecognised_header_is_not_guessed_as_an_azure_platform(self) -> None:
        report = build_report(self.config, [], self.config_path.name)

        self.assertIsNone(report["device"]["platform"])
        self.assertEqual(report["device"]["platform_identifier"], "FGT60F")
        self.assertIn("| Platform identifier | FGT60F |", report["technical_commentary"])
        self.assertNotIn("FortiGate-VM (Azure)", report["technical_commentary"])

    def test_missing_header_does_not_infer_a_platform(self) -> None:
        self.config_path.write_text(
            FORTIOS_CONFIG.split("\n", 1)[1],
            encoding="utf-8",
        )
        config = FortigateParser().parse(str(self.config_path))
        self.assertIsNone(config.platform)
        self.assertIsNone(config.platform_identifier)
        self.assertIsNone(config.model)

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
        self.assertIn("The table below provides further details", html)
        self.assertNotIn("<strong>", html)
        self.assertNotIn("validated before reporting", html)
        self.assertIn(
            "### Administrative Services Permitted via Virtual IPs\n",
            report["technical_commentary"],
        )
        self.assertNotIn("WAN-facing VIP (High)", report["technical_commentary"])
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
        self.assertNotIn("**", markdown["all"])
        self.assertIn("| Rule |", markdown["technical_commentary"])
        self.assertIn("| 2 |", markdown["technical_commentary"])
        self.assertNotIn("Affected policies:", markdown["technical_commentary"])
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

    def test_cli_writes_to_default_output_directory(self) -> None:
        arguments = build_parser().parse_args(["--config", str(self.config_path)])
        previous_directory = Path.cwd()
        try:
            os.chdir(self.directory)
            run_audit_workflow(arguments)
        finally:
            os.chdir(previous_directory)

        output = self.directory / "firewall-audit"
        self.assertEqual({path.suffix for path in output.iterdir()}, {".json", ".html"})

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


class ExecutiveSummaryTests(unittest.TestCase):
    def test_prioritises_and_deduplicates_observations_with_business_impact(self) -> None:
        report = {
            "device": {"hostname": "edge-fw", "vendor": "Fortinet"},
            "findings": [
                {"id": "ntp-server-review", "severity": "medium"},
                {"id": "broad-allow-rule", "severity": "high"},
                {"id": "broad-allow-rule", "severity": "high"},
            ],
        }

        summary = build_narratives(report)["executive_summary"]

        self.assertIn("edge-fw (Fortinet)", summary)
        self.assertNotIn("**", summary)
        self.assertEqual(summary.count("Some firewall policies"), 1)
        self.assertLess(summary.index("Some firewall policies"), summary.index("time source"))
        self.assertIn("unintended connections", summary)
        self.assertIn("effectiveness of security investigations", summary)
        self.assertIn("Remediation activities should be prioritised", summary)
        self.assertNotIn("The identified areas include", summary)

    def test_no_findings_does_not_claim_the_firewall_is_secure(self) -> None:
        summary = build_narratives({"findings": [], "parse_warnings": ["Limited scope"]})[
            "executive_summary"
        ]

        self.assertIn("applicable automated checks did not identify findings", summary)
        self.assertIn("does not establish that the firewall is secure", summary)
        self.assertIn("scope and parsing limitations", summary)

    def test_logging_observation_requires_an_enabled_destination(self) -> None:
        report = {
            "device": {"vendor": "Fortinet"},
            "findings": [],
            "logging": {"destinations": {"syslog": {"status": "disable", "server": "log"}}},
        }
        summary = build_narratives(report)["executive_summary"]
        self.assertNotIn("centralised logging destinations were configured", summary)

        report["logging"]["destinations"]["syslog"]["status"] = "enable"
        summary = build_narratives(report)["executive_summary"]
        self.assertIn("centralised logging destinations were configured", summary)
        self.assertIn("log collection, coverage and retention could not be independently", summary)

    def test_summary_flows_from_findings_to_logging_and_time(self) -> None:
        report = {
            "device": {"hostname": "edge-fw", "vendor": "Fortinet"},
            "logging": {"destinations": {"syslog": {"status": "enable", "server": "log"}}},
            "findings": [
                {"id": "admin-service-vip-policy", "severity": "high"},
                {"id": "legacy-service-policy", "severity": "high"},
                {"id": "local-admin-auth", "severity": "medium"},
                {"id": "ntp-server-review", "severity": "medium"},
            ],
        }

        paragraphs = build_narratives(report)["executive_summary"].split("\n\n")

        self.assertEqual(len(paragraphs), 4)
        self.assertIn("Although a centralised logging destination was configured", paragraphs[0])
        self.assertIn("assessment highlighted areas requiring further review", paragraphs[0])
        observations = paragraphs[1]
        self.assertTrue(observations.startswith("Firewall policies permitted"))
        self.assertIn("Additionally, some policies", observations)
        self.assertIn("Furthermore, no central authentication service", observations)
        self.assertIn("Moreover, the collection, coverage and retention", observations)
        self.assertIn("Finally, the configured time source", observations)
        self.assertEqual(observations.count("Finally,"), 1)
        self.assertLess(observations.index("system administration"), observations.index("legacy"))
        self.assertLess(observations.index("authentication service"), observations.index("logs"))
        self.assertLess(observations.index("logs"), observations.index("time source"))
        self.assertIn("Network Time Protocol (NTP)", observations)
        self.assertIn("strengthen access controls", paragraphs[2])
        self.assertIn("improve administrative security", paragraphs[2])
        self.assertIn("enhance monitoring assurance", paragraphs[2])
        self.assertIn("static assessment", paragraphs[3])

    def test_one_observation_has_no_final_transition_or_unsupported_positive_claim(self) -> None:
        report = {"findings": [{"id": "broad-allow-rule", "severity": "high"}]}

        paragraphs = build_narratives(report)["executive_summary"].split("\n\n")

        self.assertIn("assessment highlighted areas requiring further review", paragraphs[0])
        self.assertNotIn("Although", paragraphs[0])
        self.assertTrue(paragraphs[1].startswith("Some firewall policies"))
        self.assertNotIn("Finally,", paragraphs[1])

    def test_final_transition_preserves_unknown_finding_names(self) -> None:
        report = {
            "findings": [
                {"id": "broad-allow-rule", "severity": "high"},
                {
                    "id": "future-finding",
                    "title": "FortiGate control weakness",
                    "impact": "This may affect access.",
                    "severity": "medium",
                },
            ]
        }

        observations = build_narratives(report)["executive_summary"].split("\n\n")[1]

        self.assertIn(
            "Finally, the following issue was identified: FortiGate control weakness. "
            "This may affect access.",
            observations,
        )
        self.assertEqual(observations.count("Finally,"), 1)

    def test_inventory_only_does_not_claim_a_security_review(self) -> None:
        summary = build_narratives(
            {
                "device": {"vendor": "WatchGuard"},
                "checks_run": False,
                "findings": [],
            }
        )["executive_summary"]

        self.assertIn("not assessed using automated security checks", summary)
        self.assertIn("separate configuration review is required", summary)
        self.assertNotIn("did not identify findings", summary)
        self.assertIn("Not assessed", render_html({"checks_run": False, "findings": []}))

    def test_unrecognised_finding_uses_its_own_impact(self) -> None:
        summary = build_narratives(
            {
                "findings": [
                    {
                        "id": "future-finding",
                        "title": "Additional control weakness",
                        "severity": "high",
                        "impact": "This may affect access.",
                    }
                ]
            }
        )["executive_summary"]

        self.assertIn(
            "The following issue was identified: Additional control weakness. "
            "This may affect access.",
            summary,
        )


class RemediationGuidanceTests(unittest.TestCase):
    def test_prioritises_bullets_and_deduplicates_relevant_references(self) -> None:
        report = {
            "findings": [
                {
                    "id": "policy-logging-gap",
                    "severity": "low",
                    "recommendation": "Enable policy logging.",
                },
                {
                    "id": "broad-allow-rule",
                    "severity": "high",
                    "recommendation": "Restrict the policy.",
                },
                {
                    "id": "broad-allow-rule",
                    "severity": "high",
                    "recommendation": "Restrict the policy.",
                },
                {
                    "id": "logging-coverage-gap",
                    "severity": "medium",
                    "recommendation": "Configure central logging.",
                },
            ]
        }

        guidance = build_narratives(report)["remediation_guidance"]

        self.assertEqual(guidance.count("- Restrict the policy."), 1)
        self.assertLess(guidance.index("- Restrict"), guidance.index("- Configure"))
        self.assertLess(guidance.index("- Configure"), guidance.index("- Enable"))
        self.assertEqual(guidance.count("https://csrc.nist.gov/pubs/sp/800/92/final"), 1)
        self.assertIn("https://csrc.nist.gov/pubs/sp/800/41/r1/final", guidance)
        self.assertNotIn("https://www.rfc-editor.org/info/rfc8915", guidance)
        html = render_html(report)
        self.assertIn('<a href="https://csrc.nist.gov/pubs/sp/800/92/final">', html)
        self.assertIn("<li>Restrict the policy.</li>", html)

    def test_no_checks_does_not_claim_there_were_no_findings(self) -> None:
        guidance = build_narratives({"checks_run": False, "findings": []})["remediation_guidance"]
        self.assertIn("configuration review is required", guidance)
        self.assertNotIn("absence of automated findings", guidance)
        self.assertNotIn("### References", guidance)


class TechnicalCommentaryTests(unittest.TestCase):
    def test_groups_rules_and_writes_evidence_led_commentary(self) -> None:
        report = {
            "device": {"hostname": "edge-fw", "vendor": "Fortinet"},
            "findings": [
                {
                    "id": "broad-allow-rule",
                    "severity": "high",
                    "affected_objects": [f"Policy {rule_id}"],
                    "evidence": {
                        "rule_id": str(rule_id),
                        "source_addresses": ["all"],
                        "destination_addresses": ["all"],
                        "services": ["ALL"],
                    },
                    "recommendation": "Restrict the affected policies.",
                }
                for rule_id in (1, 2)
            ],
        }

        narratives = build_narratives(report)
        commentary = narratives["technical_commentary"]

        self.assertIn("firewall policies, administrative access controls", commentary)
        self.assertEqual(commentary.count("### Policies with Unrestricted"), 1)
        self.assertIn("Two enabled policies permitted traffic", commentary)
        self.assertIn("`edge-fw`", commentary)
        self.assertNotIn("Affected policies:", commentary)
        self.assertIn("| 1 |", commentary)
        self.assertIn("| 2 |", commentary)
        self.assertIn("| ALL |", commentary)
        self.assertNotIn("Restrict the affected policies.", commentary)
        self.assertIn("Restrict the affected policies.", narratives["remediation_guidance"])
        self.assertIn(
            "The table below provides further details of the observed configuration.",
            commentary,
        )
        self.assertNotIn("Impact:", commentary)
        self.assertNotIn("**", commentary)

    def test_ntp_commentary_reflects_observed_state(self) -> None:
        for state, expected in (
            ("enable", "synchronisation was enabled"),
            ("disable", "synchronisation was disabled"),
            ("", "synchronisation state was not confirmed"),
        ):
            with self.subTest(state=state):
                report = {
                    "findings": [
                        {
                            "id": "ntp-server-review",
                            "evidence": {"ntp": {"ntpsync": state}},
                        }
                    ]
                }
                commentary = build_narratives(report)["technical_commentary"]
                self.assertIn(expected, commentary)
                self.assertIn("no explicit NTP server entries", commentary)

    def test_cisco_and_inventory_commentary_describe_their_actual_scope(self) -> None:
        cisco = build_narratives({"device": {"vendor": "Cisco"}, "findings": []})[
            "technical_commentary"
        ]
        inventory = build_narratives(
            {"device": {"vendor": "WatchGuard"}, "checks_run": False, "findings": []}
        )["technical_commentary"]
        self.assertIn("bound access-control entries", cisco)
        self.assertNotIn("administrative access controls", cisco)
        self.assertIn("not assessed using automated security checks", inventory)
        self.assertNotIn("firewall configuration review was performed", inventory)

    def test_single_cisco_rule_does_not_claim_clear_text_is_in_use(self) -> None:
        report = {
            "device": {"vendor": "Cisco"},
            "findings": [
                {
                    "id": "legacy-service-policy",
                    "affected_objects": ["Rule EDGE / line 1"],
                    "evidence": {"rules": [{"id": "EDGE / line 1", "services": ["ALL"]}]},
                }
            ],
        }
        commentary = build_narratives(report)["technical_commentary"]
        self.assertIn("One enabled rule referenced", commentary)
        self.assertIn("including `ALL`", commentary)
        self.assertIn("does not by itself establish which protocols", commentary)
        self.assertIn("| EDGE / line 1 |", commentary)
        self.assertNotIn("Affected rules:", commentary)

    def test_untrusted_identifiers_are_safe_in_prose_and_plain_table_cells(self) -> None:
        hostname = r"edge|`\<script>alert(1)</script>"
        rule = "ACL|`1"
        service = "WEB|`<&>"
        report = {
            "device": {"hostname": hostname, "vendor": "Cisco"},
            "findings": [
                {
                    "id": "legacy-service-policy",
                    "affected_objects": [f"Rule {rule}"],
                    "evidence": {"rules": [{"id": rule, "services": [service]}]},
                }
            ],
        }
        commentary = build_narratives(report)["technical_commentary"]
        html = render_html(report)

        self.assertIn(r"ACL\|\`1", commentary)
        self.assertIn(r"WEB\|\`\<&\>", commentary)
        self.assertNotIn("<script>alert(1)</script>", html)

        class CodeParser(HTMLParser):
            in_code = False
            in_cell = False
            values: list[str]
            cells: list[str]
            code_in_cell = False

            def __init__(self) -> None:
                super().__init__()
                self.values = []
                self.cells = []

            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                self.in_code = tag == "code"
                if tag == "td":
                    self.in_cell = True
                    self.cells.append("")
                elif tag == "code" and self.in_cell:
                    self.code_in_cell = True

            def handle_data(self, data: str) -> None:
                if self.in_code:
                    self.values.append(data)
                if self.in_cell:
                    self.cells[-1] += data

            def handle_endtag(self, tag: str) -> None:
                if tag == "code":
                    self.in_code = False
                elif tag == "td":
                    self.in_cell = False

        parser = CodeParser()
        parser.feed(html)
        self.assertIn(hostname, parser.values)
        self.assertIn(service, parser.values)
        self.assertIn(hostname, parser.cells)
        self.assertIn(rule, parser.cells)
        self.assertIn(service, parser.cells)
        self.assertFalse(parser.code_in_cell)

    def test_unknown_finding_preserves_its_description_and_impact(self) -> None:
        report = {
            "findings": [
                {
                    "id": "other",
                    "title": "Additional observation",
                    "description": "A configuration issue was identified.",
                    "impact": "It may affect access.",
                    "affected_objects": ["Policy custom-rule"],
                }
            ]
        }
        commentary = build_narratives(report)["technical_commentary"]
        self.assertIn("A configuration issue was identified.", commentary)
        self.assertIn("It may affect access.", commentary)
        self.assertIn("| Policy custom-rule |", commentary)


if __name__ == "__main__":
    unittest.main()
