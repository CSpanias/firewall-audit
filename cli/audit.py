"""Orchestrate firewall configuration parsing, checks, and report exports."""

from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.text import Text

from analysis.cisco_checks import run_cisco_checks
from analysis.fortigate_checks import run_fortigate_checks
from common.console import console, success, warn
from common.tables import build_configuration_summary_table, build_findings_table
from common.validation import validate_configuration_file
from common.vendor_detection import VendorDetector
from parsers.factory import ParserFactory
from reporting.findings import build_report, export_json
from reporting.html import export_html
from reporting.source_evidence import build_source_evidence
from reporting.sureformat import export_sureformat


def run_audit_workflow(args: Namespace) -> None:
    """Execute the audit workflow and write structured and HTML reports."""
    if args.evidence_full and args.evidence is None:
        raise ValueError("--evidence-full requires --evidence.")
    config_path = Path(args.config).expanduser()
    output_dir = Path(args.output_dir).expanduser()
    valid, message = validate_configuration_file(str(config_path))
    if not valid:
        raise ValueError(message)

    report_paths: list[Path] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        disable=not console.is_terminal,
    ) as progress:
        task = progress.add_task("Validating configuration", total=4)
        progress.advance(task)

        progress.update(task, description="Detecting firewall vendor")
        vendor = VendorDetector.detect(str(config_path))
        parser = ParserFactory.get_parser(vendor)
        progress.advance(task)

        progress.update(task, description=f"Parsing {vendor} configuration")
        evidence_source = (
            config_path.read_text(encoding="utf-8", errors="replace")
            if args.evidence is not None and vendor != "watchguard"
            else None
        )
        config = parser.parse(str(config_path))
        if evidence_source is not None and evidence_source != config_path.read_text(
            encoding="utf-8", errors="replace"
        ):
            raise ValueError("The configuration changed during parsing; rerun the assessment.")
        for message in config.parse_warnings:
            warn(message)
        progress.advance(task)

        progress.update(task, description="Analyzing security controls and writing reports")
        if vendor == "fortigate":
            findings = run_fortigate_checks(config, args.assessment_ip)
        elif vendor == "cisco":
            findings = run_cisco_checks(config, args.assessment_ip)
        elif vendor == "watchguard":
            findings = []
        else:
            raise ValueError(f"No analysis workflow is available for detected vendor: {vendor}.")
        selected_findings = findings
        if args.evidence not in (None, "all"):
            selected_findings = [finding for finding in findings if finding.id == args.evidence]
            if not selected_findings:
                raise ValueError(f"No finding with ID '{args.evidence}' was identified.")
        report = build_report(config, findings, config_path.name, args.assessment_ip)
        evidence = (
            build_source_evidence(
                evidence_source, config, selected_findings, sample=not args.evidence_full
            )
            if evidence_source is not None
            else []
        )

        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        report_stem = f"{config_path.stem}-{timestamp}"
        if not args.csacyber:
            report_paths.append(export_json(report, output_dir / f"{report_stem}.json"))
        report_paths.append(export_html(report, output_dir / f"{report_stem}.html"))
        if args.csacyber:
            xml_path, exported, unmapped = export_sureformat(
                report, output_dir / f"{report_stem}.xml"
            )
            report_paths.append(xml_path)
            if unmapped:
                warn(
                    f"{unmapped} finding(s) have no CSA Cyber SureFormat mapping and were "
                    "not included as separate XML items."
                )
            success(f"Exported {exported} CSA Cyber item(s), including the firewall review.")
        progress.advance(task)

    console.print()
    console.print(build_configuration_summary_table(config))
    console.print()
    console.print(build_findings_table(findings))
    console.print()
    if args.assessment_ip:
        context = report["assessment_context"]
        if not context["addresses_available"]:
            warn("Assessment IP matching is unavailable because rule addresses were not parsed.")
        else:
            console.print(
                f"Assessment host exclusions: {len(context['excluded_rules'])} dedicated rule(s)."
            )
    if config.checks_supported:
        success(f"Assessment complete: {len(findings)} finding(s) identified.")
    else:
        warn("Policy inventory complete; no automated security checks were run.")
    for path in report_paths:
        console.print(Text(f"Report written: {path}", style="green"))
    if args.evidence is not None:
        if not evidence:
            console.print(Text("No source evidence is available: no findings were identified."))
        for item in evidence:
            console.print()
            title = Text(f"{item.finding.title} [{item.finding.id}]", style="cyan")
            displayed = []
            truncated = False
            for number, line in item.lines:
                text = Text(f"{number:>6} | {line}")
                if not args.evidence_full and text.cell_len > min(console.width, 120):
                    text.truncate(min(console.width, 120), overflow="ellipsis")
                    truncated = True
                displayed.append(text)
            width = min(
                console.width,
                max(title.cell_len + 4, *(line.cell_len for line in displayed), 0),
            )
            console.print(Rule(title), width=width)
            console.print(Text("Selected source lines; other configuration lines are omitted."))
            for line in displayed:
                console.print(line)
            for note in item.notes:
                console.print(Text(f"Note: {note}"))
            if truncated:
                console.print(Text(
                    "Note: Long lines were truncated; use --evidence-full for complete lines."
                ))
