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
from rich.text import Text

from analysis.fortigate_checks import run_fortigate_checks
from common.console import console, success, warn
from common.tables import build_configuration_summary_table, build_findings_table
from common.validation import validate_configuration_file
from common.vendor_detection import VendorDetector
from parsers.factory import ParserFactory
from reporting.findings import build_report, export_json, export_yaml
from reporting.html import export_html
from reporting.sureformat import export_sureformat


def run_audit_workflow(args: Namespace) -> None:
    """Execute the audit workflow and write structured and Markdown reports."""
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
        config = parser.parse(str(config_path))
        progress.advance(task)

        progress.update(task, description="Analyzing security controls and writing reports")
        findings = run_fortigate_checks(config)
        report = build_report(config, findings, config_path.name)

        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        report_stem = f"{config_path.stem}-{timestamp}"
        if args.format in ("yaml", "both"):
            report_paths.append(export_yaml(report, output_dir / f"{report_stem}.yaml"))
        if args.format in ("json", "both"):
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
                    "not included in the XML. Add sureformat_id to their YAML definitions."
                )
            success(f"Exported {exported} mapped CSA Cyber finding(s).")
        progress.advance(task)

    console.print()
    console.print(build_configuration_summary_table(config))
    console.print()
    console.print(build_findings_table(findings))
    console.print()
    success(f"Assessment complete: {len(findings)} finding(s) identified.")
    for path in report_paths:
        console.print(Text(f"Report written: {path}", style="green"))
