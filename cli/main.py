"""Command-line entry point for Firewall-Audit."""

import argparse
from textwrap import dedent

from rich.text import Text

from cli.audit import run_audit_workflow
from common.console import console


class HelpFormatter(
    argparse.ArgumentDefaultsHelpFormatter,
    argparse.RawDescriptionHelpFormatter,
):
    """Keep usage examples verbatim while showing argument defaults."""


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="firewall-audit",
        description="Review a firewall configuration and export structured findings.",
        formatter_class=HelpFormatter,
        epilog=dedent(
            """\
            Examples:
              firewall-audit audit --config firewall.conf
              firewall-audit audit -C firewall.conf -O reports --format both
            """
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit_parser = subparsers.add_parser(
        "audit",
        help="Review a firewall configuration",
        description="Parse a supported firewall configuration and generate a review report.",
        formatter_class=HelpFormatter,
    )
    audit_parser.add_argument(
        "-C",
        "--config",
        required=True,
        metavar="FILE",
        help="Path to the exported firewall configuration.",
    )
    audit_parser.add_argument(
        "-O",
        "--output-dir",
        default="firewall-audit-output",
        metavar="DIR",
        help="Directory for generated reports.",
    )
    audit_parser.add_argument(
        "--format",
        choices=("yaml", "json", "both"),
        default="yaml",
        help="Structured report format. An HTML report is always generated.",
    )
    audit_parser.add_argument(
        "--csacyber",
        action="store_true",
        help="Also export mapped findings in CSA Cyber SureFormat XML.",
    )
    audit_parser.set_defaults(func=run_audit_workflow)
    return parser


def main(argv: list[str] | None = None) -> None:
    """Parse arguments and run the selected command."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (OSError, ValueError) as exc:
        console.print(Text(f"Error: {exc}", style="bold red"))
        parser.exit(2)


if __name__ == "__main__":
    main()
