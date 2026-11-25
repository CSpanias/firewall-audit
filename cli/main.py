"""Command-line entry point for Firewall-Audit."""

import argparse
import ipaddress
from textwrap import dedent

from rich.text import Text

from cli.audit import run_audit_workflow
from common.console import console


def _assessment_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid assessment IP address: {value}") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        raise argparse.ArgumentTypeError("Assessment IPv6 addresses cannot include a scope ID.")
    return str(address)


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
              firewall-audit --config firewall.conf
              firewall-audit -C firewall.conf -O reports
            """
        ),
    )
    parser.add_argument(
        "-C",
        "--config",
        required=True,
        metavar="FILE",
        help="Path to the exported firewall configuration.",
    )
    parser.add_argument(
        "-O",
        "--output-dir",
        default="firewall-audit",
        metavar="DIR",
        help="Directory for generated reports.",
    )
    parser.add_argument(
        "--assessment-ip",
        action="append",
        type=_assessment_ip,
        default=[],
        metavar="IP",
        help="Exclude rules dedicated to an assessment host; may be specified more than once.",
    )
    parser.add_argument(
        "--csacyber",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """Parse arguments and run the selected command."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        run_audit_workflow(args)
    except (OSError, ValueError) as exc:
        console.print(Text(f"Error: {exc}", style="bold red"))
        parser.exit(2)


if __name__ == "__main__":
    main()
