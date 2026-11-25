"""
Console output helpers.

Provides consistent output formatting across the application.
"""

from rich.console import Console

console = Console()


def success(message: str) -> None:
    """
    Display a success message.
    """

    console.print(f"[green][+][/green] {message}")


def info(message: str) -> None:
    """
    Display an informational message.
    """

    console.print(f"[cyan][*][/cyan] {message}")


def warn(message: str) -> None:
    """
    Display a warning message.
    """

    console.print(f"[yellow][!][/yellow] {message}")


def error(message: str) -> None:
    """
    Display an error message.
    """

    console.print(f"[red][-][/red] {message}")
