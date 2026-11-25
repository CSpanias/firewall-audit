"""Formatting helpers for report prose."""

_NUMBERS = ("zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine")


def number_as_words(value: int) -> str:
    """Spell out single-digit counts in prose."""
    return _NUMBERS[value] if 0 <= value < len(_NUMBERS) else str(value)
