"""Pixel challenge lookup in caller-supplied HTML, without fetching or scripts."""

import re

PIXEL_CHALLENGE_PATTERN = re.compile(
    r"""\bbazadebezolkohpepadr\s*=\s*(['"])([0-9]+)\1"""
)


def get_pixel_challenge(html: str) -> str | None:
    """Find a quoted numeric challenge assignment anywhere in the supplied HTML."""
    match = PIXEL_CHALLENGE_PATTERN.search(html)
    return match.group(2) if match else None
