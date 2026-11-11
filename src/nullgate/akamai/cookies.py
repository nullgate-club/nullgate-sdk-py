"""Local cookie gate for stopping ordinary Akamai sensor sends."""

import re
from urllib.parse import unquote

_MALFORMED_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
_COUNTER_PREFIX = re.compile(
    r"[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*"
    r"([+-]?[0-9]+)"
)


def abck_counters(value: str | None) -> tuple[float, float]:
    """Return the response limit and generation; unavailable counters are -1."""
    if value is None or _MALFORMED_ESCAPE.search(value):
        return -1, -1
    try:
        parts = unquote(value, encoding="utf-8", errors="strict").split("~")
    except UnicodeError:
        return -1, -1
    if len(parts) < 4:
        return -1, -1
    limit = _COUNTER_PREFIX.match(parts[1])
    generation = _COUNTER_PREFIX.match(parts[3])
    # JavaScript parseInt returns a Number, including its large-integer rounding.
    return (
        float(limit[1]) if limit else -1,
        float(generation[1]) if generation else -1,
    )


def is_enough(value: str | None, *, response_count: int = 0) -> bool:
    """Check ordinary-send eligibility, not website acceptance.

    Count completed target sensor responses in the current cookie generation.
    An unavailable limit is -1 and keeps the ordinary-send gate open.
    """
    limit, _ = abck_counters(value)
    return limit != -1 and response_count >= limit
