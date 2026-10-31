"""Privacy-preserving summaries of fields explicitly filled by the caller."""

import re
from collections.abc import Mapping, Sequence
from hashlib import sha256
from struct import iter_unpack
from typing import NotRequired, TypedDict

_NON_SPECIAL = re.compile(
    r"[A-Za-z0-9_\t\n\v\f\r \u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000\ufeff]"
)
_WHITESPACE = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005"
    "\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)


class InputValue(TypedDict):
    length: int
    hash: str
    counts: NotRequired[tuple[int, int, int, int]]
    hash31: NotRequired[int]
    trimmed_hash31: NotRequired[int]
    trimmed_length: NotRequired[int]


class PreparedInput(TypedDict):
    attributes: dict[str, str]
    value: InputValue


def prepare_inputs(inputs: Sequence[Mapping[str, str]]) -> list[PreparedInput]:
    """Keep field order and attributes; replace raw values with UTF-16 summaries."""
    prepared: list[PreparedInput] = []
    for field in inputs:
        value = field.get("value", "")
        encoded_value = value.encode("utf-16-le", errors="surrogatepass")
        trimmed = value.strip(_WHITESPACE).encode("utf-16-le", errors="surrogatepass")
        special_value = _NON_SPECIAL.sub("", value).encode(
            "utf-16-le", errors="surrogatepass"
        )
        prepared.append(
            {
                "attributes": {
                    key: value for key, value in field.items() if key != "value"
                },
                "value": {
                    "length": len(encoded_value) // 2,
                    "hash": sha256(encoded_value).hexdigest(),
                    "counts": (
                        len(encoded_value) // 2,
                        len(special_value) // 2,
                        sum("a" <= char <= "z" for char in value.lower()),
                        sum("0" <= char <= "9" for char in value),
                    ),
                    "hash31": _hash31(encoded_value),
                    "trimmed_hash31": _hash31(trimmed),
                    "trimmed_length": len(trimmed) // 2,
                },
            }
        )
    return prepared


def _prepare_actions(
    observations: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    actions: list[dict[str, object]] = []
    for action in observations:
        if action.get("type") in ("input", "change") and isinstance(
            action.get("value"), str
        ):
            raise TypeError(
                "Raw action input values are not allowed; use a prepared InputValue"
            )
        actions.append(dict(action))
    return actions


def _hash31(encoded: bytes) -> int:
    result = 0
    for (unit,) in iter_unpack("<H", encoded):
        result = (31 * result + unit) & 0xFFFFFFFF
    return result - 2**32 if result >= 2**31 else result
