"""Privacy-preserving summaries of fields explicitly filled by the caller."""

import re
from collections.abc import Mapping, Sequence
from hashlib import sha256
from typing import NotRequired, TypedDict

_NON_SPECIAL = re.compile(
    r"[A-Za-z0-9_\t\n\v\f\r \u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000\ufeff]"
)


class InputValue(TypedDict):
    length: int
    hash: str
    counts: NotRequired[tuple[int, int, int, int]]


class PreparedInput(TypedDict):
    attributes: dict[str, str]
    value: InputValue


def prepare_inputs(inputs: Sequence[Mapping[str, str]]) -> list[PreparedInput]:
    """Keep field order and attributes; replace raw values with UTF-16 summaries."""
    prepared: list[PreparedInput] = []
    for field in inputs:
        value = field.get("value", "")
        encoded_value = value.encode("utf-16-le", errors="surrogatepass")
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
                },
            }
        )
    return prepared
