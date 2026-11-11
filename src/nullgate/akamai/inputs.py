"""Privacy-preserving summaries of fields explicitly filled by the caller."""

import re
from collections.abc import Mapping, Sequence
from hashlib import sha256
from struct import iter_unpack
from typing import NotRequired, TypedDict, cast

from ..errors import NullgateError

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
    selector: NotRequired[str]


def prepare_inputs(inputs: Sequence[Mapping[str, str]]) -> list[PreparedInput]:
    """Keep field order and attributes; replace raw values with UTF-16 summaries."""
    prepared: list[PreparedInput] = []
    for field in inputs:
        if not isinstance(field, Mapping) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in field.items()
        ):
            raise NullgateError(
                "Input fields must contain string attributes and values",
                code="invalid_inputs",
            )
        value = field.get("value", "")
        encoded_value = value.encode("utf-16-le", errors="surrogatepass")
        trimmed = value.strip(_WHITESPACE).encode("utf-16-le", errors="surrogatepass")
        special_value = _NON_SPECIAL.sub("", value).encode(
            "utf-16-le", errors="surrogatepass"
        )
        prepared.append(
            {
                "attributes": {
                    key: value
                    for key, value in field.items()
                    if key not in ("value", "selector")
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
        if "selector" in field:
            prepared[-1]["selector"] = field["selector"]
    return prepared


def _validate_summary(value: object) -> None:
    if (
        not isinstance(value, Mapping)
        or not {"length", "hash"} <= value.keys()
        or not value.keys()
        <= {"length", "hash", "counts", "hash31", "trimmed_hash31", "trimmed_length"}
        or type(value["length"]) is not int
        or value["length"] < 0
        or not isinstance(value["hash"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["hash"]) is None
    ):
        raise ValueError("Input value must be a redacted summary")
    length = value["length"]
    for key in ("hash31", "trimmed_hash31"):
        if key in value and (
            type(value[key]) is not int or not -(2**31) <= value[key] < 2**31
        ):
            raise ValueError("Input hashes must be signed 32-bit integers")
    if "trimmed_length" in value:
        trimmed = value["trimmed_length"]
        if type(trimmed) is not int or not 0 <= trimmed <= length:
            raise ValueError("Trimmed input length must be within input length")
        if trimmed == 0 and value.get("trimmed_hash31", 0) != 0:
            raise ValueError("An empty trimmed value must have hash zero")
    if "counts" in value:
        counts = value["counts"]
        if (
            not isinstance(counts, (tuple, list))
            or len(counts) != 4
            or any(type(count) is not int or count < 0 for count in counts)
            or counts[0] != length
            or counts[1] + counts[3] > length
            or counts[2] + counts[3] > length
        ):
            raise ValueError(
                "Input counts must be four consistent nonnegative integers"
            )


def _prepared_input(value: Mapping[str, object]) -> PreparedInput:
    if not {"attributes", "value"} <= value.keys() or not value.keys() <= {
        "attributes",
        "value",
        "selector",
    }:
        raise ValueError("Prepared input requires attributes and a value summary")
    attributes = value["attributes"]
    if (
        not isinstance(attributes, Mapping)
        or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in attributes.items()
        )
        or {"value", "selector"} & attributes.keys()
    ):
        raise ValueError("Prepared attributes must contain strings without raw values")
    _validate_summary(value["value"])
    summary = dict(cast(Mapping[str, object], value["value"]))
    if "counts" in summary:
        summary["counts"] = tuple(cast(Sequence[int], summary["counts"]))
    prepared: PreparedInput = {
        "attributes": dict(attributes),
        "value": cast(InputValue, summary),
    }
    if "selector" in value:
        selector = value["selector"]
        if not isinstance(selector, str) or not selector:
            raise ValueError("Prepared selector must be a nonempty string")
        prepared["selector"] = selector
    return prepared


def _prepare_actions(
    observations: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    actions: list[dict[str, object]] = []
    for action in observations:
        if isinstance(action.get("value"), str):
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
