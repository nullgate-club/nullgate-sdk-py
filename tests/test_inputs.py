from hashlib import sha256
from types import MappingProxyType

import pytest

from nullgate.akamai import prepare_inputs


def test_explicit_fields_preserve_order_and_hide_utf16_values() -> None:
    fields = [
        MappingProxyType({"name": "credential", "type": "password", "value": "s🔑&"}),
        MappingProxyType({"name": "surrogate", "value": "\ud800"}),
        MappingProxyType({"name": "missing"}),
    ]

    prepared = prepare_inputs(fields)

    assert [field["attributes"]["name"] for field in prepared] == [
        "credential",
        "surrogate",
        "missing",
    ]
    assert [field["value"]["length"] for field in prepared] == [4, 1, 0]
    assert [field["value"]["hash"] for field in prepared] == [
        sha256(bytes.fromhex("73003dd811dd2600")).hexdigest(),
        sha256(b"\x00\xd8").hexdigest(),
        sha256(b"").hexdigest(),
    ]
    assert all("value" not in field["attributes"] for field in prepared)
    assert "s🔑&" not in repr(prepared)
    assert fields[0]["value"] == "s🔑&"
    assert fields[1]["value"] == "\ud800"
    assert list(prepared[0]["attributes"]) == ["name", "type"]


@pytest.mark.parametrize(
    ("value", "counts"),
    [
        ("AZaz09_ !", (9, 1, 4, 2)),
        ("ÉİKß😀\ud800", (7, 7, 2, 0)),
        (
            "_ \t\n\u00a0\u1680\u2000\u200a\u2028\u2029\u202f\u205f\u3000\ufeff",
            (14, 0, 0, 0),
        ),
        ("\u0085\u001c\u001d\u001e\u001f", (5, 5, 0, 0)),
    ],
)
def test_counts_match_source_unicode_and_ascii_boundaries(
    value: str, counts: tuple[int, int, int, int]
) -> None:
    prepared = prepare_inputs([{"id": "entry", "value": value}])
    assert prepared[0]["value"]["counts"] == counts


@pytest.mark.parametrize(
    ("text", "hash31", "trimmed_hash31", "trimmed_length"),
    [
        ("", 0, 0, 0),
        ("A_9 😀İ\u00a0", -902761640, 386520648, 7),
        ("\u0085\ufeff", 69402, 133, 1),
        ("\ufeff\u00a0😀 \u0085\tX\u3000\ufeff", -2113306057, 927999095, 6),
        (" \0 ", 30784, 0, 1),
        ("\u180ex\u200b", 5929761, 5929761, 3),
        ("\ud800", 55296, 55296, 1),
    ],
)
def test_hash_facts_match_native_ecmascript_utf16_and_trim(
    text,
    hash31,
    trimmed_hash31,
    trimmed_length,
):
    value = prepare_inputs([{"value": text}])[0]["value"]
    assert (value["hash31"], value["trimmed_hash31"], value["trimmed_length"]) == (
        hash31,
        trimmed_hash31,
        trimmed_length,
    )
