from hashlib import sha256
from types import MappingProxyType

import pytest

from nullgate import prepare_inputs


def test_explicit_fields_preserve_order_and_hide_utf16_values() -> None:
    fields = [
        MappingProxyType({"name": "credential", "type": "password", "value": "s🔑&"}),
        MappingProxyType({"name": "surrogate", "value": "\ud800"}),
        MappingProxyType({"name": "missing"}),
    ]

    prepared = prepare_inputs(fields)

    assert prepared == [
        {
            "attributes": {"name": "credential", "type": "password"},
            "value": {
                "length": 4,
                "hash": sha256(bytes.fromhex("73003dd811dd2600")).hexdigest(),
                "counts": (4, 3, 1, 0),
            },
        },
        {
            "attributes": {"name": "surrogate"},
            "value": {
                "length": 1,
                "hash": sha256(b"\x00\xd8").hexdigest(),
                "counts": (1, 1, 0, 0),
            },
        },
        {
            "attributes": {"name": "missing"},
            "value": {
                "length": 0,
                "hash": sha256(b"").hexdigest(),
                "counts": (0, 0, 0, 0),
            },
        },
    ]
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
