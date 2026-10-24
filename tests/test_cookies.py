import pytest

from nullgate import abck_counters, is_enough


@pytest.mark.parametrize(
    ("value", "response_count", "expected"),
    [
        ("opaque~0~other~generation", 0, True),
        ("opaque~2~other~generation", 0, False),
        ("opaque~2~other~generation", 1, False),
        ("opaque~2~other~generation", 2, True),
        ("opaque~2~other~generation", 3, True),
        ("opaque~-1~other~generation", 100, False),
        ("opaque~-2~other~generation", 0, True),
        ("opaque~-0~other~generation", 0, True),
        ("opaque~+2suffix~other~generation", 2, True),
        ("opaque~2.9~other~generation", 2, True),
        ("opaque~2e3~other~generation", 2, True),
        ("opaque~0x10~other~generation", 0, True),
        ("opaque~\ufeff\u00a0\t+2~other~generation", 2, True),
        ("opaque~\x852~other~generation", 2, False),
        ("opaque~\x1c2~other~generation", 2, False),
        ("opaque~\u0660~other~generation", 0, False),
        ("opaque~+~other~generation", 100, False),
        ("opaque~NaN~other~generation", 100, False),
        ("opaque~Infinity~other~generation", 100, False),
        ("opaque~~other~generation", 100, False),
        ("opaque~0~other", 100, False),
        ("opaque~0~~", 0, True),
        ("opaque~0~other~unavailable-generation~extra", 0, True),
        ("opaque%7E%2B2suffix%7Eother%7Egeneration", 2, True),
        ("%E2%82%AC~0~other~generation", 0, True),
        ("opaque%257E0%257Eother%257Egeneration", 0, False),
        ("opaque~0~other~%", 0, False),
        ("opaque~0~other~%0", 0, False),
        ("opaque~0~other~%GG", 0, False),
        ("opaque~0~other~%FF", 0, False),
        ("opaque~0~other~%C0%AF", 0, False),
        ("opaque~0~other~%E2%82", 0, False),
        ("opaque~0~other~%ED%A0%80", 0, False),
        ("opaque~0~other~%F4%90%80%80", 0, False),
        ("opaque~9007199254740993~other~generation", 9007199254740992, True),
        (f"opaque~{'9' * 5000}~other~generation", 100, False),
        ("", 100, False),
        (None, 100, False),
    ],
)
def test_ordinary_send_gate(
    value: str | None, response_count: int, expected: bool
) -> None:
    assert is_enough(value, response_count=response_count) is expected


def test_default_count_stops_at_closed_limits() -> None:
    assert is_enough("opaque~0~other~generation")
    assert not is_enough("opaque~1~other~generation")
    assert not is_enough(None)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("opaque~-1~other~-1", (-1, -1)),
        ("opaque~2~other~4", (2, 4)),
        ("opaque%7E%2B2suffix%7Eother%7E%EF%BB%BF3tail", (2, 3)),
        ("opaque~invalid~other~3", (-1, 3)),
        ("opaque~2~other~invalid", (2, -1)),
        ("opaque~2~other~%FF", (-1, -1)),
    ],
)
def test_cookie_counters_preserve_independent_generation(
    value: str, expected: tuple[float, float]
) -> None:
    assert abck_counters(value) == expected
