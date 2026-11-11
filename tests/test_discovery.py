import pytest

from nullgate import Nullgate, NullgateError

URL = "https://shop.example/login"


@pytest.mark.parametrize(
    "html,expected",
    [
        (
            '<script src="/assets/app.js"></script><script src="/guard"></script>',
            ("https://shop.example/guard", None, None),
        ),
        (
            '<base href="/assets/"><script src="../guard?x=1&amp;y=2#frag"></script>',
            ("https://shop.example/guard?x=1&y=2", None, None),
        ),
        (
            '<script src="https://elsewhere.example/guard"></script>'
            '<script type="module" src="/guard"></script>',
            (None, None, None),
        ),
        (
            '<template><script src="/ignored"></script></template>'
            '<noscript><script src="/ignored2"></script></noscript>',
            (None, None, None),
        ),
        (
            '<script nomodule src="/guard"></script>'
            '<script type="application/json" src="/data"></script>',
            (None, None, None),
        ),
        (
            '<script>bazadebezolkohpepadr="123"</script>'
            '<script src="/akam/13/abc"></script>',
            (None, "https://shop.example/akam/13/abc", None),
        ),
        (
            '<script src="/guard?v=00000000-0000-0000-0000-000000000001"></script>',
            (
                None,
                None,
                "https://shop.example/guard?v=00000000-0000-0000-0000-000000000001",
            ),
        ),
        (
            '<script src="/guard?v=00000000-0000-0000-'
            '0000-000000000001&v=other"></script>',
            (None, None, None),
        ),
        (
            '<script src="/guard"></script><script src="/guard"></script>',
            ("https://shop.example/guard", None, None),
        ),
    ],
)
def test_realistic_discovery_preserves_v1_script_rules(html, expected):
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, html)
        assert (page.sensor_url, page.pixel_url, page.sbsd_url) == expected


def test_ambiguity_lists_candidates_and_explicit_selection_works(api):
    calls, _ = api
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(
            URL, '<script src="/first"></script><script src="/second"></script>'
        )
        with pytest.raises(NullgateError) as error:
            _ = page.sensor_url
        assert error.value.code == "ambiguous_protection"
        assert "https://shop.example/first" in error.value.message
        assert "https://shop.example/second" in error.value.message
        page.sensor(script="source", cookies={}, script_url="/second")
    assert b'"script_url":"https://shop.example/second"' in calls[0].content


def test_pixel_ambiguous_challenges_require_unambiguous_observations():
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(
            URL,
            '<script>bazadebezolkohpepadr="1";'
            'bazadebezolkohpepadr="2"</script>'
            '<script src="/akam/13/abc"></script>',
        )
        with pytest.raises(NullgateError) as error:
            page.pixel(script="source", script_url="/akam/13/abc")
    assert error.value.code == "ambiguous_protection"
    assert "challenge 1" in error.value.message and "challenge 2" in error.value.message
