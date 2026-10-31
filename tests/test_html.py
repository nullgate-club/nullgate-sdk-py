import asyncio
from typing import cast

import pytest
from magic_filter import MagicFilter

from nullgate import (
    AmbiguousProtectionError,
    F,
    NullgateClient,
    NullgateClientAsync,
    Page,
)
from nullgate.akamai import Pixel, Sbsd, Sensor
from nullgate.html import find_protections

VERSION = "11111111-2222-4333-8444-555555555555"


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_local_discovery_retains_page_occurrences_and_provenance(
    asynchronous: bool,
) -> None:
    page = Page(
        "https://target.example/login/index",
        '<base href="/resources/">\n'
        '<script>var bazadebezolkohpepadr = "001234";</script>\n'
        '<script src="/akam/13/aB09?x=a%2Fb+z&amp;x=two#ignored"></script>\n'
        f'<script src="/.well-known/sbsd/neutral?v={VERSION}"></script>\n'
        f'<script src="opaque/block?v={VERSION}&amp;t="></script>\n'
        '<script src="opaque/sensor?first=%2f&amp;second=+value"></script>\n'
        '<script src="opaque/sensor?first=%2f&amp;second=+value"></script>',
    )
    client = (
        NullgateClientAsync("not-used") if asynchronous else NullgateClient("not-used")
    )
    # Both clients discover synchronously; no network client needs to be opened.
    with pytest.raises(AmbiguousProtectionError, match="panic=False"):
        client.find_protections(page)
    found = client.find_protections(page, panic=False)
    if isinstance(client, NullgateClientAsync):
        asyncio.run(client.aclose())
    else:
        client.close()
    assert [type(item) for item in found] == [Pixel, Sbsd, Sbsd, Sensor, Sensor]
    assert all(item.page is page for item in found)
    pixel, normal, blocking, first_sensor, second_sensor = found
    assert isinstance(pixel, Pixel)
    assert pixel.challenge == "001234"
    assert pixel.script_url == "https://target.example/akam/13/aB09?x=a%2Fb+z&x=two"
    assert pixel.provenance is not None
    assert pixel.provenance.raw_source == "/akam/13/aB09?x=a%2Fb+z&x=two#ignored"
    assert (pixel.provenance.tag_index, pixel.provenance.line) == (1, 3)
    assert pixel.challenge_offset is not None
    assert page.html[pixel.challenge_offset :].startswith("bazadebezolkohpepadr")
    assert isinstance(normal, Sbsd) and not normal.blocking
    assert isinstance(blocking, Sbsd) and blocking.blocking
    assert blocking.script_url.endswith(f"?v={VERSION}&t=")
    assert first_sensor.script_url == (
        "https://target.example/resources/opaque/sensor?first=%2f&second=+value"
    )
    assert first_sensor.provenance != second_sensor.provenance


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        ("", "https://target.example/login/collector"),
        ('<base href="/assets/">', "https://target.example/assets/collector"),
        ('<base href="http://[">', "https://target.example/login/collector"),
        ('<base href="javascript:ignored">', "https://target.example/login/collector"),
        ('<base href="https://other.example/">', None),
    ],
)
def test_discovery_resolves_only_same_origin_active_classic_scripts(
    base: str, expected: str | None
) -> None:
    page = Page(
        "https://target.example/login/page",
        base + '<!-- <script src="/comment"></script> -->'
        '<template><script src="/template"></script></template>'
        '<noscript><script src="/noscript"></script></noscript>'
        '<script type="module" src="/module"></script>'
        '<script nomodule src="/legacy"></script>'
        '<script type="application/json" src="/data"></script>'
        '<script src="https://other.example/cross"></script>'
        '<script src="http://target.example/insecure"></script>'
        '<script src="https://target.example:8443/port"></script>'
        '<script src="http://["></script>'
        '<script src="javascript:ignored"></script>'
        '<script src=""></script>'
        '<SCRIPT TYPE="text/javascript" SRC="collector" '
        'src="https://other.example/duplicate"></SCRIPT>',
    )
    with NullgateClient("not-used") as client:
        found = client.find_protections(page)
    assert [item.script_url for item in found] == (
        [] if expected is None else [expected]
    )


def test_discovery_exposes_ambiguity_instead_of_picking_a_script_or_challenge() -> None:
    page = Page(
        "https://target.example/",
        '<script>bazadebezolkohpepadr="12"; bazadebezolkohpepadr="34";</script>'
        '<script src="/akam/13/abc"></script>'
        '<script src="/akam/13/def"></script>'
        '<script src="/first"></script><script src="/second"></script>',
    )
    with NullgateClient("not-used") as client:
        found = client.find_protections(page, panic=False)
    assert [
        (item.script_url, item.challenge) for item in found if isinstance(item, Pixel)
    ] == [
        ("https://target.example/akam/13/abc", "12"),
        ("https://target.example/akam/13/abc", "34"),
        ("https://target.example/akam/13/def", "12"),
        ("https://target.example/akam/13/def", "34"),
    ]
    assert [item.script_url for item in found if isinstance(item, Sensor)] == [
        "https://target.example/first",
        "https://target.example/second",
    ]


@pytest.mark.parametrize(
    "source",
    ["/app.js", "/app.JS?x=2", "/app.mjs", "/app.cjs", "/app%2Ejs"],
)
def test_js_assets_are_not_relabelled_as_sensors(source: str) -> None:
    with NullgateClient("not-used") as client:
        assert (
            client.find_protections(
                Page("https://target.example/", f'<script src="{source}"></script>')
            )
            == []
        )


def test_pixel_requires_live_challenge_and_sbsd_rejects_ambiguous_service_queries() -> (
    None
):
    page = Page(
        "https://target.example/",
        '<!-- bazadebezolkohpepadr="123" -->'
        '<template><script>bazadebezolkohpepadr="456";</script></template>'
        '<script type="application/json">bazadebezolkohpepadr="789";</script>'
        '<script src="/akam/13/abc"></script>'
        f'<script src="/duplicate?v={VERSION}&amp;v={VERSION}"></script>'
        f'<script src="/tokens?v={VERSION}&amp;t=one&amp;t=two"></script>',
    )
    with NullgateClient("not-used") as client:
        assert client.find_protections(page) == []


@pytest.mark.parametrize("token", ["", "=", "=opaque%2Ftoken+part"])
def test_sbsd_blocking_is_query_presence_not_truthiness(token: str) -> None:
    sbsd = Sbsd(
        Page("https://target.example/", ""),
        f"https://target.example/s?v={VERSION}&t{token}",
    )
    assert sbsd.blocking
    assert not Sbsd(sbsd.page, f"https://target.example/s?v={VERSION}&other=t").blocking


def test_magic_filter_only_resolves_each_concrete_protection() -> None:
    page = Page(
        "https://target.example/",
        f'<script src="/one?v={VERSION}"></script>'
        f'<script src="/two?v={VERSION}&amp;t="></script>'
        '<script src="/sensor"></script>'
        '<script src="/turnstile/v0/api.js"></script>',
    )
    with NullgateClient("not-used") as client:
        assert [
            item.script_url
            for item in client.find_protections(
                page, where=(F.provider == "akamai") & (F.kind == "sbsd") & F.blocking
            )
        ] == [f"https://target.example/two?v={VERSION}&t="]
        assert client.find_protections(page, where=F.missing_attribute) == []
        assert client.find_protections(page, where=F.provider == "turnstile") == []
        with pytest.raises(TypeError):
            client.find_protections(page, where=cast(MagicFilter, lambda item: True))
        with pytest.raises(AmbiguousProtectionError):
            client.find_protections(page, where=F.kind == "sbsd")


def test_local_discovery_keeps_empty_and_single_results_as_lists() -> None:
    assert find_protections(Page("https://target.example/", "")) == []
    page = Page("https://target.example/", '<script src="/sensor"></script>')
    found = find_protections(page)
    assert [item.script_url for item in found] == ["https://target.example/sensor"]
    assert found[0].page is page


def test_local_discovery_checks_filtered_candidates_without_deduplicating() -> None:
    page = Page(
        "https://target.example/",
        '<script src="/sensor"></script><script src="/sensor"></script>'
        f'<script src="/sbsd?v={VERSION}"></script>',
    )
    with pytest.raises(AmbiguousProtectionError, match="3 protection candidates"):
        find_protections(page)
    with pytest.raises(AmbiguousProtectionError):
        find_protections(page, where=F.kind == "sensor")
    assert [
        item.script_url for item in find_protections(page, where=F.kind == "sbsd")
    ] == [f"https://target.example/sbsd?v={VERSION}"]
    assert find_protections(page, where=F.kind == "pixel") == []
    found = find_protections(page, where=F.kind == "sensor", panic=False)
    assert [item.script_url for item in found] == [
        "https://target.example/sensor",
        "https://target.example/sensor",
    ]
    assert found[0] is not found[1]
    assert found[0].provenance != found[1].provenance


@pytest.mark.parametrize(
    "url", ["/relative", "file:///tmp/page", "javascript:x", "https://["]
)
def test_page_requires_an_absolute_http_url(url: str) -> None:
    with pytest.raises(ValueError):
        Page(url, "")


def test_tmx_cross_origin_queries_preserve_cross_provider_ambiguity() -> None:
    from nullgate import ThreatMetrix

    page = Page(
        "https://target.example/login",
        '<script src="/sensor"></script>'
        '<script src="https://arbitrary.example/fp/tags.js?org_id=org'
        '&amp;session_id=actual%2Fsession"></script>'
        '<script src="/fp/tags.js?org_id=org&amp;org_id=again'
        '&amp;session_id=session"></script>'
        '<script src="/fp/tags.js?org_id=org&amp;session_id="></script>'
        '<script src="/fp/tags.js?org_id=org&amp;session_id=session'
        '&amp;session_id=again"></script>',
    )
    with pytest.raises(AmbiguousProtectionError):
        find_protections(page)
    found = find_protections(page, panic=False)
    assert [type(item) for item in found] == [Sensor, ThreatMetrix]
    [protection] = find_protections(page, where=F.provider == "threatmetrix")
    assert isinstance(protection, ThreatMetrix)
    assert protection.page is page
    assert protection.script_url == (
        "https://arbitrary.example/fp/tags.js?org_id=org&session_id=actual%2Fsession"
    )
    assert protection.provenance is not None
    assert protection.provenance.tag_index == 1


def test_module_tags_are_active_without_expanding_akamai_classic_discovery() -> None:
    from nullgate import ThreatMetrix

    page = Page(
        "https://target.example/document",
        '<script type="module" src="/not-an-akamai-sensor"></script>'
        '<script type="module" src="https://tags.example/fp/tags.js'
        '?org_id=org&amp;session_id=session"></script>'
        '<script type="application/json" src="/fp/tags.js'
        '?org_id=org&amp;session_id=inert"></script>',
    )
    [protection] = find_protections(page)
    assert isinstance(protection, ThreatMetrix)
    assert protection.script_url.endswith("session_id=session")
