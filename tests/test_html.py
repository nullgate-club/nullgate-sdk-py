import pytest

from nullgate import (
    get_pixel_challenge,
    get_pixel_script_url,
    get_sensor_script_url,
)


def test_pixel_challenge_embedded_among_statements() -> None:
    html = """
        <html><script>
        window.ready = true; var bazadebezolkohpepadr = '001234'; finish();
        </script></html>
    """
    assert get_pixel_challenge(html) == "001234"


def test_missing_pixel_challenge() -> None:
    assert get_pixel_challenge('<script>var other = "1234";</script>') is None


@pytest.mark.parametrize(
    ("base", "sensor"),
    [
        ("", "https://shop.example/login/assets/collector?x=1&y=2"),
        (
            '<base href="/resources/">',
            "https://shop.example/resources/assets/collector?x=1&y=2",
        ),
        (
            '<base href="http://[">',
            "https://shop.example/login/assets/collector?x=1&y=2",
        ),
    ],
)
def test_script_urls_resolve_base_entities_and_duplicates(
    base: str, sensor: str
) -> None:
    html = (
        base
        + """
        <!-- <script src="/ignored"></script> -->
        <template><script src="/template"></script></template>
        <noscript><script src="/noscript"></script></noscript>
        <script type="module" src="/app.js"></script>
        <script nomodule src="/legacy.js"></script>
        <script type="application/json" src="/data"></script>
        <script src="https://cdn.example/analytics.js"></script>
        <script src="http://shop.example/insecure"></script>
        <script src="https://shop.example:8443/other"></script>
        <script src="javascript:alert(1)"></script>
        <script src="http://["></script>
        <script src=""></script>
        <SCRIPT TYPE="text/javascript"
            SRC="assets/collector?x=1&amp;y=2#fragment" async></SCRIPT>
        <script src="assets/collector?x=1&amp;y=2"></script>
        <script src="//SHOP.EXAMPLE:443/akam/13/7aB0?version=2"></script>
    """
    )
    page = "https://shop.example/login/index"
    assert get_sensor_script_url(html, page) == sensor
    assert get_pixel_script_url(html, page) == (
        "https://shop.example/akam/13/7aB0?version=2"
    )


def test_sensor_discovery_ignores_frontend_assets() -> None:
    sensor = "/opaque/session/collector"
    html = f"""
        <script src="/static/checkout/bundle.js"></script>
        <script src="/static/catalog/bundle.js"></script>
        <script src="{sensor}?version=2"></script>
        <script src="/static/account/bundle.js"></script>
        <script src="/static/navigation/bundle.js"></script>
        <script src="/static/forms/bundle.js"></script>
        <script src="/static/shared/bundle.js"></script>
        <script src="/akam/13/abc"></script>
    """
    assert get_sensor_script_url(html, "https://shop.example/page") == (
        f"https://shop.example{sensor}?version=2"
    )
    assert get_pixel_script_url(html, "https://shop.example/page") == (
        "https://shop.example/akam/13/abc"
    )


@pytest.mark.parametrize(
    "source",
    [
        "/assets/app.js",
        "/assets/app.JS?version=2",
        "/assets/app.mjs",
        "/assets/app.cjs",
        "/assets/app%2Ejs",
    ],
)
def test_javascript_assets_are_not_sensor_candidates(source: str) -> None:
    assert (
        get_sensor_script_url(
            f'<script src="{source}"></script>', "https://shop.example/page"
        )
        is None
    )


def test_sensor_discovery_checks_path_suffix_not_directory_or_query() -> None:
    html = """
        <script src="/assets/app.js?next=/collector"></script>
        <script src="/version.js/collector?file=app.js"></script>
    """
    assert get_sensor_script_url(html, "https://shop.example/page") == (
        "https://shop.example/version.js/collector?file=app.js"
    )


@pytest.mark.parametrize(
    ("find", "html"),
    [
        (
            get_sensor_script_url,
            '<script src="/app.js"></script>'
            '<script src="/one"></script><script src="/two"></script>',
        ),
        (
            get_pixel_script_url,
            '<script src="/akam/13/abc"></script><script src="/akam/13/def"></script>',
        ),
    ],
)
def test_ambiguous_script_urls_are_not_guessed(find, html: str) -> None:
    with pytest.raises(ValueError, match="Multiple .* script candidates"):
        find(html, "https://shop.example/login")


def test_missing_script_urls_and_cross_origin_base() -> None:
    html = '<base href="https://cdn.example/"><script src="collector"></script>'
    assert get_sensor_script_url(html, "https://shop.example/login") is None
    assert get_pixel_script_url(html, "https://shop.example/login") is None
    assert get_sensor_script_url("<p>No scripts</p>", "https://shop.example") is None


def test_script_discovery_uses_the_first_duplicate_attribute() -> None:
    html = '<script src="/collector" src="https://cdn.example/ignored"></script>'
    assert get_sensor_script_url(html, "https://shop.example") == (
        "https://shop.example/collector"
    )


@pytest.mark.parametrize(
    "page_url", ["/login", "file:///tmp/page.html", "javascript:x"]
)
def test_script_discovery_requires_an_http_page(page_url: str) -> None:
    with pytest.raises(ValueError, match="absolute HTTP"):
        get_sensor_script_url('<script src="/collector"></script>', page_url)
