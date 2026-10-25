"""Find Akamai resources in caller-supplied HTML."""

import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

import httpx

PIXEL_CHALLENGE_PATTERN = re.compile(
    r"""\bbazadebezolkohpepadr\s*=\s*(['"])([0-9]+)\1"""
)


def get_pixel_challenge(html: str) -> str | None:
    """Find a quoted numeric challenge assignment anywhere in the supplied HTML."""
    match = PIXEL_CHALLENGE_PATTERN.search(html)
    return match.group(2) if match else None


class _ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.base: str | None = None
        self.sources: list[str] = []
        self._inert: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"template", "noscript"}:
            self._inert.append(tag)
            return
        if self._inert:
            return
        attributes = dict(reversed(attrs))
        if tag == "base" and self.base is None and "href" in attributes:
            self.base = (attributes["href"] or "").strip()
        if tag != "script" or "nomodule" in attributes:
            return
        script_type = (attributes.get("type") or "").strip().lower()
        if script_type in {"", "text/javascript", "application/javascript"}:
            source = (attributes.get("src") or "").strip()
            if source:
                self.sources.append(source)

    def handle_endtag(self, tag: str) -> None:
        if self._inert and self._inert[-1] == tag:
            self._inert.pop()


def _script_urls(html: str, page_url: str) -> list[httpx.URL]:
    # Reject malformed authorities before HTTPX normalizes them.
    urlsplit(page_url)
    page = httpx.URL(page_url)
    if page.scheme not in {"http", "https"} or not page.host:
        raise ValueError("page_url must be an absolute HTTP(S) URL")
    parser = _ScriptParser()
    parser.feed(html)
    try:
        urlsplit(parser.base or "")
        base = page.join(parser.base or "")
    except (ValueError, httpx.InvalidURL):
        base = page
    if base.scheme not in {"http", "https"}:
        base = page
    urls: list[httpx.URL] = []
    for source in parser.sources:
        try:
            urlsplit(source)
            url = base.join(source).copy_with(fragment=None)
        except (ValueError, httpx.InvalidURL):
            continue
        if (url.scheme, url.host, url.port) == (page.scheme, page.host, page.port):
            if url not in urls:
                urls.append(url)
    return urls


def _find_script_url(html: str, page_url: str, *, pixel: bool) -> str | None:
    candidates = [
        str(url)
        for url in _script_urls(html, page_url)
        if bool(re.fullmatch(r"/akam/13/[0-9a-fA-F]+", url.path)) == pixel
        and (pixel or not url.path.lower().endswith((".js", ".mjs", ".cjs")))
    ]
    if len(candidates) > 1:
        kind = "pixel" if pixel else "sensor"
        raise ValueError(f"Multiple {kind} script candidates; select a URL explicitly")
    return candidates[0] if candidates else None


def get_pixel_script_url(html: str, page_url: str) -> str | None:
    """Find the page's same-origin /akam/13/<hex> classic script."""
    return _find_script_url(html, page_url, pixel=True)


def get_sensor_script_url(html: str, page_url: str) -> str | None:
    """Find a unique same-origin non-pixel script without a JS asset suffix."""
    return _find_script_url(html, page_url, pixel=False)
