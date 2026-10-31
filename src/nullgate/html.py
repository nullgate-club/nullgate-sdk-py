"""Discover supported protection candidates without fetching or executing sources."""

import re
from html.parser import HTMLParser
from typing import TypeAlias
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from magic_filter import MagicFilter

from .akamai import Pixel, Sbsd, Sensor
from .akamai import Protection as AkamaiProtection
from .models import Page, ScriptReference
from .threatmetrix import ThreatMetrix

_PIXEL_CHALLENGE = re.compile(r"""\bbazadebezolkohpepadr\s*=\s*(['"])([0-9]+)\1""")
_PIXEL_PATH = re.compile(r"/akam/13/[0-9a-fA-F]+")

Protection: TypeAlias = AkamaiProtection | ThreatMetrix


class AmbiguousProtectionError(ValueError):
    """More than one protection candidate remains after local filtering."""


class _Scripts(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.base: str | None = None
        self.sources: list[tuple[ScriptReference, bool]] = []
        self.challenges: dict[str, int] = {}
        self._inert: list[str] = []
        self._inline = False
        self._script_index = 0
        self._line_offsets = [0, *(match.end() for match in re.finditer("\n", html))]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        index = self._script_index
        if tag == "script":
            self._script_index += 1
        if tag in {"template", "noscript"}:
            self._inert.append(tag)
        if self._inert:
            return
        attributes = dict(reversed(attrs))
        if tag == "base" and self.base is None and "href" in attributes:
            self.base = (attributes["href"] or "").strip()
        if tag != "script":
            return
        script_type = (attributes.get("type") or "").strip().lower()
        self._inline = "nomodule" not in attributes and script_type in {
            "",
            "text/javascript",
            "application/javascript",
        }
        if not self._inline and not (
            script_type == "module" and "nomodule" not in attributes
        ):
            return
        source = (attributes.get("src") or "").strip()
        if source:
            line, column = self.getpos()
            self.sources.append(
                (ScriptReference(source, index, line, column), self._inline)
            )
        if "src" in attributes:
            self._inline = False

    def handle_data(self, data: str) -> None:
        if self._inert or not self._inline:
            return
        line, column = self.getpos()
        offset = self._line_offsets[line - 1] + column
        for match in _PIXEL_CHALLENGE.finditer(data):
            self.challenges.setdefault(match[2], offset + match.start())

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._inline = False
        if self._inert and self._inert[-1] == tag:
            self._inert.pop()


def _is_uuid(value: str) -> bool:
    try:
        return len(value) == 36 and str(UUID(value)) == value.lower()
    except ValueError:
        return False


def find_protections(
    page: Page, where: MagicFilter | None = None, *, panic: bool = True
) -> list[Protection]:
    """Discover candidates, raising on ambiguity unless panic=False.

    Sensor discovery uses the existing same-origin extensionless classic-script
    heuristic. It does not prove a script's contents; the service validates the
    caller-supplied source. TMX uses the actual tags.js query, across origins.
    """
    if where is not None and not isinstance(where, MagicFilter):
        raise TypeError("where must be a MagicFilter expression")
    document = httpx.URL(page.url)
    parser = _Scripts(page.html)
    parser.feed(page.html)
    try:
        urlsplit(parser.base or "")
        base = document.join(parser.base or "")
    except (ValueError, httpx.InvalidURL):
        base = document
    if base.scheme not in {"http", "https"}:
        base = document
    found: list[Protection] = []
    for reference, classic in parser.sources:
        try:
            urlsplit(reference.raw_source)
            source = base.join(reference.raw_source).copy_with(fragment=None)
        except (ValueError, httpx.InvalidURL):
            continue
        script_url = str(source)
        if source.scheme not in {"http", "https"} or not source.host:
            continue
        if source.path.endswith("/tags.js"):
            try:
                found.append(ThreatMetrix(page, script_url, provenance=reference))
            except ValueError:
                pass
            continue
        if not classic:
            continue
        if (source.scheme, source.host, source.port) != (
            document.scheme,
            document.host,
            document.port,
        ):
            continue
        if _PIXEL_PATH.fullmatch(source.path):
            for challenge, offset in parser.challenges.items():
                found.append(
                    Pixel(
                        page,
                        script_url,
                        challenge,
                        provenance=reference,
                        challenge_offset=offset,
                    )
                )
            continue
        query: dict[str, list[str]] = {}
        for part in source.query.decode().split("&"):
            name, _, value = part.partition("=")
            query.setdefault(name, []).append(value)
        versions = query.get("v", [])
        if any(_is_uuid(version) for version in versions):
            if len(versions) == 1 and len(query.get("t", [])) <= 1:
                found.append(Sbsd(page, script_url, provenance=reference))
            continue
        if source.path and not source.path.lower().endswith((".js", ".mjs", ".cjs")):
            found.append(Sensor(page, script_url, provenance=reference))
    if where is not None:
        found = [item for item in found if bool(where.resolve(item))]
    if panic and len(found) > 1:
        raise AmbiguousProtectionError(
            f"Found {len(found)} protection candidates; use where to select one "
            "or panic=False to inspect all candidates."
        )
    return found
