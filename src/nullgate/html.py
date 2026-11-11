"""Local script discovery, using the v1 HTML heuristics."""

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx

from .models import Page, ScriptReference

_PIXEL_CHALLENGE = re.compile(r"""\bbazadebezolkohpepadr\s*=\s*(['"])([0-9]+)\1""")
_PIXEL_PATH = re.compile(r"/akam/13/[0-9a-fA-F]+")


@dataclass(frozen=True)
class Candidate:
    kind: str
    url: str
    challenge: str | None = None


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


def discover(page: Page) -> tuple[list[Candidate], list[str]]:
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
    found: list[Candidate] = []
    for reference, classic in parser.sources:
        try:
            urlsplit(reference.raw_source)
            source = base.join(reference.raw_source).copy_with(fragment=None)
        except (ValueError, httpx.InvalidURL):
            continue
        script_url = str(source)
        if (
            source.scheme not in {"http", "https"}
            or not source.host
            or source.username
            or source.password
        ):
            continue
        if source.path.endswith("/tags.js"):
            query = parse_qs(source.query.decode(), keep_blank_values=True)
            if all(
                len(query.get(key, [])) == 1 and query[key][0]
                for key in ("org_id", "session_id")
            ):
                found.append(Candidate("threatmetrix", script_url))
            continue
        if not classic or (source.scheme, source.host, source.port) != (
            document.scheme,
            document.host,
            document.port,
        ):
            continue
        if _PIXEL_PATH.fullmatch(source.path):
            found.extend(
                Candidate("pixel", script_url, challenge)
                for challenge in parser.challenges
            )
            continue
        query_parts: dict[str, list[str]] = {}
        for part in source.query.decode().split("&"):
            name, _, value = part.partition("=")
            query_parts.setdefault(name, []).append(value)
        versions = query_parts.get("v", [])
        if any(_is_uuid(version) for version in versions):
            if len(versions) == 1 and len(query_parts.get("t", [])) <= 1:
                found.append(Candidate("sbsd", script_url))
            continue
        if source.path and not source.path.lower().endswith((".js", ".mjs", ".cjs")):
            found.append(Candidate("sensor", script_url))
    return list(dict.fromkeys(found)), list(parser.challenges)
