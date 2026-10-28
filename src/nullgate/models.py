"""Caller-owned page content and local discovery provenance."""

from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class Page:
    url: str
    html: str = field(repr=False)

    def __post_init__(self) -> None:
        parsed = urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Page.url must be an absolute HTTP(S) URL")


@dataclass(frozen=True, slots=True)
class ScriptReference:
    """Location of a classic script tag in the supplied Page, never fetched."""

    raw_source: str
    tag_index: int
    line: int
    column: int
