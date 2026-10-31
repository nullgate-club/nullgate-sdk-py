"""Caller-owned page content and local discovery provenance."""

from dataclasses import dataclass, field
from time import time_ns
from urllib.parse import urlsplit
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class Page:
    url: str
    html: str = field(repr=False)
    document_id: str = field(default_factory=lambda: str(uuid4()), init=False)
    started_at_ms: int = field(
        default_factory=lambda: time_ns() // 1_000_000, init=False
    )

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
