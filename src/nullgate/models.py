"""Caller-owned page content and local discovery provenance."""

from dataclasses import dataclass, field
from time import time_ns
from urllib.parse import urlsplit
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class Page:
    url: str
    html: str = field(repr=False)
    document_id: str = field(default_factory=lambda: str(uuid4()), kw_only=True)
    started_at_ms: int = field(
        default_factory=lambda: time_ns() // 1_000_000, kw_only=True
    )

    def __post_init__(self) -> None:
        parsed = urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Page.url must be an absolute HTTP(S) URL")
        UUID(self.document_id)
        if type(self.started_at_ms) is not int or self.started_at_ms < 0:
            raise ValueError("Page.started_at_ms must be a nonnegative integer")


@dataclass(frozen=True, slots=True)
class ScriptReference:
    """Location of a classic script tag in the supplied Page, never fetched."""

    raw_source: str
    tag_index: int
    line: int
    column: int
