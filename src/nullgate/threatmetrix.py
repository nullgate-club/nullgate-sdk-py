"""ThreatMetrix discovery provenance; collectors execute only on the service."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import ClassVar, Literal
from urllib.parse import parse_qs, urljoin, urlsplit, urlunsplit

from .models import Page, ScriptReference


def _tags_url(page: Page, source: str) -> str:
    try:
        parsed = urlsplit(urljoin(page.url, source))
        query = parse_qs(parsed.query, keep_blank_values=True)
        valid = (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.path.endswith("/tags.js")
            and len(query.get("org_id", [])) == 1
            and bool(query["org_id"][0])
            and len(query.get("session_id", [])) == 1
            and bool(query["session_id"][0])
        )
        _ = parsed.port
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(
            "ThreatMetrix requires a tags.js URL with one org_id/session_id"
        )
    return urlunsplit(parsed._replace(fragment=""))


@dataclass(frozen=True, slots=True)
class ThreatMetrix:
    page: Page
    script_url: str
    provenance: ScriptReference | None = field(default=None, kw_only=True)
    provider: ClassVar[Literal["threatmetrix"]] = "threatmetrix"
    kind: ClassVar[Literal["profile"]] = "profile"

    def __post_init__(self) -> None:
        object.__setattr__(self, "script_url", _tags_url(self.page, self.script_url))


@dataclass(frozen=True, slots=True)
class ThreatMetrixCollector:
    """A caller-resolved collector, not a replacement tags loader."""

    page: Page
    script_url: str
    org_id: str
    session_id: str
    provider: ClassVar[Literal["threatmetrix"]] = "threatmetrix"
    kind: ClassVar[Literal["profile"]] = "profile"

    def __post_init__(self) -> None:
        if not isinstance(self.page, Page):
            raise TypeError("ThreatMetrixCollector requires a Page")
        parsed = urlsplit(self.script_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.netloc.endswith(":")
            or "#" in self.script_url
            or "\\" in self.script_url
            or any(
                char.isspace() or ord(char) < 32 or ord(char) == 127
                for char in self.script_url
            )
        ):
            raise ValueError(
                "Collector requires an absolute HTTP URL without userinfo or fragment"
            )
        _ = parsed.port
        if any(
            not isinstance(value, str)
            or not value.strip()
            or any(character in value for character in "\r\n")
            for value in (self.org_id, self.session_id)
        ):
            raise ValueError("Collector organization and session must be nonempty")


@dataclass(frozen=True, slots=True)
class ThreatMetrixParams:
    protection: ThreatMetrix | ThreatMetrixCollector
    inputs: Sequence[Mapping[str, str]] | None = field(default=None, repr=False)
    actions: Sequence[Mapping[str, object]] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.protection, (ThreatMetrix, ThreatMetrixCollector)):
            raise TypeError(
                "ThreatMetrixParams requires a tags or collector protection"
            )
