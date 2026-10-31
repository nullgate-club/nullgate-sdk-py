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
class ThreatMetrixParams:
    protection: ThreatMetrix
    inputs: Sequence[Mapping[str, str]] | None = field(default=None, repr=False)
    actions: Sequence[Mapping[str, object]] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.protection, ThreatMetrix):
            raise TypeError("ThreatMetrixParams requires a ThreatMetrix protection")
