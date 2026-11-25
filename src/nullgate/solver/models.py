"""Local solver inputs and errors, separate from the remote generation API."""

import math
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit


class SolveError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        stage: str,
        cause: str | None = None,
        request_id: str | None = None,
        status: int | None = None,
    ) -> None:
        self.code, self.message, self.stage = code, message, stage
        self.cause, self.request_id, self.status = cause, request_id, status
        super().__init__(message)


def http_url(value: object) -> str:
    if not isinstance(value, str):
        raise SolveError(
            "invalid_request", "url must be an absolute HTTP(S) URL", stage="validate"
        )
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or any(c.isspace() or ord(c) < 32 for c in value)
            or "\\" in value
        ):
            raise ValueError
        _ = parsed.port
    except ValueError:
        raise SolveError(
            "invalid_request",
            "url must be an absolute HTTP(S) URL without credentials or fragment",
            stage="validate",
        ) from None
    return value


@dataclass(kw_only=True)
class Options:
    type: Literal["akamai", "threatmetrix"]
    url: str
    user_agent: str | None = None
    proxy: str | None = field(default=None, repr=False)
    session: str | None = None
    cookies: list[dict[str, Any]] | None = field(default=None, repr=False)
    transport: dict[str, Any] | None = None
    headers: dict[str, str] | None = field(default=None, repr=False)
    collector: dict[str, str] | None = None
    script_url: str | None = None
    pixel_iframe: bool = False

    def __post_init__(self) -> None:
        if self.type not in {"akamai", "threatmetrix"}:
            raise SolveError(
                "invalid_request",
                "type must be akamai or threatmetrix",
                stage="validate",
            )
        self.url = http_url(self.url)
        if self.script_url is not None:
            self.script_url = http_url(self.script_url)
        if self.user_agent is not None and (
            not isinstance(self.user_agent, str)
            or not self.user_agent.strip()
            or len(self.user_agent) > 1024
            or any(ord(c) < 32 or ord(c) > 126 for c in self.user_agent)
        ):
            raise SolveError(
                "invalid_request",
                "user_agent must be a nonempty ASCII header value",
                stage="validate",
            )
        if self.session is not None and (
            not isinstance(self.session, str)
            or not 1 <= len(self.session) <= 128
            or any(ord(c) < 32 for c in self.session)
        ):
            raise SolveError(
                "invalid_request",
                "session must be a nonempty name up to 128 characters",
                stage="validate",
            )
        if type(self.pixel_iframe) is not bool:
            raise SolveError(
                "invalid_request", "pixel_iframe must be a boolean", stage="validate"
            )
        if self.proxy is not None and (
            not isinstance(self.proxy, str) or not self.proxy
        ):
            raise SolveError(
                "invalid_request",
                "proxy must be an absolute proxy URL",
                stage="validate",
            )
        if self.transport is not None and not isinstance(self.transport, dict):
            raise SolveError(
                "invalid_request", "transport must be an object", stage="validate"
            )
        if self.headers is not None:
            if not isinstance(self.headers, dict) or not all(
                isinstance(k, str)
                and isinstance(v, str)
                and k
                and all(32 < ord(c) < 127 and c not in '()<>@,;:\\"/[]?={}' for c in k)
                and all(32 <= ord(c) < 127 for c in v)
                for k, v in self.headers.items()
            ):
                raise SolveError(
                    "invalid_request",
                    "headers must contain valid text headers",
                    stage="validate",
                )
            forbidden = {
                "host",
                "content-length",
                "transfer-encoding",
                "cookie",
                "user-agent",
            }
            if any(k.lower() in forbidden for k in self.headers):
                raise SolveError(
                    "invalid_request",
                    "use user_agent and cookies, not transport-owned headers",
                    stage="validate",
                )
        if self.collector is not None and (
            not isinstance(self.collector, dict)
            or set(self.collector) != {"url", "org_id", "session_id"}
            or not all(isinstance(v, str) and v for v in self.collector.values())
        ):
            raise SolveError(
                "invalid_request",
                "collector needs url, org_id and site session_id",
                stage="validate",
            )
        if self.collector is not None:
            http_url(self.collector["url"])
        if self.cookies is not None:
            if not isinstance(self.cookies, list) or len(self.cookies) > 256:
                raise SolveError(
                    "invalid_request",
                    "cookies must be an array of at most 256 cookies",
                    stage="validate",
                )
            allowed = {
                "name",
                "value",
                "domain",
                "path",
                "secure",
                "http_only",
                "expires",
                "same_site",
                "host_only",
            }
            for cookie in self.cookies:
                if not isinstance(cookie, dict) or set(cookie) - allowed:
                    raise SolveError(
                        "invalid_request", "unknown cookie fields", stage="validate"
                    )
                if not all(isinstance(cookie.get(k), str) for k in ("name", "value")):
                    raise SolveError(
                        "invalid_request",
                        "cookies require name and value strings",
                        stage="validate",
                    )
                if (
                    not cookie["name"]
                    or any(c in cookie["name"] for c in "\r\n;=\t ")
                    or any(c in cookie["value"] for c in "\r\n;")
                    or any(
                        ord(c) < 32 or ord(c) > 126
                        for c in cookie["name"] + cookie["value"]
                    )
                ):
                    raise SolveError(
                        "invalid_request",
                        "invalid cookie name or value",
                        stage="validate",
                    )
                for key in ("domain", "path"):
                    if key in cookie and (
                        not isinstance(cookie[key], str)
                        or not cookie[key]
                        or any(c in cookie[key] for c in "\r\n")
                    ):
                        raise SolveError(
                            "invalid_request",
                            "cookie domain/path must be nonempty strings",
                            stage="validate",
                        )
                for key in ("secure", "http_only", "host_only"):
                    if key in cookie and type(cookie[key]) is not bool:
                        raise SolveError(
                            "invalid_request",
                            "cookie flags must be booleans",
                            stage="validate",
                        )
                expires = cookie.get("expires")
                if expires is not None and (
                    type(expires) not in (int, float)
                    or not math.isfinite(expires)
                    or expires < 0
                ):
                    raise SolveError(
                        "invalid_request",
                        "cookie expires must be a nonnegative Unix timestamp or null",
                        stage="validate",
                    )
                if cookie.get("same_site") not in (None, "Lax", "Strict", "None"):
                    raise SolveError(
                        "invalid_request", "invalid cookie same_site", stage="validate"
                    )
