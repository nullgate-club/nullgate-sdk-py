"""Finite target HTTP operations using the caller's transport and cookie store."""

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal, TypeAlias
from urllib.parse import urlsplit

from python_socks import parse_proxy_url

from .errors import NullgateError


@dataclass(frozen=True, slots=True)
class TargetRequest:
    role: str
    url: str
    method: str
    headers: Mapping[str, str] = field(repr=False)
    body: bytes | None = field(repr=False)
    credentials: Literal["include", "omit"]


@dataclass(frozen=True, slots=True)
class TargetResponse:
    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise NullgateError(
                "TargetResponse.status must be an HTTP status", code="invalid_response"
            )
        if not isinstance(self.body, bytes):
            raise NullgateError(
                "TargetResponse.body must be bytes", code="invalid_response"
            )
        if not all(
            isinstance(name, str) and isinstance(value, str)
            for name, value in self.headers.items()
        ):
            raise NullgateError(
                "TargetResponse.headers must contain strings", code="invalid_response"
            )


TargetFetch: TypeAlias = Callable[
    [TargetRequest], TargetResponse | Awaitable[TargetResponse]
]


def _proxy_url(proxy: str | None) -> str | None:
    if proxy is None or proxy == "":
        return None
    try:
        parsed = urlsplit(proxy)
        if (
            not parsed.hostname
            or parsed.port is None
            or not 1 <= parsed.port <= 65535
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or any(character.isspace() for character in proxy)
        ):
            raise ValueError
        parse_proxy_url(proxy)
    except (TypeError, ValueError):
        raise ValueError(
            "Target proxy must be an absolute http, socks4, or socks5 URL "
            "with an explicit port; use proxy=None for direct access"
        ) from None
    return proxy


@dataclass(frozen=True, slots=True)
class Target:
    """Reuse a fetch callback; proxy is the explicit local TURN route.

    The callback owns HTTP routing, deadlines and response cleanup. It must honor
    credentials='omit' without sending or retaining cookies. The SDK never closes
    or changes its client. Sync callbacks run off the WebSocket event-loop thread.
    """

    fetch: TargetFetch = field(repr=False)
    proxy: str | None = field(repr=False, kw_only=True)

    def __post_init__(self) -> None:
        if not callable(self.fetch):
            raise TypeError("Target.fetch must be callable")
        object.__setattr__(self, "proxy", _proxy_url(self.proxy))

    async def _fetch(self, request: TargetRequest) -> TargetResponse:
        if inspect.iscoroutinefunction(self.fetch):
            response = await self.fetch(request)
        else:
            work = asyncio.create_task(asyncio.to_thread(self.fetch, request))
            try:
                response = await asyncio.shield(work)
            except asyncio.CancelledError:
                # A Python thread cannot be killed; drain the caller's bounded fetch.
                try:
                    response = await work
                except Exception:
                    pass
                else:
                    if inspect.isawaitable(response):
                        pending = asyncio.ensure_future(response)
                        pending.cancel()
                        await asyncio.gather(pending, return_exceptions=True)
                raise
            if inspect.isawaitable(response):
                response = await response
        if not isinstance(response, TargetResponse):
            raise TypeError("Target.fetch must return a TargetResponse")
        return response
