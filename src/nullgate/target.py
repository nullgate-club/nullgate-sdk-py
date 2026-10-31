"""Finite target HTTP operations using the caller's transport and cookie store."""

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, TypeAlias
from urllib.parse import urlsplit

from python_socks import parse_proxy_url

if TYPE_CHECKING:
    import wreq
    import wreq.blocking
    from wreq import Request as WreqRequest


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
            raise ValueError("TargetResponse.status must be an HTTP status")
        if not isinstance(self.body, bytes):
            raise TypeError("TargetResponse.body must be bytes")
        if not all(
            isinstance(name, str) and isinstance(value, str)
            for name, value in self.headers.items()
        ):
            raise TypeError("TargetResponse.headers must contain strings")


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


def _wreq_headers(headers: "wreq.HeaderMap") -> dict[str, str]:
    result: dict[str, str] = {}
    for key in headers.keys():
        name = bytes(key).decode("ascii")
        result[name] = ", ".join(
            bytes(value).decode("latin-1") for value in headers.get_all(name)
        )
    return result


class WreqTarget(Target):
    """Optional wreq 0.13 adapter; never owns or reconfigures the supplied client.

    Configure that client for the same explicit proxy/direct route. Request-level
    fresh Jars isolate omit operations without touching its shared cookie store.
    """

    def __init__(
        self, client: "wreq.Client | wreq.blocking.Client", *, proxy: str | None
    ) -> None:
        from wreq import Client, Jar, Method, redirect
        from wreq.blocking import Client as BlockingClient

        def options(request: TargetRequest) -> "WreqRequest":
            headers = dict(request.headers)
            if request.credentials == "omit":
                headers = {
                    name: value
                    for name, value in headers.items()
                    if name.lower() != "cookie"
                }
            kwargs: WreqRequest = {
                "headers": headers,
                "default_headers": False,
                "redirect": redirect.Policy.none(),
            }
            if request.body is not None:
                kwargs["body"] = request.body
            if request.credentials == "omit":
                kwargs["cookie_provider"] = Jar()
            return kwargs

        fetch: TargetFetch
        if isinstance(client, Client):
            async_client = client

            async def fetch_async(request: TargetRequest) -> TargetResponse:
                async with async_client.request(
                    getattr(Method, request.method), request.url, **options(request)
                ) as response:
                    return TargetResponse(
                        response.status.as_int(),
                        _wreq_headers(response.headers),
                        bytes(await response.bytes()),
                    )

            fetch = fetch_async
        elif isinstance(client, BlockingClient):
            blocking_client = client

            def fetch_sync(request: TargetRequest) -> TargetResponse:
                with blocking_client.request(
                    getattr(Method, request.method), request.url, **options(request)
                ) as response:
                    return TargetResponse(
                        response.status.as_int(),
                        _wreq_headers(response.headers),
                        bytes(response.bytes()),
                    )

            fetch = fetch_sync
        else:
            raise TypeError("WreqTarget requires a wreq Client or blocking.Client")
        super().__init__(fetch, proxy=proxy)
