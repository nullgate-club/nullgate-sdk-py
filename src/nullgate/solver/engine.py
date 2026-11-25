"""Optional local cookie solving. Install ``nullgate-sdk-py[solver]``."""

import asyncio
import math
from dataclasses import dataclass, field
from hashlib import sha256
from http.cookiejar import Cookie
from types import TracebackType
from typing import Any, Self
from uuid import UUID, uuid5

import httpx

from ..aio import Nullgate
from ..errors import NullgateError
from . import akamai, threatmetrix
from .models import Options, SolveError
from .transport import Transport

__all__ = ["SolveError", "Solver"]


def _domain_matches(cookie: Cookie, host: str) -> bool:
    domain = cookie.domain.lstrip(".").lower()
    return host == domain or (cookie.domain_specified and host.endswith("." + domain))


def _replace_cookies(
    transport: Transport, url: str, values: list[dict[str, Any]]
) -> None:
    host = httpx.URL(url).host.lower()
    incoming = []
    for value in values:
        domain = value.get("domain", host).lower()
        normalized = domain.lstrip(".")
        host_only = value.get("host_only", "domain" not in value)
        if (
            host != normalized
            and (host_only or not host.endswith("." + normalized))
            or (normalized != host and "." not in normalized)
            or not value.get("path", "/").startswith("/")
        ):
            raise SolveError(
                "invalid_request",
                "Cookie domain/path is outside the target site",
                stage="validate",
            )
        rest: dict[str, Any] = {}
        if value.get("http_only"):
            rest["HttpOnly"] = None
        if value.get("same_site") is not None:
            rest["SameSite"] = value["same_site"]
        incoming.append(
            Cookie(
                version=0,
                name=value["name"],
                value=value["value"],
                port=None,
                port_specified=False,
                domain=domain,
                domain_specified=not host_only,
                domain_initial_dot=domain.startswith("."),
                path=value.get("path", "/"),
                path_specified=True,
                secure=value.get("secure", False),
                expires=int(value["expires"])
                if value.get("expires") is not None
                else None,
                discard=value.get("expires") is None,
                comment=None,
                comment_url=None,
                rest=rest,
                rfc2109=False,
            )
        )
    for cookie in list(transport.cookies.jar):
        if _domain_matches(cookie, host):
            transport.cookies.jar.clear(cookie.domain, cookie.path, cookie.name)
    for cookie in incoming:
        transport.cookies.jar.set_cookie(cookie)


def _export_cookies(transport: Transport, url: str) -> list[dict[str, object]]:
    transport.cookies.jar.clear_expired_cookies()
    host = httpx.URL(url).host.lower()
    return [
        {
            "name": cookie.name,
            "value": cookie.value or "",
            "domain": cookie.domain,
            "path": cookie.path,
            "secure": cookie.secure,
            "http_only": cookie.has_nonstandard_attr("HttpOnly"),
            "expires": cookie.expires,
            "host_only": not cookie.domain_specified,
            "same_site": cookie.get_nonstandard_attr("SameSite"),
        }
        for cookie in transport.cookies.jar
        if _domain_matches(cookie, host)
    ]


@dataclass
class _State:
    http: Transport
    user_agent: str
    proxy: str | None = field(repr=False)
    options: dict[str, Any]
    headers: dict[str, str] = field(repr=False)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class Solver:
    """Own a bounded set of local sessions, without a browser or target logins."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = "https://api.nullgate.club",
        timeout: float = 60,
    ) -> None:
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or not 0 < timeout <= 180
        ):
            raise SolveError(
                "invalid_request",
                "timeout must be positive and at most 180 seconds",
                stage="validate",
            )
        self._api = Nullgate(api_key, base_url=base_url, timeout=min(timeout, 30))
        self._namespace = UUID(bytes=sha256(self._api._key.encode()).digest()[:16])
        self._timeout = timeout
        self._states: dict[str, _State] = {}
        self._active: set[asyncio.Task[Any]] = set()
        self._closed = False

    async def solve(self, **kwargs: Any) -> list[dict[str, object]]:
        try:
            request = Options(**kwargs)
        except TypeError:
            raise SolveError(
                "invalid_request",
                "Provide type, url and user_agent; reject unknown fields",
                stage="validate",
            ) from None
        if self._closed:
            raise SolveError("closed", "Solver is closed", stage="validate")
        if len(self._active) >= 4:
            raise SolveError(
                "busy",
                "Four solves are active; try again after one completes",
                stage="admission",
            )
        task = asyncio.current_task()
        assert task is not None
        self._active.add(task)
        state: _State | None = None
        temporary = request.session is None
        try:
            async with asyncio.timeout(self._timeout):
                state = self._states.get(request.session) if request.session else None
                if state is None:
                    if request.user_agent is None:
                        raise SolveError(
                            "session_not_found",
                            "Unknown session; resend UA, proxy and transport",
                            stage="session",
                        )
                    if not temporary and len(self._states) >= 64:
                        raise SolveError(
                            "session_capacity",
                            "64 sessions stored; restart or use one-shot solves",
                            stage="session",
                        )
                    state = _State(
                        Transport(
                            request.user_agent,
                            request.proxy,
                            request.transport,
                            request.headers,
                        ),
                        request.user_agent,
                        request.proxy,
                        dict(request.transport or {}),
                        dict(request.headers or {}),
                    )
                    if request.session:
                        self._states[request.session] = state
                elif (
                    request.user_agent is not None
                    and request.user_agent != state.user_agent
                    or request.proxy is not None
                    and request.proxy != state.proxy
                    or request.transport is not None
                    and request.transport != state.options
                    or request.headers is not None
                    and request.headers != state.headers
                ):
                    raise SolveError(
                        "session_conflict",
                        "UA/proxy/headers/transport changed; use a new session",
                        stage="session",
                    )
                async with state.lock:
                    if request.cookies is not None:
                        _replace_cookies(state.http, request.url, request.cookies)
                    profile = (
                        uuid5(self._namespace, request.session)
                        if request.session
                        else None
                    )
                    # New documents need fresh remote checkpoints.
                    sdk_session = self._api.session(
                        user_agent=state.user_agent, profile=profile
                    )
                    if request.type == "akamai":
                        await akamai.solve(
                            sdk_session,
                            state.http,
                            request.url,
                            script_url=request.script_url,
                            pixel_iframe=request.pixel_iframe,
                        )
                    else:
                        await threatmetrix.solve(
                            sdk_session,
                            state.http,
                            request.url,
                            script_url=request.script_url,
                            collector=request.collector,
                        )
                    return _export_cookies(state.http, request.url)
        except TimeoutError:
            raise SolveError(
                "timeout",
                "Solve exceeded its total deadline",
                stage="solve",
                cause="TimeoutError",
            ) from None
        except NullgateError as error:
            context = error.__context__
            raise SolveError(
                error.code,
                "Nullgate API request failed",
                stage="generate",
                cause=type(context).__name__ if context else None,
                request_id=error.request_id,
                status=error.status,
            ) from None
        finally:
            try:
                if temporary and state is not None:
                    await state.http.aclose()
            finally:
                self._active.discard(task)

    async def aclose(self) -> None:
        self._closed = True
        caller = asyncio.current_task()
        await asyncio.gather(
            *(task for task in self._active if task is not caller),
            return_exceptions=True,
        )
        await asyncio.gather(*(state.http.aclose() for state in self._states.values()))
        self._states.clear()
        await self._api.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
