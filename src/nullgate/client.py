"""Provider-neutral clients with one isolated state stream per open session."""

import asyncio
import json
import math
from threading import Lock
from types import TracebackType
from typing import Literal, TypedDict, cast, overload
from uuid import UUID

import httpx
from magic_filter import MagicFilter

from .akamai import Params, PixelParams, Protection, SbsdParams, SensorParams
from .akamai.inputs import prepare_inputs
from .html import find_protections
from .models import Page
from .solution import Solution, SolutionAsync

_BASE_URL = "https://akamai.nullgate.club"
_ANALYTICS_URL = "https://analytics.nullgate.club"
_REPORT_TIMEOUT = httpx.Timeout(3.0)


class NullgateAPIError(httpx.HTTPStatusError):
    """Original service status, detail, response, and diagnostic request ID."""

    def __init__(self, response: httpx.Response) -> None:
        self.status_code = response.status_code
        self.request_id = response.headers.get("X-Request-ID")
        self.detail: object
        try:
            body = response.json()
        except ValueError:
            self.detail = response.text
        else:
            self.detail = body.get("detail", body) if isinstance(body, dict) else body
        super().__init__(
            f"Nullgate HTTP {self.status_code}: {self.detail} "
            f"(request_id={self.request_id})",
            request=response.request,
            response=response,
        )


class _Generated(TypedDict):
    send_at: float
    headers: dict[str, str]


class _SensorGenerated(_Generated):
    sensor_data: str


class _TargetGenerated(_Generated):
    url: str
    body: str


class _SolutionData(TypedDict):
    url: str
    body: str
    send_at: float
    headers: dict[str, str]
    request_id: str


def _payload(
    params: Params, timezone: str | None
) -> tuple[Literal["pixel", "akamai", "sbsd"], dict[str, object]]:
    operation: Literal["pixel", "akamai", "sbsd"]
    match params:
        case PixelParams():
            operation = "pixel"
            values: dict[str, object] = {"challenge": params.protection.challenge}
        case SensorParams():
            operation = "akamai"
            values = {"cookies": dict(params.cookies or {})}
            if params.inputs is not None:
                values["inputs"] = prepare_inputs(params.inputs)
            if params.actions is not None:
                actions: list[dict[str, object]] = []
                for action in params.actions:
                    if action.get("type") in ("input", "change") and isinstance(
                        action.get("value"), str
                    ):
                        raise TypeError(
                            "Raw action input values are not allowed; "
                            "use a prepared InputValue"
                        )
                    actions.append(dict(action))
                values["actions"] = actions
        case SbsdParams():
            operation = "sbsd"
            values = {"cookies": dict(params.cookies or {})}
        case _:
            raise TypeError("solve requires PixelParams, SensorParams, or SbsdParams")
    protection = params.protection
    values["website"] = {"url": protection.page.url, "html": protection.page.html}
    values["script"] = {"source": protection.script_url, "text": params.script}
    if timezone is not None:
        values["timezone"] = timezone
    return operation, values


def _solution_data(response: httpx.Response, params: Params) -> _SolutionData:
    if not response.is_success:
        raise NullgateAPIError(response)
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("Nullgate response must be a JSON object")
    headers = data.get("headers")
    send_at = data.get("send_at")
    if not isinstance(headers, dict) or not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in headers.items()
    ):
        raise ValueError("Nullgate response headers must contain string values")
    if (
        isinstance(send_at, bool)
        or not isinstance(send_at, (int, float))
        or not math.isfinite(send_at)
    ):
        raise ValueError("Nullgate response send_at must be a finite Unix timestamp")
    request_id = response.headers.get("X-Request-ID")
    if not request_id:
        raise ValueError("Nullgate response is missing X-Request-ID")
    match params:
        case SensorParams():
            sensor = cast(_SensorGenerated, data)
            if not isinstance(sensor.get("sensor_data"), str):
                raise ValueError("Nullgate response sensor_data must be a string")
            content_type = "text/plain;charset=UTF-8"
            url = params.protection.script_url
            body = json.dumps(
                {"sensor_data": sensor["sensor_data"]},
                ensure_ascii=False,
                separators=(",", ":"),
            )
            common: _Generated = sensor
        case PixelParams() | SbsdParams():
            target = cast(_TargetGenerated, data)
            if not isinstance(target.get("url"), str) or not isinstance(
                target.get("body"), str
            ):
                raise ValueError("Nullgate response must contain target URL and body")
            content_type = (
                "application/json"
                if isinstance(params, SbsdParams)
                else "application/x-www-form-urlencoded"
            )
            url, body = target["url"], target["body"]
            common = target
        case _:
            raise TypeError("solve requires PixelParams, SensorParams, or SbsdParams")
    target_headers = {name.lower(): value for name, value in common["headers"].items()}
    target_headers["content-type"] = content_type
    return {
        "url": url,
        "body": body,
        "headers": target_headers,
        "send_at": send_at,
        "request_id": request_id,
    }


def _generate_request(
    base_url: str,
    api_key: str,
    identity: UUID,
    user_agent: str,
    timezone: str | None,
    state_id: str | None,
    params: Params,
) -> httpx.Request:
    operation, payload = _payload(params, timezone)
    headers = {"Authorization": f"Bearer {api_key}", "User-Agent": user_agent}
    if state_id is not None:
        headers["X-State-ID"] = state_id
    return httpx.Request(
        "POST",
        f"{base_url}/v1/{identity}/generate",
        params={"type": operation},
        headers=headers,
        json=payload,
    )


def _report_request(analytics_url: str, request_id: str) -> httpx.Request:
    # A fresh Request deliberately bypasses the shared client's cookie/header defaults.
    return httpx.Request(
        "POST",
        f"{analytics_url}/report",
        json={"request_id": request_id},
        extensions={"timeout": _REPORT_TIMEOUT.as_dict()},
    )


class NullgateClient:
    """Own one reusable API transport, never the caller's target transport."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = _BASE_URL,
        analytics_url: str = _ANALYTICS_URL,
        timeout: httpx.Timeout | float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._analytics_url = analytics_url.rstrip("/")
        self._http = httpx.Client(timeout=timeout, transport=transport)

    @property
    def is_closed(self) -> bool:
        return self._http.is_closed

    def open(
        self, *, identity: UUID | str, user_agent: str, timezone: str | None = None
    ) -> "NullgateSession":
        if self.is_closed:
            raise RuntimeError("NullgateClient is closed")
        return NullgateSession(self, identity, user_agent, timezone)

    def find_protections(
        self, page: Page, where: MagicFilter | None = None, *, panic: bool = True
    ) -> list[Protection]:
        return find_protections(page, where, panic=panic)

    def report(self, request_id: str) -> bool:
        """Best-effort HTTP delivery; a 2xx does not prove archive acceptance."""
        try:
            response = self._http.send(
                _report_request(self._analytics_url, request_id),
                auth=None,
                follow_redirects=False,
            )
        except (
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.RemoteProtocolError,
            httpx.ProxyError,
            httpx.DecodingError,
        ):
            return False
        return response.is_success

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "NullgateClient":
        self._http.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class NullgateClientAsync:
    """Async API transport with synchronous local protection discovery."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = _BASE_URL,
        analytics_url: str = _ANALYTICS_URL,
        timeout: httpx.Timeout | float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._analytics_url = analytics_url.rstrip("/")
        self._http = httpx.AsyncClient(timeout=timeout, transport=transport)

    @property
    def is_closed(self) -> bool:
        return self._http.is_closed

    def open(
        self, *, identity: UUID | str, user_agent: str, timezone: str | None = None
    ) -> "NullgateSessionAsync":
        if self.is_closed:
            raise RuntimeError("NullgateClientAsync is closed")
        return NullgateSessionAsync(self, identity, user_agent, timezone)

    def find_protections(
        self, page: Page, where: MagicFilter | None = None, *, panic: bool = True
    ) -> list[Protection]:
        return find_protections(page, where, panic=panic)

    async def report(self, request_id: str) -> bool:
        """Best-effort HTTP delivery; cancellation and programming errors propagate."""
        try:
            response = await self._http.send(
                _report_request(self._analytics_url, request_id),
                auth=None,
                follow_redirects=False,
            )
        except (
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.RemoteProtocolError,
            httpx.ProxyError,
            httpx.DecodingError,
        ):
            return False
        return response.is_success

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "NullgateClientAsync":
        await self._http.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()


class NullgateSession:
    """A document state stream; closing it never closes the originating client."""

    def __init__(
        self,
        client: NullgateClient,
        identity: UUID | str,
        user_agent: str,
        timezone: str | None,
    ) -> None:
        self.identity = identity if isinstance(identity, UUID) else UUID(identity)
        self.user_agent = user_agent
        self.timezone = timezone
        self._client = client
        self._state_id: str | None = None
        self._closed = False
        self._lock = Lock()

    @property
    def is_closed(self) -> bool:
        return self._closed or self._client.is_closed

    @overload
    def solve(self, params: PixelParams) -> Solution: ...

    @overload
    def solve(self, params: SensorParams) -> Solution: ...

    @overload
    def solve(self, params: SbsdParams) -> Solution: ...

    def solve(self, params: Params) -> Solution:
        with self._lock:
            if self.is_closed:
                raise RuntimeError("NullgateSession is closed")
            response = self._client._http.send(
                _generate_request(
                    self._client._base_url,
                    self._client._api_key,
                    self.identity,
                    self.user_agent,
                    self.timezone,
                    self._state_id,
                    params,
                ),
                auth=None,
                follow_redirects=False,
                stream=True,
            )
            try:
                state_id = response.headers.get("X-State-ID")
                if state_id is not None:
                    self._state_id = state_id
                response.read()
                return Solution(
                    **_solution_data(response, params), _reporter=self._client.report
                )
            finally:
                response.close()

    def close(self) -> None:
        self._closed = True
        self._state_id = None

    def __enter__(self) -> "NullgateSession":
        if self.is_closed:
            raise RuntimeError("NullgateSession is closed")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class NullgateSessionAsync:
    """Sequential async generation in one state stream, independent of others."""

    def __init__(
        self,
        client: NullgateClientAsync,
        identity: UUID | str,
        user_agent: str,
        timezone: str | None,
    ) -> None:
        self.identity = identity if isinstance(identity, UUID) else UUID(identity)
        self.user_agent = user_agent
        self.timezone = timezone
        self._client = client
        self._state_id: str | None = None
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def is_closed(self) -> bool:
        return self._closed or self._client.is_closed

    @overload
    async def solve(self, params: PixelParams) -> SolutionAsync: ...

    @overload
    async def solve(self, params: SensorParams) -> SolutionAsync: ...

    @overload
    async def solve(self, params: SbsdParams) -> SolutionAsync: ...

    async def solve(self, params: Params) -> SolutionAsync:
        async with self._lock:
            if self.is_closed:
                raise RuntimeError("NullgateSessionAsync is closed")
            response = await self._client._http.send(
                _generate_request(
                    self._client._base_url,
                    self._client._api_key,
                    self.identity,
                    self.user_agent,
                    self.timezone,
                    self._state_id,
                    params,
                ),
                auth=None,
                follow_redirects=False,
                stream=True,
            )
            try:
                state_id = response.headers.get("X-State-ID")
                if state_id is not None:
                    self._state_id = state_id
                await response.aread()
                return SolutionAsync(
                    **_solution_data(response, params), _reporter=self._client.report
                )
            finally:
                await response.aclose()

    async def aclose(self) -> None:
        self._closed = True
        self._state_id = None

    async def __aenter__(self) -> "NullgateSessionAsync":
        if self.is_closed:
            raise RuntimeError("NullgateSessionAsync is closed")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()
