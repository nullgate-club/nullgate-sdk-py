"""One WebSocket reader and owned target operations for an active document."""

import asyncio
import base64
import binascii
import json
import re
from collections.abc import Awaitable, Callable, Coroutine
from contextlib import suppress
from threading import Event, Thread, current_thread
from time import time_ns
from types import TracebackType
from typing import TypeVar, cast
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import InvalidStatus

from ._turn import _TurnAllocation, _TurnServer
from .akamai.inputs import _prepare_actions, prepare_inputs
from .target import Target, TargetRequest
from .threatmetrix import ThreatMetrixCollector, ThreatMetrixParams

_PROFILE_BASE_URL = "https://threatmetrix.nullgate.club"
_T = TypeVar("_T")


class ProfileError(Exception):
    """A profiling failure, without a fabricated HTTP-library response."""

    def __init__(
        self,
        detail: str,
        *,
        request_id: str | None = None,
        status_code: int | None = None,
    ) -> None:
        self.detail = detail
        self.request_id = request_id
        self.status_code = status_code
        super().__init__(f"{detail} (status={status_code}, request_id={request_id})")


class ProfileServiceError(ProfileError):
    """The service rejected or failed the profile."""


class ProfileProtocolError(ProfileError):
    """The peer sent a malformed, out-of-order, or unknown protocol message."""


class ProfileTransportError(ProfileError):
    """The WebSocket or a held TURN allocation ended unexpectedly."""


class ProfileClosedError(ProfileError):
    """An operation requires a live profile, but it has been closed."""


def _profile_url(base_url: str, identity: UUID) -> str:
    try:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https", "ws", "wss"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
        _ = parsed.port
    except ValueError:
        raise ValueError(
            "profile_base_url must be an absolute HTTP(S) or WS(S) URL"
        ) from None
    scheme = {"http": "ws", "https": "wss"}.get(parsed.scheme, parsed.scheme)
    return urlunsplit(
        (
            scheme,
            parsed.netloc,
            f"{parsed.path.rstrip('/')}/v1/{identity}/profile",
            "",
            "",
        )
    )


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError
    return cast(dict[str, object], value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError
    return value


def _request_id(value: object) -> str:
    result = _text(value)
    UUID(result)
    return result


def _http_request(value: object) -> TargetRequest:
    data = _object(value)
    if data.keys() != {"role", "url", "method", "headers", "body", "credentials"}:
        raise ValueError
    url, method = _text(data["url"]), _text(data["method"])
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method)
    ):
        raise ValueError
    _ = parsed.port
    headers = _object(data["headers"])
    if not all(isinstance(value, str) for value in headers.values()):
        raise ValueError
    credentials = data["credentials"]
    if credentials not in {"include", "omit"}:
        raise ValueError
    raw_body = data["body"]
    if raw_body is None:
        body = None
    elif isinstance(raw_body, str):
        body = base64.b64decode(raw_body, validate=True)
    else:
        raise ValueError
    return TargetRequest(
        _text(data["role"]),
        url,
        method,
        cast(dict[str, str], headers),
        body,
        credentials,
    )


def _turn_server(value: object) -> _TurnServer:
    data = _object(value)
    if data.keys() != {"host", "port", "transport", "username", "credential"}:
        raise ValueError
    host = _text(data["host"])
    port, username, credential = data["port"], data["username"], data["credential"]
    if (
        type(port) is not int
        or not 1 <= port <= 65535
        or data["transport"] != "tcp"
        or any(character.isspace() for character in host)
        or not isinstance(username, str)
        or not isinstance(credential, str)
    ):
        raise ValueError
    return _TurnServer(host, port, username, credential)


class ProfileAsync:
    """An active TMX document. Closing does not generate a pagehide event."""

    def __init__(
        self,
        *,
        url: str,
        api_key: str,
        user_agent: str,
        state_id: str | None,
        timezone: str | None,
        params: ThreatMetrixParams,
        target: Target,
        on_state: Callable[[str], None],
        on_close: Callable[[], None],
        reporter: Callable[[str], Awaitable[bool]],
        open_timeout: float | None,
    ) -> None:
        self._url = url
        self._api_key = api_key
        self._user_agent = user_agent
        self._state_id = state_id
        page = params.protection.page
        self._start_message: dict[str, object] = {
            "type": "start",
            "at_ms": time_ns() // 1_000_000,
            "website": {
                "url": page.url,
                "html": page.html,
                "document_id": page.document_id,
                "started_at_ms": page.started_at_ms,
            },
            "timezone": timezone,
        }
        protection = params.protection
        if isinstance(protection, ThreatMetrixCollector):
            self._start_message["collector"] = {
                "url": protection.script_url,
                "org_id": protection.org_id,
                "session_id": protection.session_id,
            }
        else:
            self._start_message["tags_url"] = protection.script_url
        if params.inputs is not None:
            self._start_message["inputs"] = prepare_inputs(params.inputs)
        if params.actions is not None:
            self._start_message["actions"] = _prepare_actions(params.actions)
        self._target = target
        self._on_state = on_state
        self._on_close = on_close
        self._reporter = reporter
        self._open_timeout = open_timeout
        self._request_id: str | None = None
        self._error: ProfileError | None = None
        self._websocket: ClientConnection | None = None
        self._runner: asyncio.Task[None] | None = None
        self._close_task: asyncio.Task[None] | None = None
        self._writes = asyncio.Lock()
        self._pagehides = asyncio.Lock()
        self._ready = asyncio.Event()
        self._collected = asyncio.Event()
        self._ready_received = False
        self._collected_received = False
        self._closed = False
        self._closing = False
        self._pagehide_waiter: asyncio.Future[None] | None = None
        self._network: set[asyncio.Task[None]] = set()
        self._seen_ids: set[int] = set()
        self._ice_releases: dict[int, asyncio.Event] = {}
        self._ice_tasks: dict[int, asyncio.Task[None]] = {}

    @property
    def request_id(self) -> str:
        if self._request_id is None:
            raise ProfileProtocolError("Profile has no request ID")
        return self._request_id

    @property
    def is_closed(self) -> bool:
        return self._closed or self._closing

    @property
    def error(self) -> ProfileError | None:
        return self._error

    @property
    def is_collected(self) -> bool:
        """All installed collector lifetimes ended, not target acceptance."""
        return self._collected_received and not self.is_closed and self._error is None

    def raise_for_error(self) -> None:
        if self._error is not None:
            raise self._error
        if self.is_closed:
            raise ProfileClosedError("Profile is closed", request_id=self._request_id)

    async def _start(self) -> None:
        self.raise_for_error()
        self._runner = asyncio.create_task(self._run())
        try:
            await self._ready.wait()
            self.raise_for_error()
            if not self._ready_received:
                raise ProfileProtocolError(
                    "Profile ended before ready", request_id=self._request_id
                )
        except BaseException:
            await self.aclose()
            raise

    async def _send(self, message: dict[str, object]) -> None:
        async with self._writes:
            if self._websocket is None:
                raise ProfileTransportError(
                    "Profile connection is unavailable", request_id=self._request_id
                )
            try:
                await self._websocket.send(
                    json.dumps(message, ensure_ascii=False, separators=(",", ":"))
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise ProfileTransportError(
                    "Profile connection failed", request_id=self._request_id
                ) from None

    async def _run(self) -> None:
        try:
            headers = {
                "Authorization": f"Bearer {self._api_key}",
                "User-Agent": self._user_agent,
            }
            if self._state_id is not None:
                headers["X-State-ID"] = self._state_id
            try:
                self._websocket = await connect(
                    self._url,
                    additional_headers=headers,
                    user_agent_header=None,
                    proxy=None,
                    open_timeout=self._open_timeout,
                    close_timeout=4,
                )
            except InvalidStatus as exc:
                diagnostic_id = exc.response.headers.get("X-Request-ID")
                if diagnostic_id is not None:
                    try:
                        diagnostic_id = _request_id(diagnostic_id)
                    except ValueError:
                        diagnostic_id = None
                raise ProfileServiceError(
                    "Profile handshake rejected",
                    status_code=exc.response.status_code,
                    request_id=diagnostic_id,
                ) from None
            await self._send(self._start_message)
            while not self._closing:
                raw = await self._websocket.recv()
                try:
                    if not isinstance(raw, str):
                        raise ValueError
                    message = _object(json.loads(raw, object_pairs_hook=_unique_object))
                    self._receive(message)
                except (ValueError, TypeError, KeyError, binascii.Error):
                    raise ProfileProtocolError(
                        "Malformed profile message", request_id=self._request_id
                    ) from None
        except asyncio.CancelledError:
            if not self._closing and self._error is None:
                self._error = ProfileTransportError(
                    "Profile connection cancelled", request_id=self._request_id
                )
        except ProfileError as exc:
            self._error = exc
        except Exception:
            self._error = ProfileTransportError(
                "Profile connection closed unexpectedly", request_id=self._request_id
            )
        finally:
            self._closed = True
            self._ready.set()
            self._collected.set()
            waiter = self._pagehide_waiter
            if waiter is not None and not waiter.done():
                waiter.set_exception(
                    self._error
                    or ProfileClosedError(
                        "Profile is closed", request_id=self._request_id
                    )
                )
            for task in self._network:
                task.cancel()
            await asyncio.gather(*self._network, return_exceptions=True)
            self._ice_tasks.clear()
            if self._websocket is not None:
                with suppress(Exception):
                    await self._websocket.close()
            self._api_key = ""
            self._start_message.clear()

    def _receive(self, message: dict[str, object]) -> None:
        kind = message.get("type")
        if kind == "error":
            if not {"type", "status", "detail"} <= message.keys() or not (
                message.keys() <= {"type", "status", "detail", "request_id"}
            ):
                raise ValueError
            status, detail = message["status"], message["detail"]
            if type(status) is not int or not 100 <= status <= 599:
                raise ValueError
            detail = _text(detail)
            if self._api_key:
                detail = detail.replace(self._api_key, "[redacted]")
            request_id = message.get("request_id", self._request_id)
            if request_id is not None:
                request_id = _request_id(request_id)
            if (
                self._request_id is not None
                and request_id is not None
                and request_id != self._request_id
            ):
                raise ValueError
            raise ProfileServiceError(detail, status_code=status, request_id=request_id)
        if kind == "hello":
            if message.keys() != {"type", "state_id", "request_id"} or self._request_id:
                raise ValueError
            state = _text(message["state_id"])
            self._request_id = _request_id(message["request_id"])
            self._on_state(state)
            return
        if self._request_id is None:
            raise ValueError
        if kind in {"http", "ice"}:
            payload_key = "request" if kind == "http" else "server"
            if message.keys() != {"type", "id", payload_key}:
                raise ValueError
            operation_id = message["id"]
            if type(operation_id) is not int or operation_id in self._seen_ids:
                raise ValueError
            self._seen_ids.add(operation_id)
            if kind == "http":
                work = self._http(operation_id, _http_request(message["request"]))
            else:
                server = _turn_server(message["server"])
                release = asyncio.Event()
                self._ice_releases[operation_id] = release
                work = self._ice(operation_id, server, release)
            task = asyncio.create_task(work)
            if kind == "ice":
                self._ice_tasks[operation_id] = task
            self._network.add(task)
            task.add_done_callback(self._network_done)
            return
        if kind == "ice.release":
            if message.keys() != {"type", "id"} or type(message["id"]) is not int:
                raise ValueError
            released = self._ice_releases.get(message["id"])
            if released is None or released.is_set():
                raise ValueError
            released.set()
            task = self._ice_tasks[message["id"]]
            if not task.done():
                task.cancel()
            return
        if kind in {"ready", "collected"}:
            if message.keys() != {"type", "request_id"}:
                raise ValueError
            if message["request_id"] != self._request_id:
                raise ValueError
            if kind == "ready":
                if self._ready_received:
                    raise ValueError
                self._ready_received = True
                self._ready.set()
            else:
                if not self._ready_received or self._collected_received:
                    raise ValueError
                self._collected_received = True
                self._collected.set()
            return
        if kind == "pagehide.done":
            waiter = self._pagehide_waiter
            if message.keys() != {"type"} or waiter is None or waiter.done():
                raise ValueError
            waiter.set_result(None)
            return
        raise ProfileProtocolError(
            "Unknown profile message type", request_id=self._request_id
        )

    def _network_done(self, task: asyncio.Task[None]) -> None:
        self._network.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None and not self._closing and not self._closed:
            self._error = (
                error
                if isinstance(error, ProfileError)
                else ProfileTransportError(
                    "Profile target operation failed", request_id=self._request_id
                )
            )
            if self._runner is not None:
                self._runner.cancel()

    async def _http(self, operation_id: int, request: TargetRequest) -> None:
        try:
            response = await self._target._fetch(request)
            received_at_ms = time_ns() // 1_000_000
        except Exception:
            await self._send(
                {
                    "type": "http.error",
                    "id": operation_id,
                    "detail": "Target request failed",
                }
            )
            return
        await self._send(
            {
                "type": "http.result",
                "id": operation_id,
                "response": {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": base64.b64encode(response.body).decode("ascii"),
                    "received_at_ms": received_at_ms,
                },
            }
        )

    async def _ice(
        self, operation_id: int, server: _TurnServer, release: asyncio.Event
    ) -> None:
        allocation = _TurnAllocation(server, self._target.proxy)
        try:
            try:
                observation = await allocation.open()
            except Exception:
                await self._send(
                    {"type": "ice.result", "id": operation_id, "observation": None}
                )
                return
            await self._send(
                {"type": "ice.result", "id": operation_id, "observation": observation}
            )
            await allocation.wait_for_release(release)
        finally:
            await allocation.aclose()

    async def pagehide(
        self, at_ms: int | None = None, *, persisted: bool = False
    ) -> None:
        if at_ms is not None and (type(at_ms) is not int or at_ms < 0):
            raise ValueError(
                "pagehide.at_ms must be a nonnegative Unix millisecond time"
            )
        if type(persisted) is not bool:
            raise TypeError("pagehide.persisted must be bool")
        try:
            async with self._pagehides:
                self.raise_for_error()
                waiter: asyncio.Future[None] = (
                    asyncio.get_running_loop().create_future()
                )
                self._pagehide_waiter = waiter
                try:
                    await self._send(
                        {
                            "type": "pagehide",
                            "at_ms": time_ns() // 1_000_000 if at_ms is None else at_ms,
                            "persisted": persisted,
                        }
                    )
                    await waiter
                    self.raise_for_error()
                finally:
                    self._pagehide_waiter = None
                    if not waiter.done():
                        waiter.cancel()
                    elif not waiter.cancelled():
                        waiter.exception()
        except asyncio.CancelledError:
            await self.aclose()
            raise

    async def wait_collected(self) -> None:
        try:
            await self._collected.wait()
            self.raise_for_error()
        except asyncio.CancelledError:
            await self.aclose()
            raise

    async def report(self) -> bool:
        """Best-effort analytics delivery, not acceptance, retry or refund."""
        return await self._reporter(self.request_id)

    async def _finish_close(self) -> None:
        self._closing = True
        try:
            if self._websocket is not None and not self._closed:
                with suppress(Exception):
                    async with asyncio.timeout(4):
                        await self._send({"type": "close"})
            if self._runner is not None:
                if not self._runner.done() and not self._closed:
                    self._runner.cancel()
                with suppress(asyncio.CancelledError):
                    await self._runner
        finally:
            self._closed = True
            self._ready.set()
            self._collected.set()
            self._on_close()

    async def aclose(self) -> None:
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._finish_close())
        try:
            await asyncio.shield(self._close_task)
        except asyncio.CancelledError:
            await self._close_task
            raise

    async def __aenter__(self) -> "ProfileAsync":
        self.raise_for_error()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()


class _ProfileLoop:
    """One background event loop, owned by the synchronous API client."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._started = Event()
        self._thread = Thread(target=self._run, name="nullgate-profile", daemon=True)
        self._thread.start()
        self._started.wait()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._started.set()
        self._loop.run_forever()
        self._loop.close()

    def run(self, coroutine: Coroutine[object, object, _T]) -> _T:
        if not self._thread.is_alive() or self._loop.is_closed():
            coroutine.close()
            raise ProfileClosedError("Profile event loop is closed")
        if current_thread() is self._thread:
            coroutine.close()
            raise RuntimeError(
                "Synchronous profile methods cannot run on their own loop"
            )
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        try:
            return future.result()
        except BaseException:
            future.cancel()
            raise

    def close(self) -> None:
        if not self._thread.is_alive():
            return
        self.run(self._loop.shutdown_asyncgens())
        self.run(self._loop.shutdown_default_executor())
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()


class Profile:
    """Synchronous handle; its reader and TURN keep running between calls."""

    def __init__(
        self,
        active: ProfileAsync,
        loop: _ProfileLoop,
        reporter: Callable[[str], bool],
    ) -> None:
        self._active = active
        self._loop = loop
        self._reporter = reporter

    @property
    def request_id(self) -> str:
        return self._active.request_id

    @property
    def is_closed(self) -> bool:
        return self._active.is_closed

    @property
    def is_collected(self) -> bool:
        return self._active.is_collected

    @property
    def error(self) -> ProfileError | None:
        return self._active.error

    def raise_for_error(self) -> None:
        self._active.raise_for_error()

    def pagehide(self, at_ms: int | None = None, *, persisted: bool = False) -> None:
        self.raise_for_error()
        try:
            self._loop.run(self._active.pagehide(at_ms, persisted=persisted))
        except BaseException:
            self.close()
            raise

    def wait_collected(self) -> None:
        self.raise_for_error()
        try:
            self._loop.run(self._active.wait_collected())
        except BaseException:
            self.close()
            raise

    def report(self) -> bool:
        return self._reporter(self.request_id)

    def close(self) -> None:
        if not self._active._close_task or not self._active._close_task.done():
            self._loop.run(self._active.aclose())

    def __enter__(self) -> "Profile":
        self.raise_for_error()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
