"""One WebSocket reader and owned target operations for an active document."""

import asyncio
import base64
import binascii
import json
import re
from collections.abc import Callable, Coroutine
from contextlib import suppress
from threading import Event, Thread, current_thread
from time import monotonic, time_ns
from types import TracebackType
from typing import TypeVar, cast
from urllib.parse import urlsplit

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import InvalidStatus

from ._turn import _TurnAllocation, _TurnServer
from .errors import NullgateError, _retry_after
from .target import Target, TargetRequest

_T = TypeVar("_T")


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
        start: dict[str, object],
        target: Target,
        on_state: Callable[[str], None],
        on_close: Callable[[], None],
        open_timeout: float,
    ) -> None:
        self._url = url
        self._api_key = api_key
        self._start_message = start
        self._target = target
        self._on_state = on_state
        self._on_close = on_close
        self._open_timeout = open_timeout
        self._request_id: str | None = None
        self._error: NullgateError | None = None
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
            raise NullgateError("Profile has no request ID", code="protocol_error")
        return self._request_id

    @property
    def is_closed(self) -> bool:
        return self._closed or self._closing

    @property
    def error(self) -> NullgateError | None:
        return self._error

    @property
    def is_collected(self) -> bool:
        """All installed collector lifetimes ended, not target acceptance."""
        return self._collected_received and not self.is_closed and self._error is None

    def raise_for_error(self) -> None:
        if self._error is not None:
            raise self._error
        if self.is_closed:
            raise NullgateError(
                "Profile is closed", code="closed", request_id=self._request_id
            )

    async def _start(self) -> None:
        self.raise_for_error()
        self._runner = asyncio.create_task(self._run())
        try:
            async with asyncio.timeout(self._open_timeout):
                await self._ready.wait()
            self.raise_for_error()
            if not self._ready_received:
                raise NullgateError(
                    "Profile ended before ready",
                    code="protocol_error",
                    request_id=self._request_id,
                )
        except TimeoutError:
            await self.aclose()
            raise NullgateError(
                "Profile startup timed out", code="transport_error"
            ) from None
        except BaseException:
            await self.aclose()
            raise

    async def _send(self, message: dict[str, object]) -> None:
        async with self._writes:
            if self._websocket is None:
                raise NullgateError(
                    "Profile connection is unavailable",
                    code="transport_error",
                    request_id=self._request_id,
                )
            try:
                await self._websocket.send(
                    json.dumps(message, ensure_ascii=False, separators=(",", ":"))
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise NullgateError(
                    "Profile connection failed",
                    code="transport_error",
                    request_id=self._request_id,
                ) from None

    async def _connect(self) -> ClientConnection:
        deadline = monotonic() + self._open_timeout
        for attempt in range(3):
            try:
                return await connect(
                    self._url,
                    additional_headers={"Authorization": f"Bearer {self._api_key}"},
                    user_agent_header=None,
                    proxy=None,
                    open_timeout=max(0.001, deadline - monotonic()),
                    close_timeout=4,
                )
            except InvalidStatus as exc:
                try:
                    body = json.loads(exc.response.body)
                    error = NullgateError(
                        _text(body["message"]).replace(self._api_key, "[redacted]"),
                        code=_text(body["code"]),
                        request_id=_text(body["request_id"]),
                        status=exc.response.status_code,
                    )
                except (ValueError, TypeError, KeyError):
                    raise NullgateError(
                        "Profile handshake rejected",
                        code="transport_error",
                        status=exc.response.status_code,
                    ) from None
                delay = _retry_after(exc.response.headers.get("Retry-After"))
                if (
                    error.code != "maintenance"
                    or attempt == 2
                    or delay is None
                    or monotonic() + delay >= deadline
                ):
                    raise error from None
                await asyncio.sleep(delay)
        raise AssertionError("Unreachable handshake retry")

    async def _run(self) -> None:
        try:
            self._websocket = await self._connect()
            await self._send(self._start_message)
            while not self._closing:
                raw = await self._websocket.recv()
                try:
                    if not isinstance(raw, str):
                        raise ValueError
                    message = _object(json.loads(raw, object_pairs_hook=_unique_object))
                    self._receive(message)
                except (ValueError, TypeError, KeyError, binascii.Error):
                    raise NullgateError(
                        "Malformed profile message",
                        code="protocol_error",
                        request_id=self._request_id,
                    ) from None
        except asyncio.CancelledError:
            if not self._closing and self._error is None:
                self._error = NullgateError(
                    "Profile connection cancelled",
                    code="transport_error",
                    request_id=self._request_id,
                )
        except NullgateError as exc:
            self._error = exc
        except Exception:
            self._error = NullgateError(
                "Profile connection closed unexpectedly",
                code="transport_error",
                request_id=self._request_id,
            )
        finally:
            self._closed = True
            self._ready.set()
            self._collected.set()
            waiter = self._pagehide_waiter
            if waiter is not None and not waiter.done():
                waiter.set_exception(
                    self._error
                    or NullgateError(
                        "Profile is closed", code="closed", request_id=self._request_id
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
            if message.keys() != {"type", "code", "message", "request_id"}:
                raise ValueError
            raise NullgateError(
                _text(message["message"]).replace(self._api_key, "[redacted]"),
                code=_text(message["code"]),
                request_id=_text(message["request_id"]),
            )
        if kind == "hello":
            if message.keys() != {"type", "session", "request_id"} or self._request_id:
                raise ValueError
            self._request_id = _text(message["request_id"])
            self._on_state(_text(message["session"]))
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
        raise NullgateError(
            "Unknown profile message type",
            code="protocol_error",
            request_id=self._request_id,
        )

    def _network_done(self, task: asyncio.Task[None]) -> None:
        self._network.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None and not self._closing and not self._closed:
            self._error = (
                error
                if isinstance(error, NullgateError)
                else NullgateError(
                    "Profile target operation failed",
                    code="transport_error",
                    request_id=self._request_id,
                )
            )
            if self._runner is not None:
                self._runner.cancel()

    async def _http(self, operation_id: int, request: TargetRequest) -> None:
        try:
            response = await self._target._fetch(request)
            received_at_ms = time_ns() // 1_000_000
        except Exception:
            message: dict[str, object] = {
                "type": "http.error",
                "id": operation_id,
                "detail": "Target request failed",
            }
            await self._send(message)
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
            raise NullgateError(
                "pagehide.at_ms must be a nonnegative Unix millisecond time",
                code="invalid_request",
            )
        if type(persisted) is not bool:
            raise NullgateError(
                "pagehide.persisted must be bool", code="invalid_request"
            )
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
            raise NullgateError("Nullgate is closed", code="closed")
        if current_thread() is self._thread:
            coroutine.close()
            raise NullgateError(
                "Synchronous methods cannot run on their own event loop",
                code="invalid_request",
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
    ) -> None:
        self._active = active
        self._loop = loop

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
    def error(self) -> NullgateError | None:
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
