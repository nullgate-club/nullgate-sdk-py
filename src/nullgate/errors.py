"""Public service metadata and conservative local transport classification."""

import asyncio
import errno
import re
import socket
import ssl
from dataclasses import asdict, dataclass
from typing import Literal, cast

import httpx

Origin = Literal["client", "request", "service", "upstream"]
CauseKind = Literal[
    "timeout",
    "dns",
    "tls",
    "proxy",
    "connection",
    "cancelled",
    "invalid_response",
    "unknown",
]
_KINDS = {
    "timeout",
    "dns",
    "tls",
    "proxy",
    "connection",
    "cancelled",
    "invalid_response",
    "unknown",
}


@dataclass(frozen=True, slots=True)
class ErrorTarget:
    role: str
    method: str
    host: str


@dataclass(frozen=True, slots=True)
class TransportCause:
    kind: CauseKind
    type: str | None = None
    code: str | None = None

    def _as_dict(self) -> dict[str, str]:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass(frozen=True, slots=True)
class ErrorInfo:
    code: str
    origin: Origin
    message: str
    retryable: bool | None
    stage: str | None = None
    target: ErrorTarget | None = None
    cause: TransportCause | None = None
    command_id: int | None = None


def _token(value: object, limit: int) -> bool:
    return isinstance(value, str) and bool(
        re.fullmatch(r"[A-Za-z0-9_.-]{1," + str(limit) + r"}", value)
    )


def _parse_error_info(value: object) -> ErrorInfo | None:
    if not isinstance(value, dict):
        return None
    code, origin, message = value.get("code"), value.get("origin"), value.get("message")
    retryable = value.get("retryable")
    if (
        not isinstance(code, str)
        or not code
        or origin not in ("client", "request", "service", "upstream")
        or not isinstance(message, str)
        or "retryable" not in value
        or (retryable is not None and type(retryable) is not bool)
    ):
        return None
    stage = value.get("stage")
    if stage is not None and not isinstance(stage, str):
        return None
    command_id = value.get("command_id")
    if "command_id" in value and (type(command_id) is not int or command_id <= 0):
        return None
    target = None
    raw_target = value.get("target")
    if raw_target is not None:
        if not isinstance(raw_target, dict) or not all(
            isinstance(raw_target.get(key), str) for key in ("role", "method", "host")
        ):
            return None
        target = ErrorTarget(
            raw_target["role"], raw_target["method"], raw_target["host"]
        )
    cause = None
    raw_cause = value.get("cause")
    if raw_cause is not None:
        if (
            not isinstance(raw_cause, dict)
            or not isinstance(raw_cause.get("kind"), str)
            or raw_cause["kind"] not in _KINDS
        ):
            return None
        if any(
            key in raw_cause and not _token(raw_cause[key], limit)
            for key, limit in (("type", 128), ("code", 64))
        ):
            return None
        cause = TransportCause(
            cast(CauseKind, raw_cause["kind"]),
            raw_cause.get("type"),
            raw_cause.get("code"),
        )
    return ErrorInfo(
        code, cast(Origin, origin), message, retryable, stage, target, cause, command_id
    )


def _transport_cause(error: BaseException) -> TransportCause:
    kind: CauseKind = "unknown"
    if isinstance(error, (TimeoutError, httpx.TimeoutException)):
        kind = "timeout"
    elif isinstance(error, socket.gaierror):
        kind = "dns"
    elif isinstance(error, ssl.SSLError):
        kind = "tls"
    elif isinstance(error, httpx.ProxyError):
        kind = "proxy"
    elif isinstance(error, (ConnectionError, httpx.NetworkError)):
        kind = "connection"
    elif isinstance(error, asyncio.CancelledError):
        kind = "cancelled"
    elif isinstance(error, httpx.ProtocolError):
        kind = "invalid_response"
    # Known types/codes only; raw exception messages can contain credentials.
    if kind == "unknown":
        return TransportCause(kind)
    name = type(error).__name__
    code = (
        errno.errorcode.get(error.errno)
        if isinstance(error, OSError) and error.errno is not None
        else None
    )
    return TransportCause(kind, name if _token(name, 128) else None, code)
