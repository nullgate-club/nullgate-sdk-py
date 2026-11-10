import asyncio
import socket
import ssl
from uuid import UUID

import httpx
import pytest

from nullgate import (
    ErrorInfo,
    ErrorTarget,
    NullgateAPIError,
    NullgateClient,
    Page,
    Target,
    TargetRequest,
    TargetResponse,
    TransportCause,
)
from nullgate.akamai import Sensor, SensorParams
from nullgate.errors import _transport_cause
from nullgate.profile import ProfileAsync, ProfileServiceError


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {"code": "bad"},
        {"code": "bad", "origin": [], "message": "safe", "retryable": None},
        {
            "code": "FUTURE_ERROR",
            "origin": "upstream",
            "message": "safe",
            "retryable": None,
            "target": {"role": "tags", "method": "GET", "host": "tags.example"},
            "cause": {"kind": "dns", "type": "gaierror", "code": "EAI_NONAME"},
        },
    ],
)
def test_http_metadata_keeps_status_and_private_legacy_detail(metadata: object) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Nullgate-Error-Format"] == "1"
        return httpx.Response(
            502,
            json={"detail": "private body", "error": metadata},
            headers={"X-Request-ID": "diagnostic-id"},
        )

    page = Page("https://target.example/", "<html></html>")
    params = SensorParams(Sensor(page, "https://target.example/script.js"), "source")
    with NullgateClient("key", transport=httpx.MockTransport(respond)) as client:
        session = client.open(identity=UUID(int=1), user_agent="UA")
        with pytest.raises(NullgateAPIError) as failure:
            session.solve(params)
    error = failure.value
    assert error.status_code == 502
    assert error.detail == "private body"
    assert error.request_id == "diagnostic-id"
    assert "private" not in str(error)
    assert "private" not in repr(error)
    if isinstance(metadata, dict) and metadata.get("code") == "FUTURE_ERROR":
        assert error.error_info == ErrorInfo(
            "FUTURE_ERROR",
            "upstream",
            "safe",
            None,
            target=ErrorTarget("tags", "GET", "tags.example"),
            cause=TransportCause("dns", "gaierror", "EAI_NONAME"),
        )
        assert "FUTURE_ERROR/upstream" in str(error)
    else:
        assert error.error_info is None
    assert "CLIENT_TRANSPORT_ERROR" not in str(error)


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (TimeoutError("private"), "timeout"),
        (socket.gaierror(-2, "private"), "dns"),
        (ssl.SSLError("private"), "tls"),
        (httpx.ProxyError("private"), "proxy"),
        (ConnectionRefusedError("private"), "connection"),
        (RuntimeError("timeout DNS proxy ECONNREFUSED private"), "unknown"),
        (
            httpx.HTTPStatusError(
                "502 private",
                request=httpx.Request("GET", "https://target.example"),
                response=httpx.Response(502),
            ),
            "unknown",
        ),
    ],
)
def test_transport_cause_uses_types_not_private_messages(
    error: BaseException,
    kind: str,
) -> None:
    cause = _transport_cause(error)
    assert cause.kind == kind
    assert "private" not in str(cause._as_dict())


def test_target_cancellation_does_not_send_http_error() -> None:
    async def scenario() -> None:
        async def fetch(request: TargetRequest) -> TargetResponse:
            raise asyncio.CancelledError

        profile = ProfileAsync.__new__(ProfileAsync)
        profile._target = Target(fetch, proxy=None)
        profile._error_format = True
        profile._target_errors = {}
        with pytest.raises(asyncio.CancelledError):
            await profile._http(
                1,
                TargetRequest(
                    "tags", "https://target.example/", "GET", {}, None, "include"
                ),
            )
        assert profile._target_errors == {}

    asyncio.run(scenario())


@pytest.mark.parametrize("command_id", [1, 2, None, True, 0, -1, "1", 1.5])
def test_http_command_id_metadata_is_optional_and_strict(command_id: object) -> None:
    error = NullgateAPIError(
        httpx.Response(
            502,
            request=httpx.Request("POST", "https://service.example/"),
            json={
                "detail": "legacy failure",
                "error": {
                    "code": "FUTURE_ERROR",
                    "origin": "service",
                    "message": "safe",
                    "retryable": None,
                    "command_id": command_id,
                },
            },
        )
    )
    assert error.status_code == 502
    assert error.detail == "legacy failure"
    if type(command_id) is int and command_id > 0:
        assert error.error_info is not None
        assert error.error_info.command_id == command_id
    else:
        assert error.error_info is None


def test_structured_failure_format_starts_with_classification() -> None:
    info = ErrorInfo(
        "CLIENT_TRANSPORT_ERROR",
        "client",
        "private metadata message",
        None,
        command_id=1,
    )
    error = ProfileServiceError(
        "private legacy detail",
        status_code=502,
        request_id="diagnostic",
        error_info=info,
        target_error=TimeoutError("private target URL"),
    )
    assert str(error).startswith("[CLIENT_TRANSPORT_ERROR/client]")
    assert "Target HTTP transport failed" in str(error)
    assert "private" not in str(error)
    assert "private" not in repr(error)
    assert "diagnostic" in str(error)
    legacy = ProfileServiceError("private detail", status_code=502)
    assert str(legacy).startswith("Unclassified profile HTTP failure")
