import asyncio
from collections.abc import Callable
from http.cookies import SimpleCookie
from uuid import UUID

import httpx
import pytest

from nullgate import AsyncSession, Session, async_open_session, open_session


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_continuation_rotation_cookies_and_context_isolation(
    asynchronous: bool,
) -> None:
    seen: list[tuple[str | None, dict[str, str], str | None]] = []
    responses = iter(
        [
            httpx.Response(
                200,
                headers={
                    "X-State-ID": "first",
                    "Set-Cookie": "server=present; Path=/",
                },
            ),
            httpx.Response(200, headers={"X-State-ID": "rotated"}),
            httpx.Response(200),
            httpx.Response(200),
            httpx.Response(200, headers={"X-State-ID": "separate"}),
        ]
    )

    def handle(request: httpx.Request) -> httpx.Response:
        cookies: SimpleCookie[str] = SimpleCookie(request.headers.get("Cookie", ""))
        seen.append(
            (
                request.headers.get("X-State-ID"),
                {key: value.value for key, value in cookies.items()},
                request.headers.get("Authorization"),
            )
        )
        return next(responses)

    transport = httpx.MockTransport(handle)
    headers = {"Authorization": "Bearer caller", "X-State-ID": "ignored"}
    uuid = UUID("a07aad50-f262-40b1-b187-11532c054bc0")

    def run_sync() -> None:
        with open_session(
            "https://nullgate.test", uuid=uuid, headers=headers, transport=transport
        ) as client:
            assert seen == []
            client.cookies.set("caller", "kept")
            for _ in range(4):
                client.get("/step").raise_for_status()
        assert client.is_closed
        with pytest.raises(RuntimeError, match="closed"):
            client.get("/step")
        with open_session(
            "https://nullgate.test", uuid=uuid, headers=headers, transport=transport
        ) as other:
            other.get("/step").raise_for_status()
        assert other.is_closed

    async def run_async() -> None:
        async with async_open_session(
            "https://nullgate.test", uuid=uuid, headers=headers, transport=transport
        ) as client:
            assert seen == []
            client.cookies.set("caller", "kept")
            for _ in range(4):
                response = await client.get("/step")
                response.raise_for_status()
        assert client.is_closed
        with pytest.raises(RuntimeError, match="closed"):
            await client.get("/step")
        async with async_open_session(
            "https://nullgate.test", uuid=uuid, headers=headers, transport=transport
        ) as other:
            response = await other.get("/step")
            response.raise_for_status()
        assert other.is_closed

    if asynchronous:
        asyncio.run(run_async())
    else:
        run_sync()

    assert seen == [
        (None, {"caller": "kept"}, "Bearer caller"),
        ("first", {"caller": "kept", "server": "present"}, "Bearer caller"),
        ("rotated", {"caller": "kept", "server": "present"}, "Bearer caller"),
        ("rotated", {"caller": "kept", "server": "present"}, "Bearer caller"),
        (None, {}, "Bearer caller"),
    ]


@pytest.mark.parametrize(
    "constructor", [Session, AsyncSession, open_session, async_open_session]
)
def test_uuid_is_required_and_invalid_uuid_is_rejected(
    constructor: Callable[..., object],
) -> None:
    args = () if constructor in (Session, AsyncSession) else ("https://nullgate.test",)
    with pytest.raises(TypeError, match="uuid"):
        constructor(*args)
    for invalid in ("not-a-uuid", "", "../other"):
        with pytest.raises(ValueError):
            constructor(*args, uuid=invalid)


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_direct_constructor_normalizes_uuid_and_preserves_native_auth(
    asynchronous: bool,
) -> None:
    identity = UUID("a07aad50-f262-40b1-b187-11532c054bc0")

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Basic dXNlcjpwYXNz"
        assert "X-State-ID" not in request.headers
        return httpx.Response(204)

    transport = httpx.MockTransport(handle)

    def run_sync() -> None:
        with Session(
            uuid=identity.hex.upper(),
            base_url="https://nullgate.test",
            auth=("user", "pass"),
            transport=transport,
        ) as client:
            assert client.uuid == identity
            client.get("/step").raise_for_status()
        assert client.is_closed

    async def run_async() -> None:
        async with AsyncSession(
            uuid=identity.hex.upper(),
            base_url="https://nullgate.test",
            auth=("user", "pass"),
            transport=transport,
        ) as client:
            assert client.uuid == identity
            response = await client.get("/step")
            response.raise_for_status()
        assert client.is_closed

    if asynchronous:
        asyncio.run(run_async())
    else:
        run_sync()


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("stateful", [False, True], ids=["direct", "factory"])
def test_explicit_api_key_overrides_only_authorization_and_preserves_httpx_options(
    asynchronous: bool, stateful: bool
) -> None:
    api_key = str(UUID("11111111-1111-4111-8111-111111111111"))
    seen: list[tuple[str, str | None]] = []
    headers = {"Authorization": "Bearer old", "X-Custom": "preserved"}

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Custom"] == "preserved"
        assert request.headers["Cookie"] == "caller=kept"
        seen.append(
            (request.headers["Authorization"], request.headers.get("X-State-ID"))
        )
        return httpx.Response(200, headers={"X-State-ID": "next"})

    kwargs = {
        "base_url": "https://nullgate.test",
        "uuid": UUID("a07aad50-f262-40b1-b187-11532c054bc0"),
        "api_key": api_key,
        "headers": headers,
        "cookies": {"caller": "kept"},
        "transport": httpx.MockTransport(handle),
    }

    async def run_async() -> None:
        constructor = async_open_session if stateful else AsyncSession
        async with constructor(**kwargs) as client:
            for _ in range(2):
                response = await client.get("/step")
                response.raise_for_status()

    if asynchronous:
        asyncio.run(run_async())
    else:
        constructor = open_session if stateful else Session
        with constructor(**kwargs) as client:
            for _ in range(2):
                client.get("/step").raise_for_status()

    assert seen == [
        (f"Bearer {api_key}", None),
        (f"Bearer {api_key}", "next" if stateful else None),
    ]
    assert headers["Authorization"] == "Bearer old"
