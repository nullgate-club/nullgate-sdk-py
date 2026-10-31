import asyncio
import base64
import json
from contextlib import suppress
from typing import Any
from uuid import UUID

import pytest
from aioice import stun
from websockets.asyncio.server import ServerConnection, serve

from nullgate import (
    NullgateClient,
    NullgateClientAsync,
    Page,
    ProfileClosedError,
    ProfileProtocolError,
    ProfileServiceError,
    Target,
    TargetRequest,
    TargetResponse,
    ThreatMetrix,
    ThreatMetrixParams,
)

REQUEST_ID = str(UUID(int=20))
PARAMS = ThreatMetrixParams(
    ThreatMetrix(
        Page("https://target.example/document", "<html></html>"),
        "https://tags.example/fp/tags.js?org_id=org&session_id=target-session",
    )
)


async def send(socket: ServerConnection, **message: object) -> None:
    await socket.send(json.dumps(message))


async def receive(socket: ServerConnection) -> dict[str, Any]:
    return json.loads(await socket.recv())


def http_operation(operation_id: int, *, departure: bool = False) -> dict[str, object]:
    return {
        "type": "http",
        "id": operation_id,
        "request": {
            "role": "departure" if departure else "tags",
            "url": (
                "https://tags.example/departure"
                if departure
                else PARAMS.protection.script_url
            ),
            "method": "POST" if departure else "GET",
            "headers": {},
            "body": "" if departure else None,
            "credentials": "omit" if departure else "include",
        },
    }


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_background_http_preserves_binary_errors_and_services_pagehide(
    asynchronous: bool,
) -> None:
    binary = b"\x00\xff\xfe\x80body"
    observed: list[TargetRequest] = []

    def fetch(request: TargetRequest) -> TargetResponse:
        observed.append(request)
        if request.role == "tags":
            return TargetResponse(403, {"tmx-nonce": "nonce"}, binary)
        return TargetResponse(202, {}, b"")

    async def scenario() -> None:
        async def handler(socket: ServerConnection) -> None:
            await receive(socket)
            await send(
                socket, type="hello", state_id="continuation", request_id=REQUEST_ID
            )
            await send(socket, type="ready", request_id=REQUEST_ID)
            await socket.send(json.dumps(http_operation(1)))
            result = await receive(socket)
            assert result["response"]["status"] == 403
            assert base64.b64decode(result["response"]["body"], validate=True) == binary
            await send(socket, type="collected", request_id=REQUEST_ID)
            departure = await receive(socket)
            assert departure["persisted"] is True
            await socket.send(json.dumps(http_operation(2, departure=True)))
            result = await receive(socket)
            assert result["response"]["status"] == 202
            assert result["response"]["body"] == ""
            await send(socket, type="pagehide.done")
            closing = await receive(socket)
            assert closing == {"type": "close"}
            await socket.wait_closed()

        async with serve(handler, "127.0.0.1", 0) as server:
            endpoint = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"

            def run_sync() -> None:
                with NullgateClient("secret", profile_base_url=endpoint) as client:
                    session = client.open(identity=UUID(int=1), user_agent="UA")
                    profile = session.profile(PARAMS, Target(fetch, proxy=None))
                    profile.wait_collected()
                    assert profile.is_collected
                    profile.pagehide(persisted=True)
                    assert not profile.is_closed
                    session.close()
                    assert profile.is_closed and not profile.is_collected
                with pytest.raises(ProfileClosedError):
                    profile.pagehide()

            async def run_async() -> None:
                async with NullgateClientAsync(
                    "secret", profile_base_url=endpoint
                ) as client:
                    session = client.open(identity=UUID(int=1), user_agent="UA")
                    profile = await session.profile(PARAMS, Target(fetch, proxy=None))
                    await profile.wait_collected()
                    assert profile.is_collected
                    await profile.pagehide(persisted=True)
                    assert not profile.is_closed
                    await session.aclose()
                    assert profile.is_closed and not profile.is_collected
                with pytest.raises(ProfileClosedError):
                    await profile.pagehide()

            async with asyncio.timeout(10):
                if asynchronous:
                    await run_async()
                else:
                    await asyncio.to_thread(run_sync)

    asyncio.run(scenario())
    assert [request.body for request in observed] == [None, b""]
    assert [request.credentials for request in observed] == ["include", "omit"]


def test_duplicate_correlation_fails_before_ready_and_cancels_inflight_http() -> None:
    async def scenario() -> None:
        entered, cancelled = asyncio.Event(), asyncio.Event()

        async def fetch(request: TargetRequest) -> TargetResponse:
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()
            raise AssertionError("unreachable")

        async def handler(socket: ServerConnection) -> None:
            await receive(socket)
            await send(socket, type="hello", state_id="state", request_id=REQUEST_ID)
            await socket.send(json.dumps(http_operation(1)))
            await entered.wait()
            await socket.send(json.dumps(http_operation(1)))
            await send(socket, type="ready", request_id=REQUEST_ID)
            await socket.wait_closed()

        async with serve(handler, "127.0.0.1", 0) as server:
            endpoint = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
            async with NullgateClientAsync(
                "secret", profile_base_url=endpoint
            ) as client:
                async with client.open(
                    identity=UUID(int=1), user_agent="UA"
                ) as session:
                    async with asyncio.timeout(5):
                        with pytest.raises(ProfileProtocolError) as failure:
                            await session.profile(PARAMS, Target(fetch, proxy=None))
                        await cancelled.wait()
                    assert failure.value.request_id == REQUEST_ID

    asyncio.run(scenario())


def test_post_ready_service_error_is_not_a_successful_or_collected_profile() -> None:
    async def scenario() -> None:
        fail = asyncio.Event()

        async def handler(socket: ServerConnection) -> None:
            await receive(socket)
            await send(socket, type="hello", state_id="state", request_id=REQUEST_ID)
            await send(socket, type="ready", request_id=REQUEST_ID)
            await fail.wait()
            await send(
                socket,
                type="error",
                status=422,
                detail="Profile rejected secret",
                request_id=REQUEST_ID,
            )
            await socket.close()

        async with serve(handler, "127.0.0.1", 0) as server:
            endpoint = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
            async with NullgateClientAsync(
                "secret", profile_base_url=endpoint
            ) as client:
                async with client.open(
                    identity=UUID(int=1), user_agent="UA"
                ) as session:
                    profile = await session.profile(
                        PARAMS,
                        Target(
                            lambda request: TargetResponse(200, {}, b""), proxy=None
                        ),
                    )
                    fail.set()
                    with pytest.raises(ProfileServiceError) as failure:
                        await asyncio.wait_for(profile.wait_collected(), timeout=5)
                    assert failure.value.status_code == 422
                    assert failure.value.request_id == REQUEST_ID
                    assert "secret" not in str(failure.value)
                    assert profile.is_closed and not profile.is_collected
                    with pytest.raises(ProfileServiceError):
                        await profile.pagehide()

    asyncio.run(scenario())


@pytest.mark.parametrize("release", [False, True], ids=["cancel", "release"])
def test_real_turn_allocation_is_held_and_refresh_zero_releases_it(
    release: bool,
) -> None:
    async def scenario() -> None:
        allocated, deleted, disconnected = (
            asyncio.Event(),
            asyncio.Event(),
            asyncio.Event(),
        )

        async def turn_peer(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                while True:
                    header = await reader.readexactly(20)
                    size = int.from_bytes(header[2:4], "big")
                    body = await reader.readexactly(size + stun.padding_length(size))
                    request = stun.parse_message(header + body)
                    response = stun.Message(
                        request.message_method,
                        stun.Class.RESPONSE,
                        transaction_id=request.transaction_id,
                    )
                    if request.message_method == stun.Method.ALLOCATE:
                        response.attributes["LIFETIME"] = 600
                        response.attributes["XOR-RELAYED-ADDRESS"] = (
                            "192.0.2.23",
                            45678,
                        )
                        allocated.set()
                    else:
                        assert request.message_method == stun.Method.REFRESH
                        assert request.attributes["LIFETIME"] == 0
                        response.attributes["LIFETIME"] = 0
                        deleted.set()
                    writer.write(bytes(response))
                    await writer.drain()
            except asyncio.IncompleteReadError:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
                disconnected.set()

        async with await asyncio.start_server(turn_peer, "127.0.0.1", 0) as turn_server:
            turn_port = turn_server.sockets[0].getsockname()[1]

            async def handler(socket: ServerConnection) -> None:
                await receive(socket)
                await send(
                    socket, type="hello", state_id="state", request_id=REQUEST_ID
                )
                await send(
                    socket,
                    type="ice",
                    id=3,
                    server={
                        "host": "127.0.0.1",
                        "port": turn_port,
                        "transport": "tcp",
                        "username": "source-user",
                        "credential": "source-credential",
                    },
                )
                result = await receive(socket)
                [candidate] = result["observation"]["candidates"]
                assert "192.0.2.23 45678 typ relay" in candidate["value"]
                assert candidate["elapsed_ms"] >= 0
                assert (
                    result["observation"]["complete_at_ms"] >= candidate["elapsed_ms"]
                )
                assert allocated.is_set() and not deleted.is_set()
                await send(socket, type="ready", request_id=REQUEST_ID)
                if release:
                    await send(socket, type="ice.release", id=3)
                    await deleted.wait()
                    await send(socket, type="collected", request_id=REQUEST_ID)
                with suppress(Exception):
                    await receive(socket)
                await socket.wait_closed()

            async with serve(handler, "127.0.0.1", 0) as server:
                endpoint = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
                async with asyncio.timeout(10):
                    async with NullgateClientAsync(
                        "secret", profile_base_url=endpoint
                    ) as client:
                        session = client.open(identity=UUID(int=1), user_agent="UA")
                        profile = await session.profile(
                            PARAMS,
                            Target(
                                lambda request: TargetResponse(200, {}, b""), proxy=None
                            ),
                        )
                        if release:
                            await profile.wait_collected()
                        else:
                            assert allocated.is_set() and not deleted.is_set()
                        await session.aclose()
                        await deleted.wait()
                        await disconnected.wait()

    asyncio.run(scenario())


def test_profile_summarizes_raw_fields_and_preserves_empty_observations() -> None:
    from nullgate.akamai import prepare_inputs

    raw_value = " a𝄞1! "
    summary = prepare_inputs([{"value": raw_value}])[0]["value"]

    async def scenario() -> None:
        starts: list[dict[str, Any]] = []

        async def handler(socket: ServerConnection) -> None:
            message = await receive(socket)
            starts.append(message)
            assert raw_value not in json.dumps(message, ensure_ascii=False)
            if len(starts) == 1:
                [field] = message["inputs"]
                assert field["attributes"] == {"name": "identifier"}
                assert field["value"]["length"] == 7
                assert field["value"]["counts"] == [7, 3, 1, 1]
                assert field["value"]["trimmed_length"] == 5
                [action] = message["actions"]
                assert action["type"] == "input" and isinstance(action["value"], dict)
            else:
                assert message["inputs"] == []
                assert message["actions"] == []
            await send(socket, type="hello", state_id="state", request_id=REQUEST_ID)
            await send(socket, type="ready", request_id=REQUEST_ID)
            await send(socket, type="collected", request_id=REQUEST_ID)
            await receive(socket)
            await socket.wait_closed()

        async with serve(handler, "127.0.0.1", 0) as server:
            endpoint = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
            async with NullgateClientAsync(
                "secret", profile_base_url=endpoint
            ) as client:
                async with client.open(
                    identity=UUID(int=1), user_agent="UA"
                ) as session:
                    target = Target(
                        lambda request: TargetResponse(200, {}, b""), proxy=None
                    )
                    async with asyncio.timeout(5):
                        async with await session.profile(
                            ThreatMetrixParams(
                                PARAMS.protection,
                                inputs=[{"name": "identifier", "value": raw_value}],
                                actions=[{"type": "input", "at": 10, "value": summary}],
                            ),
                            target,
                        ) as profile:
                            await profile.wait_collected()
                        async with await session.profile(
                            ThreatMetrixParams(
                                PARAMS.protection, inputs=[], actions=[]
                            ),
                            target,
                        ) as profile:
                            await profile.wait_collected()

    asyncio.run(scenario())


def test_raw_action_values_are_rejected_before_opening_the_profile_socket() -> None:
    async def scenario() -> None:
        opened = False

        async def handler(socket: ServerConnection) -> None:
            nonlocal opened
            opened = True
            await socket.close()

        async with serve(handler, "127.0.0.1", 0) as server:
            endpoint = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
            async with NullgateClientAsync(
                "secret", profile_base_url=endpoint
            ) as client:
                async with client.open(
                    identity=UUID(int=1), user_agent="UA"
                ) as session:
                    with pytest.raises(TypeError) as failure:
                        await session.profile(
                            ThreatMetrixParams(
                                PARAMS.protection,
                                actions=[{"type": "input", "value": "never-send-this"}],
                            ),
                            Target(
                                lambda request: TargetResponse(200, {}, b""), proxy=None
                            ),
                        )
                    assert "never-send-this" not in str(failure.value)
                    assert not opened

    asyncio.run(scenario())


def test_ice_release_during_allocate_closes_tcp_without_a_stale_observation() -> None:
    async def scenario() -> None:
        pending, disconnected = asyncio.Event(), asyncio.Event()

        async def turn_peer(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                header = await reader.readexactly(20)
                await reader.readexactly(int.from_bytes(header[2:4], "big"))
                pending.set()
                assert await reader.read() == b""
            finally:
                writer.close()
                await writer.wait_closed()
                disconnected.set()

        async with await asyncio.start_server(turn_peer, "127.0.0.1", 0) as turn_server:
            turn_port = turn_server.sockets[0].getsockname()[1]

            async def handler(socket: ServerConnection) -> None:
                await receive(socket)
                await send(
                    socket, type="hello", state_id="state", request_id=REQUEST_ID
                )
                await send(
                    socket,
                    type="ice",
                    id=5,
                    server={
                        "host": "127.0.0.1",
                        "port": turn_port,
                        "transport": "tcp",
                        "username": "source-user",
                        "credential": "source-credential",
                    },
                )
                await pending.wait()
                await send(socket, type="ice.release", id=5)
                await send(socket, type="ready", request_id=REQUEST_ID)
                await send(socket, type="collected", request_id=REQUEST_ID)
                assert await receive(socket) == {"type": "close"}
                await socket.wait_closed()

            async with serve(handler, "127.0.0.1", 0) as server:
                endpoint = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
                async with asyncio.timeout(5):
                    async with NullgateClientAsync(
                        "secret", profile_base_url=endpoint
                    ) as client:
                        async with client.open(
                            identity=UUID(int=1), user_agent="UA"
                        ) as session:
                            async with await session.profile(
                                PARAMS,
                                Target(
                                    lambda request: TargetResponse(200, {}, b""),
                                    proxy=None,
                                ),
                            ) as profile:
                                await profile.wait_collected()
                                await disconnected.wait()

    asyncio.run(scenario())
