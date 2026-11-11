import asyncio
import json
from uuid import UUID

import pytest
from websockets.asyncio.server import serve

from nullgate import NullgateError, TargetResponse
from nullgate.aio import Nullgate

HTML = '<script src="https://risk.example/tags.js?org_id=org&amp;session_id=visit"></script>'
URL = "https://shop.example/login"
PROFILE = "00000000-0000-0000-0000-00000000004a"
EMPTY_VALUE = {
    "length": 0,
    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


async def send_json(socket, value):
    await socket.send(json.dumps(value))


async def receive(socket):
    return json.loads(await socket.recv())


def test_scripted_profile_http_pagehide_and_session_continuity():
    async def run():
        starts, replies, targets = [], [], []

        async def server(socket):
            assert socket.request.path == "/threatmetrix/profile"
            assert socket.request.headers["Authorization"] == "Bearer test-key"
            assert "X-State-ID" not in socket.request.headers
            starts.append(await receive(socket))
            await send_json(
                socket,
                {
                    "type": "hello",
                    "session": "tmx-session",
                    "request_id": "correlation-id",
                },
            )
            await send_json(
                socket,
                {
                    "type": "http",
                    "id": 1,
                    "request": {
                        "role": "tags",
                        "url": "https://risk.example/fetch",
                        "method": "POST",
                        "headers": {"content-type": "text/plain"},
                        "body": "aGVsbG8=",
                        "credentials": "omit",
                    },
                },
            )
            replies.append(await receive(socket))
            await send_json(socket, {"type": "ready", "request_id": "correlation-id"})
            await send_json(
                socket, {"type": "collected", "request_id": "correlation-id"}
            )
            departure = await receive(socket)
            assert departure["type"] == "pagehide" and departure["persisted"] is False
            assert departure["at_ms"] >= starts[-1]["at_ms"]
            await send_json(socket, {"type": "pagehide.done"})
            assert await receive(socket) == {"type": "close"}

        async def send(request):
            targets.append(request)
            return TargetResponse(201, {"x-observed": "yes"}, b"world")

        async with serve(server, "127.0.0.1", 0) as listener:
            port = listener.sockets[0].getsockname()[1]
            async with Nullgate("test-key", base_url=f"http://127.0.0.1:{port}") as ng:
                page = ng.session(
                    user_agent="browser", profile=PROFILE, timezone="Europe/London"
                ).page(URL, HTML)
                for _ in range(2):
                    async with page.threatmetrix(send=send) as tmx:
                        assert tmx.request_id == "correlation-id"
                        await tmx.wait_collected()
                        assert tmx.is_collected
                        await tmx.pagehide()
        assert len(starts) == len(targets) == len(replies) == 2
        document_id = starts[0]["document_id"]
        UUID(document_id)
        expected = {
            "type": "start",
            "profile": PROFILE,
            "session": None,
            "user_agent": "browser",
            "timezone": "Europe/London",
            "url": URL,
            "html": HTML,
            "document_id": document_id,
            "started_at_ms": starts[0]["started_at_ms"],
            "at_ms": starts[0]["at_ms"],
            "tags_url": "https://risk.example/tags.js?org_id=org&session_id=visit",
        }
        assert starts[0] == expected
        assert starts[1] == {
            **expected,
            "session": "tmx-session",
            "at_ms": starts[1]["at_ms"],
        }
        assert targets[0].body == b"hello" and targets[0].credentials == "omit"
        response = replies[0].pop("response")
        assert replies[0] == {"type": "http.result", "id": 1}
        assert response == {
            "status": 201,
            "headers": {"x-observed": "yes"},
            "body": "d29ybGQ=",
            "received_at_ms": response["received_at_ms"],
        }
        assert response["received_at_ms"] >= starts[0]["at_ms"]

    asyncio.run(run())


@pytest.mark.parametrize(
    "message",
    [
        '{"type":"hello","session":"s","request_id":"id","extra":1}',
        '{"type":"hello","session":"s","request_id":"id","request_id":"duplicate"}',
        '{"type":"ready","request_id":"id"}',
        '{"type":"unknown"}',
        '{"type":"http","id":1,"request":{}}',
        b"binary",
    ],
)
def test_malformed_profile_messages_raise_one_error_type(message):
    async def run():
        async def server(socket):
            await receive(socket)
            await socket.send(message)
            await socket.wait_closed()

        async with serve(server, "127.0.0.1", 0) as listener:
            port = listener.sockets[0].getsockname()[1]
            async with Nullgate("test-key", base_url=f"http://127.0.0.1:{port}") as ng:
                page = ng.session(user_agent="browser").page(URL, HTML)
                with pytest.raises(NullgateError):
                    async with page.threatmetrix(
                        send=lambda request: TargetResponse(200, {}, b"")
                    ):
                        pytest.fail("Malformed profile became ready")

    asyncio.run(run())


@pytest.mark.parametrize(
    "code",
    [
        "invalid_key",
        "insufficient_balance",
        "forbidden",
        "invalid_request",
        "session_busy",
        "rate_limited",
        "maintenance",
        "unavailable",
        "internal",
        "upstream",
    ],
)
def test_websocket_errors_preserve_public_envelope_and_redact_key(code):
    async def run():
        async def server(socket):
            await receive(socket)
            await send_json(
                socket,
                {
                    "type": "error",
                    "code": code,
                    "message": "Rejected test-key",
                    "request_id": "support-id",
                },
            )
            await socket.wait_closed()

        async with serve(server, "127.0.0.1", 0) as listener:
            port = listener.sockets[0].getsockname()[1]
            async with Nullgate("test-key", base_url=f"http://127.0.0.1:{port}") as ng:
                with pytest.raises(NullgateError) as error:
                    async with (
                        ng.session(user_agent="browser")
                        .page(URL, HTML)
                        .threatmetrix(send=lambda request: TargetResponse(200, {}, b""))
                    ):
                        pytest.fail("Failed profile became ready")
                assert (
                    error.value.code,
                    error.value.message,
                    error.value.request_id,
                    error.value.status,
                ) == (code, "Rejected [redacted]", "support-id", None)

    asyncio.run(run())


def test_callback_failure_reports_sanitized_http_error():
    async def run():
        messages = []

        async def server(socket):
            await receive(socket)
            await send_json(
                socket, {"type": "hello", "session": "s", "request_id": "id"}
            )
            await send_json(
                socket,
                {
                    "type": "http",
                    "id": 1,
                    "request": {
                        "role": "tags",
                        "url": "https://risk.example/fetch",
                        "method": "GET",
                        "headers": {},
                        "body": None,
                        "credentials": "include",
                    },
                },
            )
            messages.append(await receive(socket))
            await send_json(
                socket,
                {
                    "type": "error",
                    "code": "upstream",
                    "message": "Transport failed",
                    "request_id": "id",
                },
            )
            await socket.wait_closed()

        def send(request):
            raise RuntimeError("secret cookie and password")

        async with serve(server, "127.0.0.1", 0) as listener:
            port = listener.sockets[0].getsockname()[1]
            async with Nullgate("test-key", base_url=f"http://127.0.0.1:{port}") as ng:
                with pytest.raises(NullgateError, match="Transport failed"):
                    async with (
                        ng.session(user_agent="browser")
                        .page(URL, HTML)
                        .threatmetrix(send=send)
                    ):
                        pytest.fail("Failed target transport became ready")
        assert messages == [
            {"type": "http.error", "id": 1, "detail": "Target request failed"}
        ]

    asyncio.run(run())


def test_ice_allocation_lives_until_release_and_is_closed(monkeypatch):
    async def run():
        closed = asyncio.Event()
        release_started = asyncio.Event()

        class Allocation:
            def __init__(self, server, proxy):
                assert proxy == "socks5://127.0.0.1:1080"

            async def open(self):
                return {
                    "candidates": [{"value": "candidate", "elapsed_ms": 1}],
                    "complete_at_ms": 2,
                }

            async def wait_for_release(self, release):
                release_started.set()
                await release.wait()

            async def aclose(self):
                closed.set()

        monkeypatch.setattr("nullgate.profile._TurnAllocation", Allocation)
        observations = []

        async def server(socket):
            await receive(socket)
            await send_json(
                socket, {"type": "hello", "session": "s", "request_id": "id"}
            )
            await send_json(
                socket,
                {
                    "type": "ice",
                    "id": 1,
                    "server": {
                        "host": "turn.example",
                        "port": 3478,
                        "transport": "tcp",
                        "username": "u",
                        "credential": "c",
                    },
                },
            )
            observations.append(await receive(socket))
            await release_started.wait()
            assert not closed.is_set()
            await send_json(socket, {"type": "ice.release", "id": 1})
            await closed.wait()
            await send_json(socket, {"type": "ready", "request_id": "id"})
            assert await receive(socket) == {"type": "close"}

        async with serve(server, "127.0.0.1", 0) as listener:
            port = listener.sockets[0].getsockname()[1]
            async with Nullgate("test-key", base_url=f"http://127.0.0.1:{port}") as ng:
                async with (
                    ng.session(user_agent="browser")
                    .page(URL, HTML)
                    .threatmetrix(
                        send=lambda request: TargetResponse(200, {}, b""),
                        proxy="socks5://127.0.0.1:1080",
                    )
                ):
                    assert closed.is_set()
        assert observations == [
            {
                "type": "ice.result",
                "id": 1,
                "observation": {
                    "candidates": [{"value": "candidate", "elapsed_ms": 1}],
                    "complete_at_ms": 2,
                },
            }
        ]

    asyncio.run(run())


@pytest.mark.parametrize(
    "failures,retry_after,expected",
    [
        (2, "0", 3),
        (3, "0", 3),
        (1, "999", 1),
        (1, "invalid", 1),
    ],
)
def test_handshake_maintenance_retries_respect_startup_timeout(
    failures, retry_after, expected
):
    async def run():
        attempts = []

        def handshake(connection, request):
            attempts.append(request.path)
            if len(attempts) <= failures:
                response = connection.respond(
                    503,
                    json.dumps(
                        {
                            "code": "maintenance",
                            "message": "Wait",
                            "request_id": "id",
                        }
                    ),
                )
                response.headers["Retry-After"] = retry_after
                return response
            return None

        async def server(socket):
            await receive(socket)
            await send_json(
                socket, {"type": "hello", "session": "s", "request_id": "id"}
            )
            await send_json(socket, {"type": "ready", "request_id": "id"})
            assert await receive(socket) == {"type": "close"}

        async with serve(server, "127.0.0.1", 0, process_request=handshake) as listener:
            port = listener.sockets[0].getsockname()[1]
            async with Nullgate(
                "test-key", base_url=f"http://127.0.0.1:{port}", timeout=1
            ) as ng:
                page = ng.session(user_agent="browser").page(URL, HTML)
                context = page.threatmetrix(
                    send=lambda request: TargetResponse(200, {}, b"")
                )
                if failures == 2 and retry_after == "0":
                    async with context as profile:
                        assert profile.request_id == "id"
                else:
                    with pytest.raises(NullgateError) as error:
                        async with context:
                            pytest.fail("Maintenance profile became ready")
                    assert error.value.code == "maintenance"
                    assert error.value.status == 503
        assert len(attempts) == expected

    asyncio.run(run())


def test_sync_profile_keeps_reader_alive_between_pagehide_calls():
    from nullgate import Nullgate as SyncNullgate

    async def run():
        departures = []

        async def server(socket):
            await receive(socket)
            await send_json(
                socket, {"type": "hello", "session": "s", "request_id": "id"}
            )
            await send_json(socket, {"type": "ready", "request_id": "id"})
            for _ in range(2):
                departures.append(await receive(socket))
                await send_json(socket, {"type": "pagehide.done"})
            assert await receive(socket) == {"type": "close"}

        async with serve(server, "127.0.0.1", 0) as listener:
            port = listener.sockets[0].getsockname()[1]

            def work():
                with SyncNullgate(
                    "test-key", base_url=f"http://127.0.0.1:{port}"
                ) as ng:
                    page = ng.session(user_agent="browser").page(URL, HTML)
                    with page.threatmetrix(
                        send=lambda request: TargetResponse(200, {}, b"")
                    ) as profile:
                        profile.pagehide(persisted=True)
                        profile.pagehide(persisted=False)

            await asyncio.to_thread(work)
        assert [message["persisted"] for message in departures] == [True, False]

    asyncio.run(run())


def test_profile_startup_timeout_closes_unready_connection():
    async def run():
        closed = asyncio.Event()

        async def server(socket):
            await receive(socket)
            await socket.wait_closed()
            closed.set()

        async with serve(server, "127.0.0.1", 0) as listener:
            port = listener.sockets[0].getsockname()[1]
            async with Nullgate(
                "test-key", base_url=f"http://127.0.0.1:{port}", timeout=0.02
            ) as ng:
                with pytest.raises(NullgateError) as error:
                    async with (
                        ng.session(user_agent="browser")
                        .page(URL, HTML)
                        .threatmetrix(send=lambda request: TargetResponse(200, {}, b""))
                    ):
                        pytest.fail("Unready profile entered")
                assert error.value.code == "transport_error"
            await asyncio.wait_for(closed.wait(), 1)

    asyncio.run(run())


@pytest.mark.parametrize(
    "html,options,entry",
    [
        (
            HTML,
            {},
            {"tags_url": "https://risk.example/tags.js?org_id=org&session_id=visit"},
        ),
        (
            "<html></html>",
            {"script_url": "https://risk.example/known-tags.js"},
            {"tags_url": "https://risk.example/known-tags.js"},
        ),
        *[
            (
                HTML + '<input id="email"><input id="credential" type="password">',
                observations,
                {
                    "tags_url": "https://risk.example/tags.js?org_id=org&session_id=visit",
                    **expected,
                },
            )
            for observations, expected in (
                ({"inputs": None, "actions": None}, {}),
                ({"inputs": [], "actions": []}, {"inputs": [], "actions": []}),
                (
                    {
                        "inputs": [
                            {"attributes": {"id": "credential"}, "value": EMPTY_VALUE}
                        ]
                    },
                    {
                        "inputs": [
                            {"attributes": {"id": "credential"}, "value": EMPTY_VALUE}
                        ]
                    },
                ),
                (
                    {"inputs": [{"id": "email", "value": ""}]},
                    {
                        "inputs": [
                            {
                                "attributes": {"id": "email"},
                                "value": {
                                    **EMPTY_VALUE,
                                    "counts": [0, 0, 0, 0],
                                    "hash31": 0,
                                    "trimmed_hash31": 0,
                                    "trimmed_length": 0,
                                },
                            }
                        ]
                    },
                ),
                (
                    {"actions": [{"type": "click", "x": 0, "y": 0, "button": 0}]},
                    {"actions": [{"type": "click", "x": 0, "y": 0, "button": 0}]},
                ),
            )
        ],
        *[
            (
                HTML
                + '<script src="https://other.example/tags.js?org_id=o&session_id=s"></script>',
                {"collector": collector},
                {"collector": collector},
            )
            for collector in (
                {
                    "url": "https://dfme.kleinanzeigen.de/observed.js?q=1",
                    "org_id": "181rzcrc",
                    "session_id": "visit",
                },
                {
                    "url": "http://collector.example:0/collect.js",
                    "org_id": "org",
                    "session_id": "visit",
                },
                {
                    "url": "https://collector.example:",
                    "org_id": " ",
                    "session_id": "\r\n",
                },
                {
                    "url": "https://[::1]:8443/collect.js",
                    "org_id": "org",
                    "session_id": "visit",
                },
            )
        ],
    ],
)
@pytest.mark.parametrize("sync", [False, True])
def test_profile_entry_selection_sends_exactly_one_tags_url_or_collector(
    html, options, entry, sync
):
    async def run():
        starts = []

        async def server(socket):
            starts.append(await receive(socket))
            await send_json(
                socket, {"type": "hello", "session": "s", "request_id": "id"}
            )
            await send_json(socket, {"type": "ready", "request_id": "id"})
            assert await receive(socket) == {"type": "close"}

        async with serve(server, "127.0.0.1", 0) as listener:
            port = listener.sockets[0].getsockname()[1]
            base_url = f"http://127.0.0.1:{port}"
            if sync:

                def work():
                    from nullgate import Nullgate as SyncNullgate

                    with SyncNullgate("test-key", base_url=base_url) as ng:
                        page = ng.session(user_agent="browser", profile=PROFILE).page(
                            URL, html, document_id=PROFILE, started_at_ms=1000
                        )
                        with page.threatmetrix(
                            send=lambda request: TargetResponse(200, {}, b""), **options
                        ):
                            pass

                await asyncio.to_thread(work)
            else:
                async with Nullgate("test-key", base_url=base_url) as ng:
                    page = ng.session(user_agent="browser", profile=PROFILE).page(
                        URL, html, document_id=PROFILE, started_at_ms=1000
                    )
                    async with page.threatmetrix(
                        send=lambda request: TargetResponse(200, {}, b""), **options
                    ):
                        pass
        assert len(starts) == 1
        start = starts[0]
        UUID(start["document_id"])
        assert start == {
            "type": "start",
            "profile": PROFILE,
            "session": None,
            "user_agent": "browser",
            "url": URL,
            "html": html,
            "document_id": PROFILE,
            "started_at_ms": 1000,
            "at_ms": start["at_ms"],
            **entry,
        }
        assert start["at_ms"] >= start["started_at_ms"]

    asyncio.run(run())


@pytest.mark.parametrize(
    "options,code",
    [
        ({}, "protection_not_found"),
        *[
            ({"collector": collector}, "invalid_request")
            for collector in (
                {},
                [],
                "",
                {"url": "https://collector.example"},
                {"url": "https://collector.example", "org_id": "org"},
                {"url": "https://collector.example", "session_id": "visit"},
                {"org_id": "org", "session_id": "visit"},
                *[
                    {
                        **{
                            "url": "https://collector.example",
                            "org_id": "org",
                            "session_id": "visit",
                        },
                        key: value,
                    }
                    for key, value in (
                        ("org_id", ""),
                        ("org_id", None),
                        ("org_id", 1),
                        ("session_id", ""),
                        ("session_id", None),
                        ("session_id", False),
                        ("extra", "not allowed"),
                        ("url", None),
                        ("url", 123),
                        *[
                            ("url", url)
                            for url in (
                                "/relative.js",
                                "ftp://collector.example",
                                "https://",
                                "https://user:pass@collector.example",
                                "https://@collector.example",
                                "https://collector.example/#",
                                "https://collector.example/#fragment",
                                "https://collector.example/with space",
                                "https://collector.example/with\ttab",
                                "https://collector.example/with\\backslash",
                                "https://collector.example:abc",
                                "https://collector.example:-1",
                                "https://collector.example:65536",
                            )
                        ],
                    )
                ],
            )
        ],
        *[
            (
                {
                    "script_url": script,
                    "collector": {
                        "url": "https://collector.example",
                        "org_id": "org",
                        "session_id": "visit",
                    },
                },
                "invalid_request",
            )
            for script in ("", "https://risk.example/tags.js")
        ],
    ],
)
def test_invalid_profile_collector_is_rejected_before_connecting(
    monkeypatch, options, code
):
    async def unexpected_connect(*args, **kwargs):
        pytest.fail("Invalid collector reached the WebSocket transport")

    monkeypatch.setattr("nullgate.profile.connect", unexpected_connect)

    async def run():
        async with Nullgate("test-key") as ng:
            page = ng.session(user_agent="browser").page(URL, "<html></html>")
            with pytest.raises(NullgateError) as error:
                async with page.threatmetrix(
                    send=lambda request: TargetResponse(200, {}, b""), **options
                ):
                    pytest.fail("Invalid collector entered a profile")
            assert error.value.code == code

    asyncio.run(run())


@pytest.mark.parametrize(
    "options,code",
    [
        ({"inputs": {"credential": "private"}}, "invalid_inputs"),
        (
            {"inputs": [{"attributes": {"id": "credential"}, "value": "private"}]},
            "invalid_inputs",
        ),
        ({"actions": [{"type": "click", "value": "private"}]}, "invalid_actions"),
        ({"actions": [{"type": "input", "value": ""}]}, "invalid_actions"),
    ],
)
def test_invalid_profile_observations_fail_before_opening_the_paid_socket(
    monkeypatch, options, code
):
    async def unexpected_connect(*args, **kwargs):
        pytest.fail("Invalid observations opened a profile socket")

    monkeypatch.setattr("nullgate.profile.connect", unexpected_connect)

    async def run():
        async with Nullgate("test-key") as ng:
            page = ng.session(user_agent="browser").page(
                URL, HTML + '<input id="credential" type="password">'
            )
            with pytest.raises(NullgateError) as error:
                async with page.threatmetrix(
                    send=lambda request: TargetResponse(200, {}, b""), **options
                ):
                    pytest.fail("Invalid observations became ready")
            assert error.value.code == code

    asyncio.run(run())
