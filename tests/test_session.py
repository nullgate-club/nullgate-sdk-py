import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock
from uuid import UUID

import httpx
import pytest

from nullgate import NullgateClient, NullgateClientAsync, Page
from nullgate.akamai import Sensor, SensorParams

IDENTITY_A = UUID(int=1)
IDENTITY_B = UUID(int=2)
SENSOR = Sensor(
    Page("https://target.example/document", "<html></html>"),
    "https://target.example/collector",
)
PARAMS = SensorParams(SENSOR, "caller-fetched-source")


class ClosingTransport(httpx.MockTransport):
    closes = 0

    def close(self) -> None:
        self.closes += 1

    async def aclose(self) -> None:
        self.closes += 1


def generated(request: httpx.Request, state: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "sensor_data": "generated-sensor",
            "headers": {"Content-Type": "application/json"},
            "send_at": 0.0,
        },
        headers={"X-State-ID": state, "X-Request-ID": "1" * 32},
    )


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_sessions_keep_identity_headers_timezone_and_lifetime_separate(
    asynchronous: bool,
) -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return generated(request, f"{request.headers['User-Agent']}-state")

    transport = ClosingTransport(handle)

    def run_sync() -> None:
        client = NullgateClient(
            "shared-secret", base_url="https://api.example", transport=transport
        )
        with client:
            first = client.open(
                identity=IDENTITY_A, user_agent="UA-A", timezone="Europe/Paris"
            )
            with client.open(identity=str(IDENTITY_B), user_agent="UA-B") as second:
                with first:
                    first.solve(PARAMS)
                    second.solve(PARAMS)
                    first.solve(PARAMS)
                assert first.is_closed and not second.is_closed and not client.is_closed
                with pytest.raises(RuntimeError):
                    first.solve(PARAMS)
                second.solve(PARAMS)
            assert second.is_closed and transport.closes == 0
            with client.open(identity=IDENTITY_A, user_agent="UA-A") as fresh:
                fresh.solve(PARAMS)
        assert client.is_closed and transport.closes == 1
        client.close()
        assert transport.closes == 1
        with pytest.raises(RuntimeError):
            client.open(identity=IDENTITY_A, user_agent="UA-A")

    async def run_async() -> None:
        client = NullgateClientAsync(
            "shared-secret", base_url="https://api.example", transport=transport
        )
        async with client:
            first = client.open(
                identity=IDENTITY_A, user_agent="UA-A", timezone="Europe/Paris"
            )
            async with client.open(
                identity=str(IDENTITY_B), user_agent="UA-B"
            ) as second:
                async with first:
                    await first.solve(PARAMS)
                    await second.solve(PARAMS)
                    await first.solve(PARAMS)
                assert first.is_closed and not second.is_closed and not client.is_closed
                with pytest.raises(RuntimeError):
                    await first.solve(PARAMS)
                await second.solve(PARAMS)
            assert second.is_closed and transport.closes == 0
            async with client.open(identity=IDENTITY_A, user_agent="UA-A") as fresh:
                await fresh.solve(PARAMS)
        assert client.is_closed and transport.closes == 1
        await client.aclose()
        assert transport.closes == 1
        with pytest.raises(RuntimeError):
            client.open(identity=IDENTITY_A, user_agent="UA-A")

    asyncio.run(run_async()) if asynchronous else run_sync()
    assert [request.headers.get("X-State-ID") for request in seen] == [
        None,
        None,
        "UA-A-state",
        "UA-B-state",
        None,
    ]
    assert [request.headers["User-Agent"] for request in seen] == [
        "UA-A",
        "UA-B",
        "UA-A",
        "UA-B",
        "UA-A",
    ]
    assert [request.url.path for request in seen] == [
        f"/v1/{identity}/generate"
        for identity in (IDENTITY_A, IDENTITY_B, IDENTITY_A, IDENTITY_B, IDENTITY_A)
    ]
    assert [json.loads(request.content).get("timezone") for request in seen] == [
        "Europe/Paris",
        None,
        "Europe/Paris",
        None,
        None,
    ]


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_client_owns_transport_while_sessions_close_independently(
    asynchronous: bool,
) -> None:
    transport = ClosingTransport(lambda request: generated(request, "state"))

    def run_sync() -> None:
        client = NullgateClient("secret", transport=transport)
        session = client.open(identity=IDENTITY_A, user_agent="UA")
        client.close()
        assert session.is_closed
        with pytest.raises(RuntimeError):
            session.solve(PARAMS)
        session.close()

    async def run_async() -> None:
        client = NullgateClientAsync("secret", transport=transport)
        session = client.open(identity=IDENTITY_A, user_agent="UA")
        await client.aclose()
        assert session.is_closed
        with pytest.raises(RuntimeError):
            await session.solve(PARAMS)
        await session.aclose()

    asyncio.run(run_async()) if asynchronous else run_sync()
    assert transport.closes == 1


def test_sync_sessions_overlap_independently_and_serialize_their_own_requests() -> None:
    barrier = Barrier(2, timeout=5)
    record_lock = Lock()
    states: dict[str, list[str | None]] = {"UA-A": [], "UA-B": []}
    active: set[str] = set()
    overlap: list[bool] = []

    def handle(request: httpx.Request) -> httpx.Response:
        user_agent = request.headers["User-Agent"]
        with record_lock:
            assert user_agent not in active
            active.add(user_agent)
            states[user_agent].append(request.headers.get("X-State-ID"))
            count = len(states[user_agent])
        if count == 1:
            barrier.wait()
            with record_lock:
                overlap.append(len(active) == 2)
        with record_lock:
            active.remove(user_agent)
        return generated(request, f"{user_agent}-{count}")

    with NullgateClient("secret", transport=httpx.MockTransport(handle)) as client:
        with (
            client.open(identity=IDENTITY_A, user_agent="UA-A") as first,
            client.open(identity=IDENTITY_B, user_agent="UA-B") as second,
        ):
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(first.solve, PARAMS),
                    executor.submit(first.solve, PARAMS),
                    executor.submit(second.solve, PARAMS),
                ]
                for future in futures:
                    future.result(timeout=10)
    assert any(overlap)
    assert states == {"UA-A": [None, "UA-A-1"], "UA-B": [None]}


def test_async_sessions_overlap_independently_and_serialize_their_own_requests() -> (
    None
):
    async def scenario() -> None:
        active: set[str] = set()
        overlap: list[bool] = []
        states: dict[str, list[str | None]] = {"UA-A": [], "UA-B": []}

        async def handle(request: httpx.Request) -> httpx.Response:
            user_agent = request.headers["User-Agent"]
            assert user_agent not in active
            active.add(user_agent)
            states[user_agent].append(request.headers.get("X-State-ID"))
            count = len(states[user_agent])
            await asyncio.sleep(0)
            overlap.append(len(active) == 2)
            active.remove(user_agent)
            return generated(request, f"{user_agent}-{count}")

        async with NullgateClientAsync(
            "secret", transport=httpx.MockTransport(handle)
        ) as client:
            async with (
                client.open(identity=IDENTITY_A, user_agent="UA-A") as first,
                client.open(identity=IDENTITY_B, user_agent="UA-B") as second,
            ):
                await asyncio.gather(
                    first.solve(PARAMS), first.solve(PARAMS), second.solve(PARAMS)
                )
        assert any(overlap)
        assert states == {"UA-A": [None, "UA-A-1"], "UA-B": [None]}

    asyncio.run(scenario())


def test_explicit_target_transport_and_cookie_jar_stay_caller_owned() -> None:
    target_requests: list[httpx.Request] = []

    def target_handle(request: httpx.Request) -> httpx.Response:
        target_requests.append(request)
        assert (
            "Authorization" not in request.headers
            and "X-State-ID" not in request.headers
        )
        assert request.headers["Cookie"] == "target=caller-owned"
        if request.method == "GET":
            return httpx.Response(200, text="caller-fetched-source")
        assert json.loads(request.content) == {"sensor_data": "generated-sensor"}
        return httpx.Response(200, headers={"Set-Cookie": "accepted=caller-observed"})

    with httpx.Client(
        cookies={"target": "caller-owned"}, transport=httpx.MockTransport(target_handle)
    ) as target:
        source = target.get(SENSOR.script_url)
        with NullgateClient(
            "secret",
            transport=httpx.MockTransport(lambda request: generated(request, "state")),
        ) as client:
            with client.open(identity=IDENTITY_A, user_agent="UA") as session:
                solution = session.solve(SensorParams(SENSOR, source.text))
            target.request(
                solution.method,
                solution.url,
                headers=solution.headers,
                content=solution.body,
            )
        assert not target.is_closed and target.cookies["accepted"] == "caller-observed"
    assert [request.method for request in target_requests] == ["GET", "POST"]


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_invalid_identity_is_rejected_before_request_allocation(
    asynchronous: bool,
) -> None:
    def run_sync() -> None:
        with NullgateClient("secret") as client:
            with pytest.raises(ValueError):
                client.open(identity="not-a-uuid", user_agent="UA")

    async def run_async() -> None:
        async with NullgateClientAsync("secret") as client:
            with pytest.raises(ValueError):
                client.open(identity="not-a-uuid", user_agent="UA")

    asyncio.run(run_async()) if asynchronous else run_sync()
