import asyncio

import httpx
import pytest

from nullgate import NullgateAPIError, NullgateClient, NullgateClientAsync, Page
from nullgate.akamai import Sensor, SensorParams
from nullgate.amazon import FwcimParams

IDENTITY = "a07aad50-f262-40b1-b187-11532c054bc0"
PAGE = Page("https://example.com", "<form></form>")
PARAMS = FwcimParams(PAGE, {"navigationStart": PAGE.started_at_ms})
DETAIL = "Service updating; retry after a short delay"


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("operation", ["fwcim", "akamai"])
def test_only_prework_maintenance_retries_with_original_state(
    asynchronous: bool, operation: str
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) < 3:
            return httpx.Response(
                503,
                headers={
                    "Retry-After": "0",
                    "X-Nullgate-Maintenance": "1",
                    "X-State-ID": "must-ignore",
                },
                json={"detail": DETAIL},
            )
        return httpx.Response(
            200,
            headers={"X-Request-ID": "id", "X-State-ID": "accepted"},
            json={
                "metadata1": "metadata",
                "sensor_data": "sensor",
                "send_at": 0,
                "headers": {},
            },
        )

    sensor = SensorParams(Sensor(PAGE, "https://example.com/opaque"), "source")
    transport = httpx.MockTransport(handler)
    if asynchronous:

        async def run() -> None:
            async with NullgateClientAsync("key", transport=transport) as client:
                async with client.open(identity=IDENTITY, user_agent="UA") as session:
                    if operation == "fwcim":
                        await session.fwcim(PARAMS)
                    else:
                        await session.solve(sensor)

        asyncio.run(run())
    else:
        with NullgateClient("key", transport=transport) as client:
            with client.open(identity=IDENTITY, user_agent="UA") as session:
                if operation == "fwcim":
                    session.fwcim(PARAMS)
                else:
                    session.solve(sensor)
    assert len(requests) == 3
    assert len({request.headers["X-State-ID"] for request in requests}) == 1
    assert len({request.content for request in requests}) == 1


@pytest.mark.parametrize(
    "status,detail,retry_after,marker,expected",
    [
        (503, DETAIL, "0", "1", 3),
        (503, "unavailable", "0", "1", 3),
        (503, DETAIL, "0", None, 1),
        (503, DETAIL, "0", "true", 1),
        (503, DETAIL, "0", "1, 1", 1),
        (502, DETAIL, "0", "1", 1),
        (503, DETAIL, None, "1", 1),
        (503, DETAIL, "NaN", "1", 1),
        (503, DETAIL, "6", "1", 1),
        (503, DETAIL, "-1", "1", 1),
        (503, DETAIL, "not-seconds", "1", 1),
    ],
)
@pytest.mark.parametrize("asynchronous", [False, True])
def test_retry_boundaries_and_exhaustion_keep_state(
    status: int,
    detail: str,
    retry_after: str | None,
    marker: str | None,
    expected: int,
    asynchronous: bool,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        headers = {}
        if retry_after is not None:
            headers["Retry-After"] = retry_after
        if marker is not None:
            headers["X-Nullgate-Maintenance"] = marker
        return httpx.Response(
            status,
            headers=headers,
            json={"detail": detail, "error": {"code": "SERVICE_UPDATING"}},
        )

    transport = httpx.MockTransport(handler)
    if asynchronous:

        async def run() -> None:
            async with NullgateClientAsync("key", transport=transport) as client:
                async with client.open(identity=IDENTITY, user_agent="UA") as session:
                    before = session._amazon_state_id
                    with pytest.raises(NullgateAPIError):
                        await session.fwcim(PARAMS)
                    assert session._amazon_state_id == before

        asyncio.run(run())
    else:
        with NullgateClient("key", transport=transport) as client:
            with client.open(identity=IDENTITY, user_agent="UA") as session:
                before = session._amazon_state_id
                with pytest.raises(NullgateAPIError):
                    session.fwcim(PARAMS)
                assert session._amazon_state_id == before
    assert len(requests) == expected


def test_async_cancellation_during_maintenance_stops_before_retry() -> None:
    async def run() -> None:
        requests: list[httpx.Request] = []
        entered = asyncio.Event()

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            entered.set()
            return httpx.Response(
                503,
                headers={"Retry-After": "5", "X-Nullgate-Maintenance": "1"},
                json={"detail": DETAIL},
            )

        async with NullgateClientAsync(
            "key", transport=httpx.MockTransport(handler)
        ) as client:
            async with client.open(identity=IDENTITY, user_agent="UA") as session:
                task = asyncio.create_task(session.fwcim(PARAMS))
                await entered.wait()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
        assert len(requests) == 1

    asyncio.run(run())


def test_closed_client_stops_maintenance_retry() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        client.close()
        return httpx.Response(
            503,
            headers={"Retry-After": "0", "X-Nullgate-Maintenance": "1"},
            json={"detail": DETAIL},
        )

    with NullgateClient("key", transport=httpx.MockTransport(handler)) as client:
        with client.open(identity=IDENTITY, user_agent="UA") as session:
            with pytest.raises(RuntimeError, match="closed"):
                session.fwcim(PARAMS)
    assert len(requests) == 1


def test_transport_failure_is_not_retried() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise httpx.ReadError("transport failed", request=request)

    with NullgateClient("key", transport=httpx.MockTransport(handler)) as client:
        with client.open(identity=IDENTITY, user_agent="UA") as session:
            with pytest.raises(httpx.ReadError):
                session.fwcim(PARAMS)
    assert len(requests) == 1


class UnreadMaintenanceBody(httpx.SyncByteStream, httpx.AsyncByteStream):
    def __iter__(self):
        raise AssertionError("Maintenance classification must not read the body")
        yield b""

    async def __aiter__(self):
        raise AssertionError("Maintenance classification must not read the body")
        yield b""


@pytest.mark.parametrize("asynchronous", [False, True])
def test_maintenance_does_not_read_body_even_on_exhaustion(asynchronous: bool) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            503,
            headers={"Retry-After": "0", "X-Nullgate-Maintenance": "1"},
            stream=UnreadMaintenanceBody(),
        )

    if asynchronous:

        async def run() -> None:
            async with NullgateClientAsync(
                "key", transport=httpx.MockTransport(handler)
            ) as client:
                async with client.open(identity=IDENTITY, user_agent="UA") as session:
                    with pytest.raises(NullgateAPIError):
                        await session.fwcim(PARAMS)

        asyncio.run(run())
    else:
        with NullgateClient("key", transport=httpx.MockTransport(handler)) as client:
            with client.open(identity=IDENTITY, user_agent="UA") as session:
                with pytest.raises(NullgateAPIError):
                    session.fwcim(PARAMS)
    assert len(requests) == 3


class TruncatedBody(httpx.SyncByteStream, httpx.AsyncByteStream):
    def __iter__(self):
        raise httpx.ReadError("truncated response")
        yield b""

    async def __aiter__(self):
        raise httpx.ReadError("truncated response")
        yield b""


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("operation", ["fwcim", "akamai"])
def test_unmarked_503_retains_rotated_state_before_body_read(
    asynchronous: bool, operation: str
) -> None:
    requests: list[httpx.Request] = []
    sensor = SensorParams(Sensor(PAGE, "https://example.com/opaque"), "source")

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                503,
                headers={"Retry-After": "0", "X-State-ID": "rotated"},
                stream=TruncatedBody(),
            )
        return httpx.Response(
            200,
            headers={"X-Request-ID": "id"},
            json={
                "metadata1": "metadata",
                "sensor_data": "sensor",
                "send_at": 0,
                "headers": {},
            },
        )

    if asynchronous:

        async def run() -> None:
            async with NullgateClientAsync(
                "key", transport=httpx.MockTransport(handler)
            ) as client:
                async with client.open(identity=IDENTITY, user_agent="UA") as session:
                    with pytest.raises(httpx.ReadError):
                        if operation == "fwcim":
                            await session.fwcim(PARAMS)
                        else:
                            await session.solve(sensor)
                    if operation == "fwcim":
                        await session.fwcim(PARAMS)
                    else:
                        await session.solve(sensor)

        asyncio.run(run())
    else:
        with NullgateClient("key", transport=httpx.MockTransport(handler)) as client:
            with client.open(identity=IDENTITY, user_agent="UA") as session:
                with pytest.raises(httpx.ReadError):
                    if operation == "fwcim":
                        session.fwcim(PARAMS)
                    else:
                        session.solve(sensor)
                if operation == "fwcim":
                    session.fwcim(PARAMS)
                else:
                    session.solve(sensor)
    assert len(requests) == 2
    assert requests[1].headers["X-State-ID"] == "rotated"
