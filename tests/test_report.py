import asyncio
import json
from uuid import UUID

import httpx
import pytest

from nullgate import NullgateClient, NullgateClientAsync, Page
from nullgate.akamai import Sensor, SensorParams

REQUEST_ID = "0123456789abcdef0123456789abcdef"
PARAMS = SensorParams(
    Sensor(
        Page("https://target.example/", "<html></html>"),
        "https://target.example/sensor",
    ),
    "source",
)


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_solution_reports_only_its_issued_id_without_secrets_or_session_headers(
    asynchronous: bool,
) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/report":
            assert request.url.host == "analytics.example"
            assert request.method == "POST"
            assert json.loads(request.content) == {"request_id": REQUEST_ID}
            assert "Authorization" not in request.headers
            assert "X-State-ID" not in request.headers
            assert "Cookie" not in request.headers
            assert "profile-UA" not in str(request.headers)
            assert "account-secret" not in str(request.headers)
            assert all(
                0 < value <= 5 for value in request.extensions["timeout"].values()
            )
            # Delivery succeeds even when the body cannot describe archive acceptance.
            return httpx.Response(200, text="not an archive receipt")
        assert request.headers["Authorization"] == "Bearer account-secret"
        return httpx.Response(
            200,
            json={"sensor_data": "sensor", "headers": {}, "send_at": 0},
            headers={
                "X-State-ID": "private-state",
                "X-Request-ID": REQUEST_ID,
                "Set-Cookie": (
                    "private_api_cookie=must-not-leak; Domain=.example; Path=/"
                ),
            },
        )

    def run_sync() -> None:
        with NullgateClient(
            "account-secret",
            base_url="https://api.example",
            analytics_url="https://analytics.example",
            timeout=30,
            transport=httpx.MockTransport(handle),
        ) as client:
            with client.open(identity=UUID(int=1), user_agent="profile-UA") as session:
                solution = session.solve(PARAMS)
            assert solution.report() is True
            assert client.report(REQUEST_ID) is True

    async def run_async() -> None:
        async with NullgateClientAsync(
            "account-secret",
            base_url="https://api.example",
            analytics_url="https://analytics.example",
            timeout=30,
            transport=httpx.MockTransport(handle),
        ) as client:
            async with client.open(
                identity=UUID(int=1), user_agent="profile-UA"
            ) as session:
                solution = await session.solve(PARAMS)
            assert await solution.report() is True
            assert await client.report(REQUEST_ID) is True

    asyncio.run(run_async()) if asynchronous else run_sync()
    assert [request.url.path == "/report" for request in requests] == [
        False,
        True,
        True,
    ]


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    "outcome", [204, 302, 400, 503, "timeout", "network", "protocol"]
)
def test_report_is_best_effort_once_without_following_redirects(
    asynchronous: bool, outcome: int | str
) -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        match outcome:
            case "timeout":
                raise httpx.ReadTimeout("offline", request=request)
            case "network":
                raise httpx.ConnectError("offline", request=request)
            case "protocol":
                raise httpx.RemoteProtocolError("disconnected", request=request)
            case int():
                return httpx.Response(
                    outcome, headers={"Location": "https://other.example/redirect"}
                )
        raise AssertionError("unexpected scenario")

    def run_sync() -> bool:
        with NullgateClient(
            "secret",
            analytics_url="https://analytics.example",
            transport=httpx.MockTransport(handle),
        ) as client:
            return client.report(REQUEST_ID)

    async def run_async() -> bool:
        async with NullgateClientAsync(
            "secret",
            analytics_url="https://analytics.example",
            transport=httpx.MockTransport(handle),
        ) as client:
            return await client.report(REQUEST_ID)

    result = asyncio.run(run_async()) if asynchronous else run_sync()
    assert result is (outcome == 204)
    assert len(seen) == 1 and seen[0].url.host == "analytics.example"


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    "failure", [ValueError, httpx.LocalProtocolError, httpx.UnsupportedProtocol]
)
def test_report_does_not_hide_programming_errors_or_closed_client_use(
    asynchronous: bool,
    failure: type[Exception],
) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise failure("programming failure")

    def run_sync() -> None:
        with NullgateClient("secret", transport=httpx.MockTransport(handle)) as client:
            with pytest.raises(failure):
                client.report(REQUEST_ID)
        with pytest.raises(RuntimeError):
            client.report(REQUEST_ID)

    async def run_async() -> None:
        async with NullgateClientAsync(
            "secret", transport=httpx.MockTransport(handle)
        ) as client:
            with pytest.raises(failure):
                await client.report(REQUEST_ID)
        with pytest.raises(RuntimeError):
            await client.report(REQUEST_ID)

    asyncio.run(run_async()) if asynchronous else run_sync()


def test_async_report_cancellation_propagates() -> None:
    async def scenario() -> None:
        async def handle(request: httpx.Request) -> httpx.Response:
            raise asyncio.CancelledError

        async with NullgateClientAsync(
            "secret", transport=httpx.MockTransport(handle)
        ) as client:
            with pytest.raises(asyncio.CancelledError):
                await client.report(REQUEST_ID)

    asyncio.run(scenario())
