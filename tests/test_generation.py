import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from hashlib import sha256
from typing import cast

import httpx
import pytest

from nullgate import (
    NullgateAPIError,
    NullgateClient,
    NullgateClientAsync,
    Page,
    Solution,
    SolutionAsync,
)
from nullgate.akamai import (
    Pixel,
    PixelParams,
    Sbsd,
    SbsdParams,
    Sensor,
    SensorParams,
)

IDENTITY = "a07aad50-f262-40b1-b187-11532c054bc0"
PAGE = Page("https://target.example/login", '<html><input name="page-only"></html>')
PIXEL = Pixel(PAGE, "https://target.example/akam/13/abc?x=1", "001234")
SENSOR = Sensor(PAGE, "https://target.example/opaque/sensor?x=%2f")
SBSD = Sbsd(
    PAGE,
    "https://target.example/opaque/sbsd?v=11111111-2222-4333-8444-555555555555&t=",
)


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_generation_yields_ready_posts_and_private_input_summaries(
    asynchronous: bool,
) -> None:
    requests: list[httpx.Request] = []
    results: list[Solution | SolutionAsync] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        kind = request.url.params["type"]
        data = {
            "body": '{"body":"sbsd-payload"}' if kind == "sbsd" else "pixel=encoded%2B",
            "url": "https://target.example/returned-target?original=1",
            "send_at": 1234.5,
            "headers": {
                "Content-Type": "application/json"
                if kind != "pixel"
                else "application/x-www-form-urlencoded"
            },
        }
        if kind == "akamai":
            data = {
                "sensor_data": 'sensor"payload',
                "send_at": 1234.5,
                "headers": {"Content-Type": "application/json"},
            }
        return httpx.Response(
            200,
            headers={
                "X-State-ID": "document-state",
                "X-Request-ID": f"{len(requests):032x}",
            },
            json=data,
        )

    transport = httpx.MockTransport(handle)
    actions: list[dict[str, object]] = [
        {"type": "mousemove", "x": 4, "y": 8},
        {
            "type": "input",
            "target": 0,
            "value": {
                "length": 4,
                "hash": sha256(bytes.fromhex("73003dd811dd2600")).hexdigest(),
                "counts": [4, 3, 1, 0],
            },
        },
        {
            "type": "change",
            "target": 0,
            "value": {"length": 0, "hash": sha256(b"").hexdigest()},
        },
        {"type": "input", "target": 1, "value": None},
        {"type": "change", "target": 1},
    ]
    params = [
        PixelParams(PIXEL, "pixel-source"),
        SensorParams(
            SENSOR,
            "sensor-source",
            cookies={"bm_sz": "target-cookie"},
            inputs=[{"name": "password", "type": "password", "value": "s🔑&"}],
            actions=actions,
        ),
        SbsdParams(SBSD, "sbsd-source", cookies={"sbsd_o": "target-cookie"}),
        SensorParams(SENSOR, "sensor-source"),
        SensorParams(SENSOR, "sensor-source", inputs=[], actions=[]),
    ]

    def run_sync() -> None:
        with NullgateClient(
            "account-secret", base_url="https://api.example", transport=transport
        ) as client:
            with client.open(
                identity=IDENTITY, user_agent="caller-UA", timezone="Europe/Paris"
            ) as session:
                results.extend(session.solve(value) for value in params)

    async def run_async() -> None:
        async with NullgateClientAsync(
            "account-secret", base_url="https://api.example", transport=transport
        ) as client:
            async with client.open(
                identity=IDENTITY, user_agent="caller-UA", timezone="Europe/Paris"
            ) as session:
                for value in params:
                    results.append(await session.solve(value))

    asyncio.run(run_async()) if asynchronous else run_sync()

    assert requests[0].headers["X-State-ID"]
    assert all(
        request.headers["X-State-ID"] == "document-state" for request in requests[1:]
    )
    assert [request.url.params["type"] for request in requests] == [
        "pixel",
        "akamai",
        "sbsd",
        "akamai",
        "akamai",
    ]
    assert all(request.url.path == f"/v1/{IDENTITY}/generate" for request in requests)
    pixel, sensor, sbsd, unchanged, cleared = [
        json.loads(request.content) for request in requests
    ]
    assert pixel["challenge"] == "001234" and "cookies" not in pixel
    assert sensor["cookies"] == {"bm_sz": "target-cookie"}
    assert sensor["actions"] == actions
    assert "challenge" not in sensor and "challenge" not in sbsd
    assert sbsd["cookies"] == {"sbsd_o": "target-cookie"}
    assert "inputs" not in sbsd and "actions" not in sbsd
    assert (
        unchanged["cookies"] == {}
        and "inputs" not in unchanged
        and "actions" not in unchanged
    )
    assert cleared["inputs"] == [] and cleared["actions"] == []
    assert sensor["script"]["source"] == SENSOR.script_url
    assert sbsd["script"]["source"] == SBSD.script_url
    for request in requests:
        payload = json.loads(request.content)
        assert request.headers["Authorization"] == "Bearer account-secret"
        assert request.headers["User-Agent"] == "caller-UA"
        assert payload["timezone"] == "Europe/Paris"
        assert "s🔑&" not in request.content.decode()
        assert "user_agent" not in payload and "identity" not in payload
    assert all(
        result.method == "POST" and result.send_at == 1234.5 for result in results
    )
    assert [result.request_id for result in results] == [
        f"{index:032x}" for index in range(1, 6)
    ]
    assert (
        results[0].url
        == results[2].url
        == "https://target.example/returned-target?original=1"
    )
    assert results[0].body == "pixel=encoded%2B"
    assert results[2].body == '{"body":"sbsd-payload"}'
    assert results[1].url == SENSOR.script_url
    assert json.loads(results[1].body) == {"sensor_data": 'sensor"payload'}


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_api_error_preserves_status_detail_request_id_and_state_rotation(
    asynchronous: bool,
) -> None:
    states: list[str | None] = []
    errors = [
        httpx.Response(
            401,
            json={"detail": "invalid credential"},
            headers={"X-State-ID": "error-state", "X-Request-ID": "1" * 32},
        ),
        httpx.Response(
            422,
            json={"detail": [{"loc": ["body", "script"], "msg": "invalid source"}]},
            headers={"X-Request-ID": "2" * 32},
        ),
        httpx.Response(
            503,
            text="upstream unavailable",
            headers={"X-State-ID": "rotated-state", "X-Request-ID": "3" * 32},
        ),
    ]
    expected_details: list[object] = [
        "invalid credential",
        [{"loc": ["body", "script"], "msg": "invalid source"}],
        "upstream unavailable",
    ]
    responses = iter(errors)

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.example"
        states.append(request.headers.get("X-State-ID"))
        return next(responses)

    def check_error(error: NullgateAPIError, index: int) -> None:
        assert isinstance(error, httpx.HTTPStatusError)
        assert error.status_code == errors[index].status_code
        assert error.detail == expected_details[index]
        assert error.request_id == str(index + 1) * 32
        assert error.response is errors[index]

    def run_sync() -> None:
        with NullgateClient(
            "secret",
            base_url="https://api.example",
            transport=httpx.MockTransport(handle),
        ) as client:
            with client.open(identity=IDENTITY, user_agent="UA") as session:
                for index in range(3):
                    with pytest.raises(NullgateAPIError) as caught:
                        session.solve(PixelParams(PIXEL, "source"))
                    check_error(caught.value, index)

    async def run_async() -> None:
        async with NullgateClientAsync(
            "secret",
            base_url="https://api.example",
            transport=httpx.MockTransport(handle),
        ) as client:
            async with client.open(identity=IDENTITY, user_agent="UA") as session:
                for index in range(3):
                    with pytest.raises(NullgateAPIError) as caught:
                        await session.solve(PixelParams(PIXEL, "source"))
                    check_error(caught.value, index)

    asyncio.run(run_async()) if asynchronous else run_sync()
    assert states[0]
    assert states[1:] == ["error-state", "error-state"]


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    "failure_type",
    [httpx.RemoteProtocolError, httpx.ReadTimeout, httpx.DecodingError],
    ids=["truncated", "timeout", "decoding"],
)
def test_body_failure_closes_response_and_preserves_state_rotation(
    asynchronous: bool, failure_type: type[httpx.RequestError]
) -> None:
    failure = failure_type("response body failed")
    states: list[str | None] = []

    class FailingBody(httpx.SyncByteStream, httpx.AsyncByteStream):
        closed = False

        def __iter__(self) -> Iterator[bytes]:
            yield b'{"sensor_data":"'
            raise failure

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b'{"sensor_data":"'
            raise failure

        def close(self) -> None:
            self.closed = True

        async def aclose(self) -> None:
            self.closed = True

    body = FailingBody()
    failed_response = httpx.Response(
        200,
        headers={"X-State-ID": "rotated-state", "X-Request-ID": "5" * 32},
        stream=body,
    )

    def handle(request: httpx.Request) -> httpx.Response:
        states.append(request.headers.get("X-State-ID"))
        if len(states) == 1:
            return failed_response
        return httpx.Response(
            200,
            json={"sensor_data": "continued", "headers": {}, "send_at": 0},
            headers={"X-Request-ID": "6" * 32},
        )

    def run_sync() -> None:
        with NullgateClient("secret", transport=httpx.MockTransport(handle)) as client:
            with client.open(identity=IDENTITY, user_agent="UA") as session:
                with pytest.raises(failure_type) as caught:
                    session.solve(SensorParams(SENSOR, "source"))
                assert caught.value is failure
                assert failed_response.is_closed and body.closed
                solution = session.solve(SensorParams(SENSOR, "source"))
                assert json.loads(solution.body) == {"sensor_data": "continued"}
                assert solution.request_id == "6" * 32

    async def run_async() -> None:
        async with NullgateClientAsync(
            "secret", transport=httpx.MockTransport(handle)
        ) as client:
            async with client.open(identity=IDENTITY, user_agent="UA") as session:
                with pytest.raises(failure_type) as caught:
                    await session.solve(SensorParams(SENSOR, "source"))
                assert caught.value is failure
                assert failed_response.is_closed and body.closed
                solution = await session.solve(SensorParams(SENSOR, "source"))
                assert json.loads(solution.body) == {"sensor_data": "continued"}
                assert solution.request_id == "6" * 32

    asyncio.run(run_async()) if asynchronous else run_sync()
    assert states[0]
    assert states[1:] == ["rotated-state"]


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("action_type", ["input", "change"])
@pytest.mark.parametrize("value", ["private-password", ""], ids=["secret", "empty"])
def test_raw_input_and_change_action_strings_are_rejected_before_transport(
    asynchronous: bool, action_type: str, value: str
) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise AssertionError("Raw action value reached the transport")

    params = SensorParams(
        SENSOR, "source", actions=[{"type": action_type, "target": 0, "value": value}]
    )

    def run_sync() -> None:
        with NullgateClient("secret", transport=httpx.MockTransport(handle)) as client:
            with client.open(identity=IDENTITY, user_agent="UA") as session:
                with pytest.raises(TypeError) as caught:
                    session.solve(params)
                assert "private-password" not in str(caught.value)

    async def run_async() -> None:
        async with NullgateClientAsync(
            "secret", transport=httpx.MockTransport(handle)
        ) as client:
            async with client.open(identity=IDENTITY, user_agent="UA") as session:
                with pytest.raises(TypeError) as caught:
                    await session.solve(params)
                assert "private-password" not in str(caught.value)

    asyncio.run(run_async()) if asynchronous else run_sync()
    assert requests == []


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_solve_does_not_retry_network_failures_or_follow_credential_redirects(
    asynchronous: bool,
) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            raise httpx.ConnectError("offline", request=request)
        return httpx.Response(
            307,
            headers={
                "Location": "https://other.example/steal",
                "X-Request-ID": "4" * 32,
            },
        )

    def run_sync() -> None:
        with NullgateClient(
            "secret",
            base_url="https://api.example",
            transport=httpx.MockTransport(handle),
        ) as client:
            with client.open(identity=IDENTITY, user_agent="UA") as session:
                with pytest.raises(httpx.ConnectError):
                    session.solve(SensorParams(SENSOR, "source"))
                with pytest.raises(NullgateAPIError) as caught:
                    session.solve(SensorParams(SENSOR, "source"))
                assert caught.value.status_code == 307

    async def run_async() -> None:
        async with NullgateClientAsync(
            "secret",
            base_url="https://api.example",
            transport=httpx.MockTransport(handle),
        ) as client:
            async with client.open(identity=IDENTITY, user_agent="UA") as session:
                with pytest.raises(httpx.ConnectError):
                    await session.solve(SensorParams(SENSOR, "source"))
                with pytest.raises(NullgateAPIError) as caught:
                    await session.solve(SensorParams(SENSOR, "source"))
                assert caught.value.status_code == 307

    asyncio.run(run_async()) if asynchronous else run_sync()
    assert len(requests) == 2
    assert all(request.url.host == "api.example" for request in requests)


def test_params_reject_wrong_protection_pairings_before_any_request() -> None:
    with pytest.raises(TypeError):
        PixelParams(cast(Pixel, SENSOR), "source")
    with pytest.raises(TypeError):
        SensorParams(cast(Sensor, SBSD), "source")
    with pytest.raises(TypeError):
        SbsdParams(cast(Sbsd, PIXEL), "source")
    with NullgateClient("secret") as client:
        with client.open(identity=IDENTITY, user_agent="UA") as session:
            with pytest.raises(TypeError):
                session.solve(cast(PixelParams, PAGE))
