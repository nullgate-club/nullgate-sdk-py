import asyncio
import json
from hashlib import sha256

import httpx
import pytest

from nullgate import async_open_session, open_session

IDENTITY = "a07aad50-f262-40b1-b187-11532c054bc0"


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_generation_protocol_preserves_state_and_summarizes_only_explicit_inputs(
    asynchronous: bool,
) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={"X-State-ID": "document-state"}, json={})

    transport = httpx.MockTransport(handle)
    website = {
        "url": "https://shop.example/login",
        "html": '<html><input name="page-only" value="existing-page-value"></html>',
    }
    script = {"source": "https://shop.example/bot-manager.js", "text": "void 0;"}
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/146.0.0.0"
    fields = [{"name": "password", "type": "password", "value": "s🔑&"}]

    def run_sync() -> None:
        with open_session(
            "https://nullgate.test", uuid=IDENTITY, transport=transport
        ) as client:
            client.pixel(
                website=website,
                script=script,
                user_agent=user_agent,
                challenge="001234",
            )
            client.sensor_data(
                website=website, script=script, user_agent=user_agent, inputs=fields
            )
            client.sensor_data(website=website, script=script, user_agent=user_agent)
            client.sensor_data(
                website=website, script=script, user_agent=user_agent, inputs=[]
            )

    async def run_async() -> None:
        async with async_open_session(
            "https://nullgate.test", uuid=IDENTITY, transport=transport
        ) as client:
            await client.pixel(
                website=website,
                script=script,
                user_agent=user_agent,
                challenge="001234",
            )
            await client.sensor_data(
                website=website, script=script, user_agent=user_agent, inputs=fields
            )
            await client.sensor_data(
                website=website, script=script, user_agent=user_agent
            )
            await client.sensor_data(
                website=website, script=script, user_agent=user_agent, inputs=[]
            )

    if asynchronous:
        asyncio.run(run_async())
    else:
        run_sync()

    assert [request.headers.get("X-State-ID") for request in requests] == [
        None,
        "document-state",
        "document-state",
        "document-state",
    ]
    assert all(request.method == "POST" for request in requests)
    assert all(request.url.path == f"/v1/{IDENTITY}/generate" for request in requests)
    assert [request.url.params["type"] for request in requests] == [
        "pixel",
        "akamai",
        "akamai",
        "akamai",
    ]
    pixel, filled, unchanged, cleared = [
        json.loads(request.content) for request in requests
    ]
    assert pixel["challenge"] == "001234"
    assert "challenge" not in filled
    assert filled["inputs"] == [
        {
            "attributes": {"name": "password", "type": "password"},
            "value": {
                "length": 4,
                "hash": sha256(bytes.fromhex("73003dd811dd2600")).hexdigest(),
                "counts": [4, 3, 1, 0],
            },
        }
    ]
    assert "inputs" not in unchanged
    assert cleared["inputs"] == []
    for request in requests:
        payload = json.loads(request.content)
        assert request.headers["User-Agent"] == user_agent
        assert "user_agent" not in payload
        assert payload["website"]["html"] == website["html"]
        assert "s🔑&" not in request.content.decode()


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_generation_errors_propagate_and_continue_state(asynchronous: bool) -> None:
    state_ids: list[str | None] = []
    pixel_error = {"detail": "user_agent must match the current state"}
    sensor_error = {"detail": "generation temporarily unavailable"}
    responses = iter(
        [
            httpx.Response(
                422, headers={"X-State-ID": "error-state"}, json=pixel_error
            ),
            httpx.Response(503, json=sensor_error),
        ]
    )

    def handle(request: httpx.Request) -> httpx.Response:
        state_ids.append(request.headers.get("X-State-ID"))
        return next(responses)

    transport = httpx.MockTransport(handle)
    website = {"url": "https://shop.example/login", "html": "<html></html>"}
    script = {"source": "https://shop.example/bot-manager.js", "text": "void 0;"}
    user_agent = "Mozilla/5.0 Chrome/146.0.0.0"

    def run_sync() -> None:
        with open_session(
            "https://nullgate.test", uuid=IDENTITY, transport=transport
        ) as client:
            with pytest.raises(httpx.HTTPStatusError) as pixel_failure:
                client.pixel(
                    website=website,
                    script=script,
                    user_agent=user_agent,
                    challenge="123456",
                )
            assert pixel_failure.value.response.status_code == 422
            assert pixel_failure.value.response.json() == pixel_error
            with pytest.raises(httpx.HTTPStatusError) as sensor_failure:
                client.sensor_data(
                    website=website, script=script, user_agent=user_agent
                )
            assert sensor_failure.value.response.status_code == 503
            assert sensor_failure.value.response.json() == sensor_error

    async def run_async() -> None:
        async with async_open_session(
            "https://nullgate.test", uuid=IDENTITY, transport=transport
        ) as client:
            with pytest.raises(httpx.HTTPStatusError) as pixel_failure:
                await client.pixel(
                    website=website,
                    script=script,
                    user_agent=user_agent,
                    challenge="123456",
                )
            assert pixel_failure.value.response.status_code == 422
            assert pixel_failure.value.response.json() == pixel_error
            with pytest.raises(httpx.HTTPStatusError) as sensor_failure:
                await client.sensor_data(
                    website=website, script=script, user_agent=user_agent
                )
            assert sensor_failure.value.response.status_code == 503
            assert sensor_failure.value.response.json() == sensor_error

    if asynchronous:
        asyncio.run(run_async())
    else:
        run_sync()

    assert state_ids == [None, "error-state"]
