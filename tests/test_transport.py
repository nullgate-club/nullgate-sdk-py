import asyncio
import gzip
import json

import httpx
import pytest

from nullgate import Nullgate, NullgateError
from nullgate.aio import Nullgate as AsyncNullgate


class SyncTransport(httpx.BaseTransport):
    def __init__(self, handler):
        self.handler = handler
        self.entered = False
        self.close_count = 0

    def __enter__(self):
        self.entered = True
        return self

    def handle_request(self, request):
        assert self.entered, "The SDK must open its owned transport"
        return self.handler(request)

    def close(self):
        self.close_count += 1


class AsyncTransport(httpx.AsyncBaseTransport):
    def __init__(self, handler):
        self.handler = handler
        self.entered = False
        self.close_count = 0

    async def __aenter__(self):
        self.entered = True
        return self

    async def handle_async_request(self, request):
        assert self.entered, "The SDK must open its owned transport"
        return self.handler(request)

    async def aclose(self):
        self.close_count += 1


@pytest.mark.parametrize(
    "asynchronous,compressed", [(False, False), (False, True), (True, False)]
)
def test_injected_transport_observes_all_api_operations_and_owns_its_lifetime(
    asynchronous, compressed, monkeypatch
):
    calls = []
    monkeypatch.setenv("HTTPS_PROXY", "http://unused.invalid:1")

    def handler(request):
        calls.append((request.method, request.url.path))
        if request.url.path.startswith("/account"):
            data = {"account": "example"}
        elif request.url.path == "/amazon/fwcim":
            data = {
                "metadata1": "generated",
                "headers": {},
                "send_at": 0,
                "request_id": "amazon-id",
                "session": "amazon-session",
            }
        else:
            data = {
                "request": {
                    "url": "https://shop.example/verify",
                    "body": "generated",
                    "headers": {},
                    "send_at": 0,
                },
                "request_id": "akamai-id",
                "session": "akamai-session",
            }
        if compressed:
            return httpx.Response(
                200,
                headers={"Content-Encoding": "gzip"},
                stream=httpx.ByteStream(gzip.compress(json.dumps(data).encode())),
            )
        return httpx.Response(200, json=data)

    transport = AsyncTransport(handler) if asynchronous else SyncTransport(handler)
    html = (
        '<form id="login"><input id="email"></form>'
        '<script>bazadebezolkohpepadr="123"</script>'
    )
    if asynchronous:

        async def run():
            async with AsyncNullgate("test-key", transport=transport) as ng:
                await ng.account()
                await ng.usage()
                page = ng.session(user_agent="browser").page(
                    "https://shop.example", html
                )
                await page.sensor(script="source", script_url="/sensor", cookies={})
                await page.pixel(script="source", script_url="/pixel")
                await page.sbsd(script="source", script_url="/sbsd", cookies={})
                await page.fwcim(
                    form="#login", timing={"navigationStart": 1800000000000}, inputs={}
                )
            await ng.aclose()

        asyncio.run(run())
    else:
        with Nullgate("test-key", transport=transport) as ng:
            ng.account()
            ng.usage()
            page = ng.session(user_agent="browser").page("https://shop.example", html)
            page.sensor(script="source", script_url="/sensor", cookies={})
            page.pixel(script="source", script_url="/pixel")
            page.sbsd(script="source", script_url="/sbsd", cookies={})
            page.fwcim(
                form="#login", timing={"navigationStart": 1800000000000}, inputs={}
            )
        ng.close()
    assert calls == [
        ("GET", "/account"),
        ("GET", "/account/usage"),
        ("POST", "/akamai/sensor"),
        ("POST", "/akamai/pixel"),
        ("POST", "/akamai/sbsd"),
        ("POST", "/amazon/fwcim"),
    ]
    assert transport.close_count == 1


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "network_failure", [False, True], ids=["http-400", "connection-error"]
)
def test_injected_failure_maps_to_public_error_without_retry(
    asynchronous, network_failure
):
    calls = []

    def handler(request):
        calls.append(request)
        if network_failure:
            raise httpx.ConnectError("private transport detail", request=request)
        return httpx.Response(
            400,
            json={
                "code": "invalid_request",
                "message": "Invalid input",
                "request_id": "failed-id",
            },
        )

    transport = AsyncTransport(handler) if asynchronous else SyncTransport(handler)
    if asynchronous:

        async def run():
            async with AsyncNullgate("test-key", transport=transport) as ng:
                await ng.account()

        with pytest.raises(NullgateError) as failure:
            asyncio.run(run())
    else:
        with (
            Nullgate("test-key", transport=transport) as ng,
            pytest.raises(NullgateError) as failure,
        ):
            ng.account()
    assert failure.value.code == (
        "transport_error" if network_failure else "invalid_request"
    )
    assert failure.value.status == (None if network_failure else 400)
    assert failure.value.request_id == (None if network_failure else "failed-id")
    assert "private transport detail" not in str(failure.value)
    assert len(calls) == 1
    assert transport.close_count == 1
