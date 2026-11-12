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


@pytest.fixture(params=["sync", "async"])
def compression_client(request):
    calls, replies = [], []

    def handler(outgoing):
        calls.append(outgoing)
        if replies:
            return replies.pop(0)
        return httpx.Response(
            200,
            json={
                "request": {
                    "url": "https://shop.example/verify",
                    "body": "generated",
                    "headers": {},
                    "send_at": 0,
                },
                "session": "akamai-session",
                "request_id": "request-id",
            },
        )

    asynchronous = request.param == "async"
    transport = AsyncTransport(handler) if asynchronous else SyncTransport(handler)
    client = (
        AsyncNullgate("test-key", transport=transport)
        if asynchronous
        else Nullgate("test-key", transport=transport)
    )
    with asyncio.Runner() as runner:
        if asynchronous:
            runner.run(client.__aenter__())
        else:
            client.__enter__()

        def call(method, **kwargs):
            result = method(**kwargs)
            return runner.run(result) if asynchronous else result

        try:
            yield client, call, calls, replies
        finally:
            if asynchronous:
                runner.run(client.aclose())
            else:
                client.close()


def compression_page(client):
    return client.session(
        user_agent="browser", profile="00000000-0000-0000-0000-000000000001"
    ).page(
        "https://shop.example",
        '<script src="/sensor"></script>',
        document_id="00000000-0000-0000-0000-000000000002",
        started_at_ms=1800000000000,
    )


def advertise_gzip(call, client, replies):
    replies.append(httpx.Response(200, json={}, headers={"Accept-Encoding": "gzip"}))
    call(client.account)


def test_gzip_requires_advertisement_and_preserves_exact_json(compression_client):
    client, call, calls, replies = compression_client
    script = "const π = '😀';" * 100
    replies.append(
        httpx.Response(
            400,
            json={"code": "invalid_request", "message": "Try again"},
            headers={"Accept-Encoding": "br, GZip; q=1"},
        )
    )
    with pytest.raises(NullgateError):
        call(compression_page(client).sensor, script=script, cookies={})
    call(compression_page(client).sensor, script=script, cookies={})
    first, second = calls
    assert "Content-Encoding" not in first.headers
    assert second.headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(second.content) == first.content
    assert int(second.headers["Content-Length"]) == len(second.content)
    assert second.headers["Content-Type"] == "application/json"


@pytest.mark.parametrize("advertisement", [None, "br", "gzip;q=0", "GZip; q=0.00"])
def test_old_servers_and_disabled_gzip_advertisements_keep_raw_json(
    compression_client, advertisement
):
    client, call, calls, replies = compression_client
    headers = {} if advertisement is None else {"Accept-Encoding": advertisement}
    replies.append(httpx.Response(200, json={}, headers=headers))
    call(client.account)
    call(compression_page(client).sensor, script="x" * 2048, cookies={})
    assert "Content-Encoding" not in calls[-1].headers
    assert json.loads(calls[-1].content)["script"] == "x" * 2048


@pytest.mark.parametrize("size", [1023, 1024, 1025])
def test_gzip_threshold_counts_serialized_utf8_bytes(compression_client, size):
    client, call, calls, replies = compression_client
    call(compression_page(client).sensor, script="", cookies={})
    overhead = len(calls[-1].content)
    advertise_gzip(call, client, replies)
    call(compression_page(client).sensor, script="a" * (size - overhead), cookies={})
    request = calls[-1]
    if size >= 1024:
        assert request.headers["Content-Encoding"] == "gzip"
        assert len(gzip.decompress(request.content)) == size
    else:
        assert "Content-Encoding" not in request.headers
        assert len(request.content) == size
    call(client.account)
    call(client.report, request_id="delivered")
    assert all("Content-Encoding" not in item.headers for item in calls[-2:])


@pytest.mark.parametrize("status", [413, 415])
def test_gzip_retries_raw_and_only_415_disables_future_compression(
    compression_client, status
):
    client, call, calls, replies = compression_client
    advertise_gzip(call, client, replies)
    replies.append(httpx.Response(status, text="proxy error"))
    call(compression_page(client).sensor, script="x" * 2048, cookies={})
    compressed, raw = calls[-2:]
    assert compressed.headers["Content-Encoding"] == "gzip"
    assert "Content-Encoding" not in raw.headers
    assert gzip.decompress(compressed.content) == raw.content
    advertise_gzip(call, client, replies)
    call(compression_page(client).sensor, script="x" * 2048, cookies={})
    assert (calls[-1].headers.get("Content-Encoding") == "gzip") is (status == 413)


@pytest.mark.parametrize(
    "failures,encodings,scripts,success",
    [
        ([413, 428], ["gzip", None, None], [False, False, True], True),
        ([428, 413], ["gzip", "gzip", None], [False, True, True], True),
        ([415, 428], ["gzip", None, None], [False, False, True], True),
        ([428, 415], ["gzip", "gzip", None], [False, True, True], True),
        ([428, 428], ["gzip", "gzip"], [False, True], False),
        ([413, 413], ["gzip", None], [False, False], False),
        ([413, 428, 428], ["gzip", None, None], [False, False, True], False),
        ([428, 413, 413], ["gzip", "gzip", None], [False, True, True], False),
        ([503, 413, 428], ["gzip", "gzip", None], [False, False, False], False),
    ],
)
def test_gzip_and_script_fallbacks_share_three_attempt_budget(
    compression_client, failures, encodings, scripts, success
):
    client, call, calls, replies = compression_client
    page = client.session(user_agent="browser").page(
        "https://shop.example",
        '<script src="/sensor"></script>' + " " * 2048,
    )
    replies.append(
        httpx.Response(
            200,
            json={
                "request": {
                    "url": "https://shop.example/verify",
                    "body": "generated",
                    "headers": {},
                    "send_at": 0,
                },
                "session": "akamai-session",
                "request_id": "first",
                "script_retained": True,
            },
            headers={"Accept-Encoding": "gzip"},
        )
    )
    call(page.sensor, script="source" * 200, cookies={})
    codes = {
        413: "invalid_request",
        415: "invalid_request",
        428: "script_required",
        503: "maintenance",
    }
    replies.extend(
        httpx.Response(
            status,
            json={"code": codes[status], "message": "Retry"},
            headers={"Retry-After": "0"},
        )
        for status in failures
    )
    if success:
        call(page.sensor, script="source" * 200, cookies={}, inputs=[], actions=[])
    else:
        with pytest.raises(NullgateError):
            call(page.sensor, script="source" * 200, cookies={}, inputs=[], actions=[])
    attempts = calls[1:]
    assert [item.headers.get("Content-Encoding") for item in attempts] == encodings
    bodies = [
        json.loads(gzip.decompress(item.content) if encoding else item.content)
        for item, encoding in zip(attempts, encodings, strict=True)
    ]
    assert ["script" in body for body in bodies] == scripts
    assert all(body["inputs"] == body["actions"] == [] for body in bodies)
