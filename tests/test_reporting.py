import asyncio
import json

import httpx
import pytest
from websockets.asyncio.server import serve

from nullgate import Nullgate, NullgateError, TargetResponse
from nullgate.aio import Nullgate as AsyncNullgate

REQUEST_ID = "0123456789abcdef0123456789abcdef"
HTML = '<form id="login"></form>'


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "kind", ["client", "sensor", "pixel", "sbsd", "fwcim", "profile"]
)
def test_all_public_report_methods_send_only_issued_id_without_credentials(
    asynchronous, kind
):
    reports = []

    def handler(request):
        if request.url.path.endswith("/analytics/report"):
            reports.append(request)
            return httpx.Response(200, json={"ok": True})
        if request.url.path.endswith("/account"):
            data = {"account": "example"}
        elif request.url.path.endswith("/fwcim"):
            data = {
                "metadata1": "generated",
                "headers": {},
                "send_at": 0,
                "session": "amazon",
                "request_id": REQUEST_ID,
            }
        else:
            data = {
                "request": {
                    "url": "https://shop.example/verify",
                    "body": "generated",
                    "headers": {},
                    "send_at": 0,
                },
                "session": "akamai",
                "request_id": REQUEST_ID,
            }
        return httpx.Response(
            200, json=data, headers={"Set-Cookie": "api_cookie=private; Path=/"}
        )

    async def server(socket):
        await socket.recv()
        await socket.send(
            json.dumps({"type": "hello", "session": "tmx", "request_id": REQUEST_ID})
        )
        await socket.send(json.dumps({"type": "ready", "request_id": REQUEST_ID}))
        assert json.loads(await socket.recv()) == {"type": "close"}

    def options():
        if kind == "fwcim":
            return {"timing": {"navigationStart": 1800000000000}}
        if kind == "pixel":
            return {"script": "source", "script_url": "/pixel", "challenge": "123"}
        return {"script": "source", "script_url": "/guard", "cookies": {}}

    async def exercise(base_url):
        if asynchronous:
            async with AsyncNullgate(
                "test-key", base_url=base_url, transport=httpx.MockTransport(handler)
            ) as ng:
                await ng.account()
                page = ng.session(user_agent="browser").page(
                    "https://shop.example/login", HTML
                )
                if kind == "profile":
                    async with page.threatmetrix(
                        send=lambda request: TargetResponse(200, {}, b""),
                        script_url="https://risk.example/tags.js",
                    ) as result:
                        pass
                    delivered = await result.report()
                elif kind == "client":
                    delivered = await ng.report(REQUEST_ID)
                else:
                    result = await getattr(page, kind)(**options())
                    delivered = await result.report()
                assert delivered is True
        else:

            def work():
                with Nullgate(
                    "test-key",
                    base_url=base_url,
                    transport=httpx.MockTransport(handler),
                ) as ng:
                    ng.account()
                    page = ng.session(user_agent="browser").page(
                        "https://shop.example/login", HTML
                    )
                    if kind == "profile":
                        with page.threatmetrix(
                            send=lambda request: TargetResponse(200, {}, b""),
                            script_url="https://risk.example/tags.js",
                        ) as result:
                            pass
                        delivered = result.report()
                    elif kind == "client":
                        delivered = ng.report(REQUEST_ID)
                    else:
                        result = getattr(page, kind)(**options())
                        delivered = result.report()
                    assert delivered is True

            await asyncio.to_thread(work)

    async def run():
        if kind == "profile":
            async with serve(server, "127.0.0.1", 0) as listener:
                port = listener.sockets[0].getsockname()[1]
                await exercise(f"http://127.0.0.1:{port}")
        else:
            await exercise("https://api.example/gateway")

    asyncio.run(run())
    assert len(reports) == 1
    request = reports[0]
    assert request.method == "POST"
    assert request.url.path == (
        "/analytics/report" if kind == "profile" else "/gateway/analytics/report"
    )
    assert json.loads(request.content) == {"request_id": REQUEST_ID}
    assert "authorization" not in request.headers
    assert "cookie" not in request.headers
    assert request.extensions["timeout"] == {
        "connect": 3.0,
        "read": 3.0,
        "write": 3.0,
        "pool": 3.0,
    }


@pytest.mark.parametrize(
    "outcome,expected",
    [(200, True), (204, True), (400, False), (503, False), ("network", False)],
)
def test_report_returns_only_http_delivery_and_never_retries(outcome, expected):
    calls = []

    def handler(request):
        calls.append(request)
        if outcome == "network":
            raise httpx.ConnectError("private detail", request=request)
        return httpx.Response(
            outcome, json={"code": "maintenance"}, headers={"Retry-After": "0"}
        )

    with Nullgate(
        "test-key", timeout=0.5, transport=httpx.MockTransport(handler)
    ) as ng:
        assert ng.report(REQUEST_ID) is expected
    assert len(calls) == 1
    assert set(calls[0].extensions["timeout"].values()) == {0.5}


@pytest.mark.parametrize("request_id", ["", " ", None, 1])
def test_invalid_report_id_is_refused_before_transport(request_id):
    def handler(request):
        pytest.fail("Invalid report ID reached API transport")

    with Nullgate("test-key", transport=httpx.MockTransport(handler)) as ng:
        with pytest.raises(NullgateError) as error:
            ng.report(request_id)
    assert error.value.code == "invalid_request"


def test_report_does_not_suppress_customer_transport_programming_errors():
    def handler(request):
        raise ValueError("custom transport bug")

    with Nullgate("test-key", transport=httpx.MockTransport(handler)) as ng:
        with pytest.raises(ValueError, match="custom transport bug"):
            ng.report(REQUEST_ID)
