import asyncio
import gzip
import json

import httpx
import pytest

from nullgate import Nullgate, NullgateError, TargetResponse
from nullgate.aio import Nullgate as AsyncNullgate


@pytest.mark.parametrize("asynchronous", [False, True])
def test_protect_fetches_css_and_recovers_metadata_once(asynchronous):
    calls = []
    target_calls = []
    script = "sdk source " * 200

    def handler(request):
        raw = request.content
        if request.headers.get("content-encoding") == "gzip":
            raw = gzip.decompress(raw)
        body = json.loads(raw)
        calls.append((request.url.path, body, request.headers.get("content-encoding")))
        if request.url.path.endswith("prepare"):
            return httpx.Response(
                200,
                json={
                    "session": "prepared",
                    "request_id": "prepare-id",
                    "sdk_version": "1",
                    "request": {
                        "role": "pingone.token",
                        "method": "GET",
                        "url": "https://apps.pingone.com/token",
                        "headers": {},
                        "body": None,
                        "credentials": "include",
                    },
                },
            )
        if len([call for call in calls if call[0].endswith("protect")]) == 1:
            return httpx.Response(428, json={"code": "script_required"})
        return httpx.Response(
            200,
            json={
                "data": "secret-data",
                "sdk_version": "1",
                "device_id": "device",
                "session": "next",
                "request_id": "request",
            },
        )

    def send(request):
        target_calls.append(request)
        return TargetResponse(200, {}, b"token css")

    options = {
        "script": script,
        "send": send,
        "jwt_device_attributes": "device.jwt",
        "jwt_agent_payload": "agent.jwt",
        "sdk_config": {"agentIdentification": True},
    }

    async def run():
        async with AsyncNullgate(
            "test-api-key", transport=httpx.MockTransport(handler)
        ) as ng:
            return (
                await ng.session(user_agent="browser")
                .page("https://identity.example/login", "<html></html>")
                .protect(**options)
            )

    if asynchronous:
        result = asyncio.run(run())
    else:
        with Nullgate("test-api-key", transport=httpx.MockTransport(handler)) as ng:
            result = (
                ng.session(user_agent="browser")
                .page("https://identity.example/login", "<html></html>")
                .protect(**options)
            )
    assert len(target_calls) == 1
    assert "test-api-key" not in repr(target_calls[0])
    assert all(
        "test-api-key" not in value for value in target_calls[0].headers.values()
    )
    assert [call[0] for call in calls] == [
        "/pingone/prepare",
        "/pingone/protect",
        "/pingone/protect",
    ]
    assert calls[0][2] == "gzip"
    assert "script" not in calls[1][1]
    assert calls[2][1]["script"] == script
    for _, body, _ in calls[1:]:
        assert body["token_response"] == "token css"
        assert body["jwt_device_attributes"] == "device.jwt"
        assert body["jwt_agent_payload"] == "agent.jwt"
        assert body["website"]["url"] == "https://identity.example/login"
    assert result.data == "secret-data"
    assert "secret-data" not in repr(result)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("status", [200, 403])
def test_client_token_skips_fetch_and_css_failure_stops_protect(asynchronous, status):
    paths = []

    def handler(request):
        paths.append(request.url.path)
        if request.url.path.endswith("prepare"):
            return httpx.Response(
                200,
                json={
                    "session": "s",
                    "request": {
                        "role": "pingone.token",
                        "method": "GET",
                        "url": "https://apps.pingone.com/token",
                        "headers": {},
                        "body": None,
                        "credentials": "include",
                    },
                },
            )
        return httpx.Response(
            200,
            json={
                "data": "data",
                "sdk_version": "1",
                "device_id": "id",
                "session": "s",
                "request_id": "id",
            },
        )

    def send(request):
        return TargetResponse(status, {}, b"css")

    options = {
        "script": "source",
        **({"client_token": "token"} if status == 200 else {"send": send}),
    }

    async def run():
        async with AsyncNullgate("key", transport=httpx.MockTransport(handler)) as ng:
            return (
                await ng.session(user_agent="browser")
                .page("https://identity.example/", "")
                .protect(**options)
            )

    def sync_run():
        with Nullgate("key", transport=httpx.MockTransport(handler)) as ng:
            return (
                ng.session(user_agent="browser")
                .page("https://identity.example/", "")
                .protect(**options)
            )

    if status == 403:
        with pytest.raises(NullgateError) as error:
            asyncio.run(run()) if asynchronous else sync_run()
        assert error.value.status == 403
        assert paths == ["/pingone/prepare"]
    else:
        result = asyncio.run(run()) if asynchronous else sync_run()
        assert result.data == "data"
        assert paths == ["/pingone/protect"]


def test_source_changes_and_pages_do_not_reuse_other_metadata():
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "data": "value",
                "sdk_version": "1",
                "device_id": "device",
                "session": "same-session",
                "request_id": "id",
            },
        )

    with Nullgate("key", transport=httpx.MockTransport(handler)) as ng:
        session = ng.session(user_agent="browser")
        first = session.page("https://identity.example/", "")
        second = session.page("https://identity.example/", "")
        first.protect(script="first", client_token="token")
        first.protect(script="first", client_token="token")
        second.protect(script="second", client_token="token")
        first.protect(script="first", client_token="token")
    assert [body.get("script") for body in bodies] == ["first", None, "second", "first"]
