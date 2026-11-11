import json
from pathlib import Path

import httpx
import pytest

WIRE = json.loads((Path(__file__).parent / "wire.json").read_text())


@pytest.fixture
def api(monkeypatch):
    calls = []
    replies = []
    original = httpx.AsyncClient

    def handler(request):
        calls.append(request)
        if replies:
            status, body, headers = replies.pop(0)
            return httpx.Response(status, content=json.dumps(body), headers=headers)
        if request.url.path == "/account":
            body = WIRE["accounts"]["components"]["schemas"]["Profile"]["examples"][0]
        elif request.url.path == "/account/usage":
            body = WIRE["accounts"]["components"]["schemas"]["UsageResponse"][
                "examples"
            ][0]
        elif request.url.path == "/amazon/fwcim":
            body = WIRE["amazon"]["components"]["schemas"]["Generated"]["examples"][0]
        else:
            body = {
                "request": {
                    "url": "https://shop.example/verify",
                    "body": "generated",
                    "headers": {"content-type": "text/plain;charset=UTF-8"},
                    "send_at": 0,
                },
                "session": "akamai-session",
                "request_id": "request-id",
            }
        return httpx.Response(200, json=body)

    def client(*args, **kwargs):
        if kwargs.get("transport") is None:
            kwargs["transport"] = httpx.MockTransport(handler)
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    return calls, replies
