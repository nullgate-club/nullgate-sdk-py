"""Simple clients must preserve session context and reject false successes."""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from nullgate.solver import SolveError, Solver
from nullgate.solver.aio import Solver as AsyncSolver


@pytest.fixture
def local_api():
    cookie = {
        "name": "device",
        "value": "pending",
        "domain": "target.example",
        "path": "/login",
        "secure": True,
        "http_only": True,
        "host_only": True,
        "expires": 4102444800,
        "same_site": "Lax",
    }
    state = {"step": 0, "response": None}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if state["response"] is not None:
                status, response = state["response"]
            elif state["step"] == 0:
                valid = (
                    data.get("type") == "akamai"
                    and data.get("session") == "account-1"
                    and data.get("proxy") == "http://user:password@proxy.example:8080"
                    and data.get("transport", {}).get("headers_order")
                    == ["user-agent", "accept"]
                    and data.get("transport", {})
                    .get("tls_options", {})
                    .get("min_tls_version")
                    == "TLS_1_2"
                )
                status = 200 if valid else 400
                response = {"cookies": [cookie], "result": {"accepted": True}}
                state["step"] = 1
            else:
                valid = (
                    data.get("session") == "account-1"
                    and data.get("type") == "pingone"
                    and data.get("cookies") == [cookie]
                    and data.get("pingone", {}).get("client_token") == "caller-token"
                )
                status = 200 if valid else 400
                response = {
                    "cookies": [cookie],
                    "result": {
                        "data": "protected-profile",
                        "device_id": "stable-device",
                        "sdk_version": "5.2.6",
                        "request_id": "generation-2",
                    },
                }
                state["step"] = 2
            body = (
                response
                if isinstance(response, bytes)
                else json.dumps(response).encode()
            )
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_client_keeps_session_transport_and_cookie_metadata(local_api, asynchronous):
    base, _ = local_api
    first = {
        "type": "akamai",
        "url": "https://target.example/login",
        "user_agent": "browser",
        "session": "account-1",
        "proxy": "http://user:password@proxy.example:8080",
        "transport": {
            "headers_order": ["user-agent", "accept"],
            "tls_options": {"min_tls_version": "TLS_1_2"},
        },
    }
    second = {
        "type": "pingone",
        "url": "https://target.example/login",
        "session": "account-1",
        "pingone": {"client_token": "caller-token"},
    }

    async def run():
        async with AsyncSolver(base) as client:
            initial = await client.solve(**first)
            second["cookies"] = initial["cookies"]
            return await client.solve(**second)

    if asynchronous:
        result = asyncio.run(run())
    else:
        with Solver(base) as client:
            initial = client.solve(**first)
            second["cookies"] = initial["cookies"]
            result = client.solve(**second)
    assert result["result"]["device_id"] == "stable-device"
    assert result["result"]["data"] == "protected-profile"


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "body",
    [
        b"not JSON",
        b'{"cookies":[],"result":{}}',
        b'{"cookies":[],"result":{"accepted":false}}',
    ],
)
def test_client_never_returns_malformed_or_unaccepted_success(
    local_api, asynchronous, body
):
    base, state = local_api
    state["response"] = (200, body)

    async def run():
        async with AsyncSolver(base) as client:
            return await client.solve(
                type="akamai", url="https://target.example", session="existing"
            )

    with pytest.raises(SolveError) as caught:
        if asynchronous:
            asyncio.run(run())
        else:
            with Solver(base) as client:
                client.solve(
                    type="akamai", url="https://target.example", session="existing"
                )
    assert caught.value.code == "invalid_response"
    assert caught.value.stage == "response"


def test_client_retains_billing_error_diagnostics(local_api):
    base, state = local_api
    state["response"] = (
        402,
        {
            "code": "insufficient_balance",
            "message": "Balance is insufficient",
            "stage": "generate",
            "request_id": "billing-request",
            "cause": "BalanceError",
        },
    )
    with Solver(base) as client, pytest.raises(SolveError) as caught:
        client.solve(type="akamai", url="https://target.example", session="existing")
    assert (
        caught.value.code,
        caught.value.status,
        caught.value.request_id,
        caught.value.cause,
    ) == ("insufficient_balance", 402, "billing-request", "BalanceError")
