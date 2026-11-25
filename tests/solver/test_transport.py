import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from nullgate.solver.models import SolveError
from nullgate.solver.transport import Transport


@pytest.fixture
def site():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(list(self.headers.items()))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_headers_order_controls_actual_http1_wire_order(site):
    port, requests = site

    async def run():
        transport = Transport(
            "test-agent",
            None,
            {"headers_order": ["x-third", "x-first", "x-second"]},
            {"x-first": "1", "x-second": "2", "x-third": "3"},
        )
        try:
            await transport.request("GET", f"http://127.0.0.1:{port}/")
        finally:
            await transport.aclose()

    asyncio.run(run())
    names = [name.lower() for name, _ in requests[0]]
    assert [name for name in names if name.startswith("x-")] == [
        "x-third",
        "x-first",
        "x-second",
    ]


@pytest.mark.parametrize(
    "order",
    [
        "x-one",
        ["x-one", "X-One"],
        [":authority"],
        ["x-bad\r\nInjected"],
        [""],
        ["x" * 257],
        [f"x-{index}" for index in range(129)],
        [42],
    ],
)
def test_headers_order_rejects_invalid_names(order):
    with pytest.raises(SolveError) as error:
        Transport("test-agent", None, {"headers_order": order})
    assert error.value.code == "invalid_request"


def test_page_context_does_not_leak_or_rebind_default_auth(site):
    port, requests = site
    page = f"http://127.0.0.1:{port}/page"
    external = f"http://localhost:{port}/asset"

    async def run():
        transport = Transport("test-agent", None, headers={"Authorization": "secret"})
        try:
            transport.set_page(page)
            await transport.request("GET", external)
            transport.set_page(external)
            await transport.request("GET", external)
            await transport.request("GET", page)
        finally:
            await transport.aclose()

    asyncio.run(run())
    first, second, third = (dict((k.lower(), v) for k, v in row) for row in requests)
    assert "authorization" not in first
    assert first["referer"] == f"http://127.0.0.1:{port}/"
    assert first["sec-fetch-site"] == "cross-site"
    assert "authorization" not in second
    assert second["sec-fetch-site"] == "same-origin"
    assert third["authorization"] == "secret"
