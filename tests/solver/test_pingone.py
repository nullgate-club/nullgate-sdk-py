"""PingOne solves use the target transport and keep the caller's device profile."""

import asyncio
import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from nullgate.solver.engine import Engine
from nullgate.solver.models import SolveError


@pytest.fixture
def pingone_site():
    state = {"token_fetches": 0, "page_fetches": 0, "profiles": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, value):
            body = json.dumps(value).encode() if isinstance(value, dict) else value
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/login":
                state["page_fetches"] += 1
                self.reply(500, b"unexpected navigation")
            elif path == "/signals-sdk.js":
                self.reply(200, b"fixture sdk source")
            elif path == "/token":
                state["token_fetches"] += 1
                if (
                    self.headers.get("Origin") != base
                    or self.headers.get("X-Context") != "prepared"
                ):
                    self.reply(403, b"missing token context")
                else:
                    self.reply(200, b"fixture token response")
            else:
                self.reply(404, b"not found")

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
            payload = json.loads(raw)
            if payload.get("website", {}).get("url") != base + "/login":
                self.reply(400, {"code": "bad_origin"})
                return
            profile = payload.get("profile")
            if not profile or (state["profiles"] and profile != state["profiles"][0]):
                self.reply(400, {"code": "bad_profile"})
                return
            state["profiles"].append(profile)
            if self.path == "/pingone/prepare":
                self.reply(
                    200,
                    {
                        "session": "prepared-session",
                        "request_id": "prepare-request",
                        "sdk_version": "5.6.10",
                        "request": {
                            "role": "pingone.token",
                            "method": "GET",
                            "url": base + "/token",
                            "body": None,
                            "credentials": "include",
                            "headers": {"origin": base, "x-context": "prepared"},
                        },
                    },
                )
            elif self.path == "/pingone/protect":
                token_valid = (
                    payload.get("token_response") == "fixture token response"
                    and payload.get("session") == "prepared-session"
                ) or payload.get("client_token") == "provided-token"
                if (
                    not token_valid
                    or payload.get("website", {}).get("html") != html
                    or payload.get("jwt_device_attributes") != "device.jwt"
                    or payload.get("jwt_agent_payload") != "agent.jwt"
                    or payload.get("sdk_config") != {"agentIdentification": True}
                    or payload.get("behavioral") != {"enabled": True}
                ):
                    self.reply(400, {"code": "bad_context"})
                    return
                self.reply(
                    200,
                    {
                        "data": "device-payload-" + profile,
                        "device_id": "device-" + profile,
                        "sdk_version": "5.6.10",
                        "session": "generated-session",
                        "request_id": "protect-request",
                    },
                )
            else:
                self.reply(404, {"code": "not_found"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    base = f"http://127.0.0.1:{server.server_port}"
    html = '<html><script src="/signals-sdk.js"></script></html>'
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield base, html, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_pingone_uses_supplied_html_and_preserves_named_device(pingone_site):
    base, html, state = pingone_site

    async def run():
        options = {
            "jwt_device_attributes": "device.jwt",
            "jwt_agent_payload": "agent.jwt",
            "sdk_config": {"agentIdentification": True},
            "behavioral": {"enabled": True},
        }
        async with Engine("test-key", base_url=base, timeout=10) as engine:
            first = await engine.solve(
                type="pingone",
                url=base + "/login",
                user_agent="browser",
                session="account",
                html=html,
                pingone=options,
            )
            second = await engine.solve(
                type="pingone",
                url=base + "/login",
                session="account",
                html=html,
                pingone={**options, "client_token": "provided-token"},
            )
            first_result = first["result"]
            second_result = second["result"]
            assert first_result["device_id"] == second_result["device_id"]
            assert first_result["data"] == "device-payload-" + state["profiles"][0]
            assert first_result["sdk_version"] == "5.6.10"
            assert first_result["request_id"] == "protect-request"
            assert second_result["data"] == first_result["data"]
            assert state["token_fetches"] == 1
            assert state["page_fetches"] == 0

    asyncio.run(run())


def test_pingone_requires_script_url_when_sdk_is_not_in_html(pingone_site):
    base, _, _ = pingone_site

    async def run():
        async with Engine("test-key", base_url=base, timeout=10) as engine:
            with pytest.raises(SolveError) as error:
                await engine.solve(
                    type="pingone",
                    url=base + "/login",
                    user_agent="browser",
                    html='<script src="/bundle.js"></script>',
                )
            assert error.value.code == "protection_not_found"
            assert "script_url" in error.value.message

    asyncio.run(run())
