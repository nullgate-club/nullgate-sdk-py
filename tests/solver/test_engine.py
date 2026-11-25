"""Consumer failures: false acceptance, stale cookies and credential leaks."""

import asyncio
import base64
import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest
from websockets.asyncio.server import serve

from nullgate.solver import SolveError
from nullgate.solver.engine import Engine

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
)


@pytest.fixture
def site():
    state = {"accept": True, "posts": [], "api_cookies": [], "target_headers": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, body=b"", status=200, cookies=()):
            self.send_response(status)
            if body and "/page" in self.path:
                body = gzip.compress(body)
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/page":
                state["posts"] = []
                self.reply(
                    b'<script src="/sensor"></script>'
                    b'<script>bazadebezolkohpepadr="123"</script>'
                    b'<script src="/akam/13/abc"></script>'
                )
            elif path == "/tmx":
                self.reply(
                    b'<script src="/fp/tags.js?org_id=org&session_id=site-session">'
                    b"</script>"
                )
            elif path == "/collector":
                state["target_headers"].append(dict(self.headers))
                omit = self.headers.get("X-Omit") == "yes"
                self.reply(
                    b"collected",
                    cookies=[
                        "unwanted=discard; Path=/"
                        if omit
                        else "tmx=complete; Path=/; HttpOnly"
                    ],
                )
            else:
                self.reply(b"source")

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path.startswith("/akamai/"):
                if self.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
                payload = json.loads(body)
                state["api_cookies"].append(payload.get("cookies", {}))
                kind = self.path.rsplit("/", 1)[1]
                self.reply(
                    json.dumps(
                        {
                            "session": "remote-state",
                            "request_id": "backend-request",
                            "request": {
                                "url": base
                                + ("/sensor" if kind == "sensor" else "/pixel"),
                                "body": "generated",
                                "headers": {
                                    "content-type": "text/plain",
                                    "sec-fetch-mode": "cors",
                                    "sec-fetch-dest": "empty",
                                    "sec-fetch-site": "same-origin",
                                },
                                "send_at": 0,
                            },
                        }
                    ).encode()
                )
            else:
                assert body == b"generated"
                required = state.get("require_cookie")
                if (
                    required
                    and not state["posts"]
                    and required not in self.headers.get("Cookie", "")
                ):
                    self.reply(status=403)
                    return
                state["posts"].append(self.path)
                valid = (
                    state["posts"] == ["/sensor", "/pixel", "/sensor", "/sensor"]
                    and state["accept"]
                )
                value = "accepted~0~value~-1" if valid else "pending~-1~0~-1"
                self.reply(
                    cookies=[
                        f"_abck={value}; Path=/; HttpOnly",
                        "scoped=a; Path=/other",
                    ]
                )

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    base = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield base, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize(
    ("accepted", "user_agent"),
    [
        (True, UA),
        (False, UA),
        (
            True,
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
        ),
        (
            True,
            "Mozilla/5.0 (iPhone; CPU iPhone OS 26_2 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 "
            "Mobile/15E148 Safari/604.1",
        ),
    ],
)
def test_akamai_requires_acceptance_after_ordered_sensor_pixel_flow(
    site, accepted, user_agent
):
    base, state = site
    state["accept"] = accepted

    async def run():
        async with Engine("test-key", base_url=base, timeout=10) as solver:
            if not accepted:
                with pytest.raises(SolveError) as caught:
                    await solver.solve(
                        type="akamai", url=base + "/page", user_agent=user_agent
                    )
                assert caught.value.code == "solve_failed"
                assert len([p for p in state["posts"] if p == "/sensor"]) == 4
            else:
                response = await solver.solve(
                    type="akamai", url=base + "/page", user_agent=user_agent
                )
                cookies = response["cookies"]
                cookie = next(c for c in cookies if c["name"] == "_abck")
                assert cookie["value"] == "accepted~0~value~-1"
                assert cookie["host_only"] is True and cookie["http_only"] is True
                assert any(
                    c["name"] == "scoped" and c["path"] == "/other" for c in cookies
                )

    asyncio.run(run())


def test_named_session_rejects_identity_changes_and_uses_current_cookie_snapshot(site):
    base, state = site

    async def run():
        async with Engine("test-key", base_url=base, timeout=10) as solver:
            await solver.solve(
                type="akamai", url=base + "/page", user_agent=UA, session="account-1"
            )
            with pytest.raises(SolveError) as caught:
                await solver.solve(
                    type="akamai",
                    url=base + "/page",
                    user_agent=UA + " changed",
                    session="account-1",
                )
            assert caught.value.code == "session_conflict"
            state["require_cookie"] = "_abck=current~-1~value~-1"
            response = await solver.solve(
                type="akamai",
                url=base + "/page",
                session="account-1",
                cookies=[
                    {"name": "_abck", "value": "current~-1~value~-1", "path": "/"}
                ],
            )
            cookies = response["cookies"]
            assert (
                next(c for c in cookies if c["name"] == "_abck")["value"]
                == "accepted~0~value~-1"
            )

    asyncio.run(run())


def test_tmx_preserves_credential_scope_through_full_profile(site):
    base, state = site
    origin = "http://parent.example.test"
    child = "http://child.parent.example.test"

    async def run():
        async def websocket(socket):
            start = json.loads(await socket.recv())
            assert start["tags_url"].endswith("org_id=org&session_id=site-session")
            await socket.send(
                json.dumps(
                    {
                        "type": "hello",
                        "session": "profile-state",
                        "request_id": "tmx-request",
                    }
                )
            )
            targets = ((origin, False), (child, False), (origin, True))
            for index, (target, omit) in enumerate(targets, 1):
                await socket.send(
                    json.dumps(
                        {
                            "type": "http",
                            "id": index,
                            "request": {
                                "role": "collector",
                                "url": target + "/collector",
                                "method": "GET",
                                "headers": {"X-Omit": "yes" if omit else "no"},
                                "body": None,
                                "credentials": "omit" if omit else "include",
                            },
                        }
                    )
                )
                reply = json.loads(await socket.recv())
                assert base64.b64decode(reply["response"]["body"]) == b"collected"
            await socket.send(
                json.dumps({"type": "ready", "request_id": "tmx-request"})
            )
            await socket.send(
                json.dumps({"type": "collected", "request_id": "tmx-request"})
            )
            assert json.loads(await socket.recv())["type"] == "pagehide"
            await socket.send(json.dumps({"type": "pagehide.done"}))
            assert json.loads(await socket.recv()) == {"type": "close"}

        async with serve(websocket, "127.0.0.1", 0) as listener:
            port = listener.sockets[0].getsockname()[1]
            async with Engine(
                "test-key", base_url=f"http://127.0.0.1:{port}", timeout=10
            ) as solver:
                response = await solver.solve(
                    type="threatmetrix",
                    url=origin + "/tmx",
                    user_agent=UA,
                    proxy=base,
                    cookies=[{"name": "auth", "value": "local-secret"}],
                    headers={"Authorization": "Bearer local-secret"},
                )
                cookies = response["cookies"]
        assert {c["name"] for c in cookies} == {"auth", "tmx"}
        included, child_request, omitted = state["target_headers"]
        assert "auth=local-secret" in included["cookie"]
        assert not any(k.lower() in {"cookie", "authorization"} for k in child_request)
        assert not any(k.lower() in {"cookie", "authorization"} for k in omitted)

    asyncio.run(run())
