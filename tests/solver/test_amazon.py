"""Exercise ACIC paid-stage limits and continuation over real HTTP."""

import asyncio
import gzip
import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import pytest

from nullgate import acic
from nullgate.solver.engine import Engine
from nullgate.solver.models import SolveError
from nullgate.solver.transport import Transport

UA = "Mozilla/5.0 Chrome/154.0.0.0"
POW = "PROOF_OF_WORK_LEVEL_3"
WAF = "WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_2"
HTML = """<script>acic.setupACIC({
 "data-ref-id":"cvf", "data-challenge-type":"POW", "data-context":"ctx",
 "data-locale":"en-GB", "data-iframe-id":"frame", "data-external-id":"id",
 "data-host-config":"prod.EUAmazon"});</script>
 <form id="cvf-aamation-challenge-form" method="post" action="/continue">
 <input type="hidden" name="same" value="one"><input type="hidden" name="same" value="">
 <input type="hidden" name="cvf_aamation_response_token" value="old"></form>"""
WAF_HTML = """<script src="https://captcha.awswaf.com/a/captcha.js"></script>
<script>const wafInputProperties = Object.assign({"problem":"grid-v2",
"visualSolutionsRequired":%d,"defaultLocale":"en-GB","id":"id"},
wafOnLoadProperty);</script>"""


@pytest.fixture
def site(monkeypatch):
    state = {"rounds": 2, "mode": "pass", "pow": 0, "waf": 0, "page": 0, "verified": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, body=b"", status=200, headers=()):
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def result(self, kind, body=b""):
            value = json.dumps(
                {
                    "actionType": kind,
                    "clientSideContext": "ctx",
                    "sessionToken": "token",
                }
            )
            self.reply(body, headers=[("amz-aamation-resp", value)])

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/challenge":
                state["page"] += 1
                self.reply(HTML.encode())
            elif path == "/a/problem":
                self.reply(
                    json.dumps(
                        {"state": "one", "key": "key", "hmac_tag": "tag"}
                    ).encode()
                )
            elif path == "/done":
                self.reply(b"done", headers=[("Set-Cookie", "done=yes; Path=/")])
            else:
                self.reply(status=404)

        def do_POST(self):
            path = urlsplit(self.path).path
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            if path == "/amazon/acic/pow":
                state["pow"] += 1
                self.reply(
                    json.dumps(
                        {"response": "proof", "request_id": "pow", "send_at": 0}
                    ).encode()
                )
            elif path == "/amazon/acic/waf":
                state["waf"] += 1
                self.reply(
                    json.dumps({"client_solution": [1], "request_id": "waf"}).encode()
                )
            elif path == "/aaut/verify/cvf":
                self.result(POW, b"pow challenge")
            elif path == "/aaut/verify/cvf/token":
                data = json.loads(body)
                if data["response"] == "proof":
                    kind = POW if state["mode"] == "repeat-stage" else WAF
                    self.result(kind, (WAF_HTML % state["rounds"]).encode())
                else:
                    assert json.loads(data["response"])["data"] == '"voucher"'
                    self.result("PASS")
            elif path == "/a/verify":
                assert not self.headers.get("Authorization")
                assert not self.headers.get("Cookie")
                state["verified"] += 1
                if state["mode"] == "reject":
                    result = {"success": False}
                elif state["verified"] == state["rounds"]:
                    result = {"captcha_voucher": "voucher"}
                else:
                    next_state = (
                        "one"
                        if state["mode"] == "repeat-problem"
                        else str(state["verified"])
                    )
                    result = {
                        "success": True,
                        "problem": {
                            "state": next_state,
                            "key": "key",
                            "hmac_tag": "tag",
                        },
                    }
                self.reply(json.dumps(result).encode())
            elif path == "/continue":
                assert parse_qsl(body.decode(), keep_blank_values=True) == [
                    ("same", "one"),
                    ("same", ""),
                    ("cvf_aamation_response_token", "token"),
                ]
                self.reply(status=303, headers=[("Location", "/done")])
            else:
                self.reply(status=404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    original_origin = acic._origin
    original_discover = acic.discover
    original_request = Transport.request

    def origin(url):
        return base if url.startswith(base) else original_origin(url)

    def discover(url, html):
        setup = original_discover(url, html)
        return replace(setup, service_url=base + "/aaut/verify/cvf") if setup else None

    async def request(self, method, url, **kwargs):
        if url.startswith("https://captcha.awswaf.com/"):
            url = (
                base
                + urlsplit(url).path
                + ("?" + urlsplit(url).query if urlsplit(url).query else "")
            )
        return await original_request(self, method, url, **kwargs)

    monkeypatch.setattr(acic, "_origin", origin)
    monkeypatch.setattr(acic, "discover", discover)
    monkeypatch.setattr(Transport, "request", request)
    try:
        yield base, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("rounds", [2, 3])
@pytest.mark.parametrize("supplied", [False, True])
def test_acic_completes_policy_and_continues(site, rounds, supplied):
    base, state = site
    state["rounds"] = rounds

    async def run():
        async with Engine("key", base_url=base) as engine:
            return await engine.solve(
                type="amazon_acic",
                url=base + "/challenge",
                user_agent=UA,
                html=HTML if supplied else None,
                headers={"Authorization": "secret"},
            )

    result = asyncio.run(run())
    assert result["result"] == {
        "status": "PASS",
        "url": base + "/done",
        "status_code": 200,
    }
    assert any(cookie["name"] == "done" for cookie in result["cookies"])
    assert (state["page"], state["pow"], state["waf"], state["verified"]) == (
        0 if supplied else 1,
        1,
        rounds,
        rounds,
    )


@pytest.mark.parametrize(
    ("mode", "waf_calls"), [("repeat-stage", 0), ("reject", 1), ("repeat-problem", 1)]
)
def test_acic_stops_before_repeated_paid_work(site, mode, waf_calls):
    base, state = site
    state["mode"] = mode

    async def run():
        async with Engine("key", base_url=base) as engine:
            with pytest.raises(SolveError):
                await engine.solve(
                    type="amazon_acic", url=base + "/challenge", user_agent=UA
                )

    asyncio.run(run())
    assert state["pow"] == 1
    assert state["waf"] == waf_calls
