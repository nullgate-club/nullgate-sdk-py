import asyncio
import json
from hashlib import sha256
from pathlib import Path
from uuid import UUID

import httpx
import pytest

from nullgate import Nullgate, NullgateError
from nullgate.aio import Nullgate as AsyncNullgate

WIRE = json.loads((Path(__file__).parent / "wire.json").read_text())
PROFILE = "00000000-0000-0000-0000-00000000004a"
URL = "https://shop.example/login"
HTML = '<form id="login"><input id="email"></form><script src="/sensor"></script>'
TIMING = {
    "navigationStart": 1800000000000,
    "fetchStart": 1800000000000,
    "responseStart": 1800000000010,
    "responseEnd": 1800000000020,
    "domInteractive": 1800000000021,
    "loadEventEnd": 1800000000022,
}


@pytest.mark.parametrize("operation", ["sensor", "pixel", "sbsd", "fwcim"])
def test_wire_body_matches_schema_and_continues_product_session(api, operation):
    calls, _ = api
    html = HTML
    if operation == "pixel":
        html += (
            '<script>bazadebezolkohpepadr="123"</script>'
            '<script src="/akam/13/abc"></script>'
        )
    elif operation == "sbsd":
        html += '<script src="/guard?v=00000000-0000-0000-0000-000000000001"></script>'
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser", profile=PROFILE).page(URL, html)
        if operation == "fwcim":
            first = page.fwcim(form="#login", timing=TIMING, inputs={})
            second = page.fwcim(form="#login", timing=TIMING, inputs={})
            assert first.metadata1 == second.metadata1 == "generated value"
            expected_extra = {
                "cookies": {},
                "form_selector": "#login",
                "performance_timing": TIMING,
                "submitted": True,
                "referrer": "",
                "inputs": [],
            }
            schema = WIRE["amazon"]["components"]["schemas"]["FwcimRequest"]
            continued = "continued-session"
        else:
            method = getattr(page, operation)
            kwargs = {"script": "observed script"}
            if operation != "pixel":
                kwargs["cookies"] = {
                    "_abck": "a",
                    "bm_sz": "b",
                    "sbsd": "c",
                    "bm_so": "so",
                    "sbsd_o": "o",
                    "bm_s": "s",
                    "unrelated": "secret",
                }
            first, second = method(**kwargs), method(**kwargs)
            assert first.body == second.body == "generated"
            assert first.url == "https://shop.example/verify"
            assert list(first.headers.items()) == [
                ("content-type", "text/plain;charset=UTF-8"),
                ("origin", "https://shop.example"),
                ("referer", URL),
            ]
            assert "generated" not in repr(first)
            expected_extra = {
                "script": "observed script",
                "script_url": getattr(page, operation + "_url"),
            }
            if operation == "sensor":
                expected_extra["cookies"] = {"_abck": "a", "bm_sz": "b"}
            elif operation == "sbsd":
                expected_extra["cookies"] = {"bm_so": "so", "sbsd_o": "o", "bm_s": "s"}
            else:
                expected_extra["challenge"] = "123"
            schema = WIRE["akamai"]["components"]["schemas"][
                operation.title() + "Request"
            ]
            continued = "akamai-session"
        bodies = [json.loads(request.content) for request in calls]
        common = {
            "profile": PROFILE,
            "session": None,
            "user_agent": "browser",
            "url": URL,
            "html": html,
            "document_id": bodies[0]["document_id"],
            "started_at_ms": TIMING["navigationStart"]
            if operation == "fwcim"
            else bodies[0]["started_at_ms"],
        }
        UUID(common["document_id"])
        assert common["started_at_ms"] > 0
        assert bodies[0] == {**common, **expected_extra}
        assert bodies[1] == {**common, **expected_extra, "session": continued}
        assert set(bodies[0]) <= set(schema["properties"])
        assert set(schema["required"]) <= set(bodies[0])
        assert calls[0].url.path == (
            "/amazon/fwcim" if operation == "fwcim" else "/akamai/" + operation
        )
        assert calls[0].headers["Authorization"] == "Bearer test-key"
        assert "X-State-ID" not in calls[0].headers


def test_product_continuations_are_independent_and_pages_keep_document_identity(api):
    calls, _ = api
    with Nullgate("test-key") as ng:
        session = ng.session(user_agent="browser")
        page = session.page(URL, HTML)
        page.sensor(script="source", cookies={})
        page.fwcim(form="#login", timing=TIMING, inputs={})
        page.sensor(script="source", cookies={})
        session.page(URL, HTML).sensor(script="source", cookies={})
    bodies = [json.loads(request.content) for request in calls]
    assert [body["session"] for body in bodies] == [
        None,
        None,
        "akamai-session",
        "akamai-session",
    ]
    assert (
        bodies[0]["document_id"] == bodies[2]["document_id"] != bodies[3]["document_id"]
    )
    assert len({body["profile"] for body in bodies}) == 1


def test_sync_and_async_share_surface_and_account_queries(api):
    calls, _ = api

    async def run():
        async with AsyncNullgate("test-key") as ng:
            request = (
                await ng.session(user_agent="browser")
                .page(URL, HTML)
                .sensor(script="source", cookies={})
            )
            await request.wait()
            account = await ng.account()
            usage = await ng.usage(
                interval="day", start="2026-11-01T00:00:00Z", end="2026-11-02T00:00:00Z"
            )
            return request, account, usage

    request, account, usage = asyncio.run(run())
    assert request.body == "generated"
    assert account["balance"] == "1.000000"
    assert usage["buckets"] == []
    assert dict(calls[-1].url.params) == {
        "interval": "day",
        "start": "2026-11-01T00:00:00Z",
        "end": "2026-11-02T00:00:00Z",
    }


@pytest.mark.parametrize(
    "status,code",
    [
        (400, "invalid_request"),
        (401, "invalid_key"),
        (402, "insufficient_balance"),
        (403, "forbidden"),
        (404, "not_found"),
        (409, "session_busy"),
        (429, "rate_limited"),
        (500, "internal"),
        (502, "upstream"),
        (503, "unavailable"),
        (503, "maintenance"),
        (400, "invalid_page"),
        (400, "future_code"),
    ],
)
def test_every_error_code_preserves_public_fields_without_retry(api, status, code):
    calls, replies = api
    replies.append(
        (
            status,
            {"code": code, "message": "Safe explanation", "request_id": "support-id"},
            {},
        )
    )
    with Nullgate("test-key") as ng, pytest.raises(NullgateError) as error:
        ng.account()
    assert (
        error.value.code,
        error.value.message,
        error.value.request_id,
        error.value.status,
    ) == (code, "Safe explanation", "support-id", status)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "count,retry_after,code,expected",
    [
        (2, "0", "maintenance", 3),
        (3, "0", "maintenance", 3),
        (1, "999", "maintenance", 1),
        (1, "bad", "maintenance", 1),
        (1, "0", "unavailable", 1),
        (1, "nan", "maintenance", 1),
    ],
)
def test_maintenance_retry_bounds(api, count, retry_after, code, expected):
    calls, replies = api
    replies.extend(
        (
            503,
            {"code": code, "message": "Wait", "request_id": "id"},
            {"Retry-After": retry_after},
        )
        for _ in range(count)
    )
    with Nullgate("test-key", timeout=1) as ng:
        if count == 2 and code == "maintenance" and retry_after == "0":
            assert ng.account()["currency"] == "USD"
        else:
            with pytest.raises(NullgateError, match="Wait"):
                ng.account()
    assert len(calls) == expected


@pytest.mark.parametrize(
    "text,length,hash31,trimmed_hash31,trimmed_length",
    [
        ("", 0, 0, 0, 0),
        ("A_9 😀İ\u00a0", 8, -902761640, 386520648, 7),
        ("\u0085\ufeff", 2, 69402, 133, 1),
        (" \0 ", 3, 30784, 0, 1),
        ("\ud800", 1, 55296, 55296, 1),
    ],
)
def test_v1_utf16_summaries_survive_public_input_preparation(
    api, text, length, hash31, trimmed_hash31, trimmed_length
):
    calls, _ = api
    with Nullgate("test-key") as ng:
        ng.session(user_agent="browser").page(URL, HTML).sensor(
            script="source", cookies={}, inputs={"email": text}
        )
    observation = json.loads(calls[0].content)["inputs"][0]
    assert observation["attributes"] == {"id": "email"}
    assert (
        observation["value"]["hash"]
        == sha256(text.encode("utf-16-le", "surrogatepass")).hexdigest()
    )
    assert tuple(
        observation["value"][key]
        for key in ("length", "hash31", "trimmed_hash31", "trimmed_length")
    ) == (length, hash31, trimmed_hash31, trimmed_length)
    assert "checksum" not in observation


@pytest.mark.parametrize(
    "control",
    [
        '<input id="password" value="secret">',
        '<input type="password" value="secret">',
        '<input autocomplete="new-password" value="secret">',
        '<input type="password" value="" value="secret">',
        '<textarea name="ap_password">secret</textarea>',
    ],
)
def test_password_html_is_refused_before_any_api_call(api, control):
    calls, _ = api
    with Nullgate("test-key") as ng, pytest.raises(NullgateError) as error:
        ng.session(user_agent="browser").page(URL, control)
    assert error.value.code == "invalid_page"
    assert not calls


@pytest.mark.parametrize(
    "action,rejected",
    [
        ({"type": "input", "value": "private"}, True),
        ({"type": "change", "value": "private"}, True),
        ({"type": "click", "value": "private"}, True),
        ({"type": "custom", "value": ""}, True),
        ({"value": "private"}, True),
        ({"type": "click"}, False),
        ({"type": "click", "value": None}, False),
        ({"type": "click", "value": 0}, False),
        ({"type": "input", "value": {"length": 0, "hash": "0" * 64}}, False),
    ],
)
def test_sensor_rejects_string_action_values_for_any_event(api, action, rejected):
    calls, _ = api
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML)
        if rejected:
            with pytest.raises(NullgateError) as error:
                page.sensor(script="source", cookies={}, actions=[action])
            assert error.value.code == "invalid_actions"
            assert not calls
        else:
            page.sensor(script="source", cookies={}, actions=[action])
            assert json.loads(calls[0].content)["actions"] == [action]


def test_amazon_observation_retains_v1_checksum_and_name_resolution(api):
    calls, _ = api
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(
            URL, '<form id="login"><input name="email"></form>'
        )
        page.fwcim(
            form="#login",
            timing=TIMING,
            inputs={"email": "hello"},
            cookies={"session-id": "visit", "unrelated": "private"},
        )
    body = json.loads(calls[0].content)
    assert body["cookies"] == {"session-id": "visit"}
    assert body["inputs"][0]["checksum"] == 907060870
    assert body["inputs"][0]["attributes"] == {"name": "email"}
    assert "hello" not in calls[0].content.decode()


def test_cookie_jar_selects_target_domain_path_and_secure_cookies(api):
    calls, _ = api
    jar = httpx.Cookies()
    jar.set("_abck", "correct", domain="shop.example", path="/")
    jar.set("_abck", "other-host", domain="other.example", path="/")
    jar.set("bm_sz", "wrong-path", domain="shop.example", path="/other")
    jar.set("unrelated", "secret", domain="shop.example")
    with Nullgate("test-key") as ng:
        ng.session(user_agent="browser").page(URL, HTML).sensor(
            script="source", cookies=jar
        )
    assert json.loads(calls[0].content)["cookies"] == {"_abck": "correct"}


@pytest.mark.parametrize("operation", ["sensor", "fwcim"])
def test_raw_observation_arrays_preserve_selectors_and_optional_canvas_facts(
    api, operation
):
    calls, _ = api
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML)
        field = {"selector": "#email", "value": "hello"}
        if operation == "sensor":
            field["type"] = "email"
            page.sensor(script="source", cookies={}, inputs=[field])
        else:
            field.update(geometry={"width": 120, "height": 30}, text="hello")
            page.fwcim(form="#login", timing=TIMING, inputs=[field])
    observation = json.loads(calls[0].content)["inputs"][0]
    assert observation["selector"] == "#email"
    assert observation["value"]["length"] == 5
    if operation == "sensor":
        assert observation["attributes"] == {"type": "email"}
        assert "text" not in observation and "checksum" not in observation
    else:
        assert observation["geometry"] == {"width": 120, "height": 30}
        assert observation["text"] == "hello"
        assert observation["checksum"] == 907060870


@pytest.mark.parametrize(
    "kwargs",
    [
        {"form": "#missing"},
        {"form": "#email"},
        {"form": "["},
        {"timing": {"navigationStart": 0}},
        {"timing": {"navigationStart": 100, "responseEnd": 99}},
        {"timing": {"navigationStart": 100, "responseEnd": True}},
        {"inputs": [{"id": "email", "value": "hello", "text": "different"}]},
        {
            "inputs": [
                {
                    "id": "email",
                    "value": "hello",
                    "geometry": {"width": -1, "height": 1},
                }
            ]
        },
        {
            "inputs": [
                {
                    "id": "email",
                    "value": "hello",
                    "geometry": {"width": float("nan"), "height": 1},
                }
            ]
        },
        {"inputs": [{"id": "email", "value": "hello", "unexpected": "private"}]},
        {"inputs": [{"selector": ".missing", "value": "hello"}]},
        {"actions": [{"type": "input", "value": "private"}]},
        {"actions": [{"type": "click", "unexpected": "private"}]},
        {"actions": [{"type": "click", "x": float("inf")}]},
        {"actions": [{"type": "touchstart", "touches": [{"x": 0, "y": None}]}]},
        {"actions": [{"type": "input", "input_summary": [1, [0, 0, -1, 0]]}]},
    ],
)
def test_v1_amazon_guards_reject_invalid_observations_before_network(api, kwargs):
    calls, _ = api
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML)
        with pytest.raises(NullgateError):
            page.fwcim(**{"form": "#login", "timing": TIMING, "inputs": {}, **kwargs})
    assert not calls


@pytest.mark.parametrize(
    "counts_text,counts",
    [
        ("AZaz09_ !", [9, 1, 4, 2]),
        ("ÉİKß😀\ud800", [7, 7, 2, 0]),
        (
            "_ \t\n\u00a0\u1680\u2000\u200a\u2028\u2029\u202f\u205f\u3000\ufeff",
            [14, 0, 0, 0],
        ),
        ("\u0085\u001c\u001d\u001e\u001f", [5, 5, 0, 0]),
    ],
)
def test_v1_input_category_counts_match_unicode_boundaries(api, counts_text, counts):
    calls, _ = api
    with Nullgate("test-key") as ng:
        ng.session(user_agent="browser").page(URL, HTML).sensor(
            script="source", cookies={}, inputs={"email": counts_text}
        )
    assert json.loads(calls[0].content)["inputs"][0]["value"]["counts"] == counts


@pytest.mark.parametrize(
    "operation,change",
    [
        (operation, change)
        for operation in ("sensor", "fwcim")
        for change in (
            {"headers": {"bad": 1}},
            {"send_at": True},
            {"send_at": float("nan")},
            {"send_at": "123"},
            {"session": None},
            {"request_id": ""},
            *(
                [{"body": 1}, {"url": "file:///etc/passwd"}]
                if operation == "sensor"
                else [{"metadata1": 123}]
            ),
        )
    ],
)
def test_malformed_generation_is_rejected_without_continuation(api, operation, change):
    calls, replies = api
    response = {"headers": {}, "send_at": 0, "body": "generated", "url": URL}
    data = {"session": "must-not-be-saved", "request_id": "id"}
    if operation == "fwcim":
        data.update(metadata1="metadata", headers={}, send_at=0)
        data.update(change)
    else:
        response.update(
            {
                key: value
                for key, value in change.items()
                if key not in ("session", "request_id")
            }
        )
        data.update(request=response)
        data.update(
            {
                key: value
                for key, value in change.items()
                if key in ("session", "request_id")
            }
        )
    replies.append((200, data, {}))
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML)
        with pytest.raises(NullgateError) as error:
            if operation == "sensor":
                page.sensor(script="source", cookies={})
            else:
                page.fwcim(form="#login", timing=TIMING, inputs={})
        assert error.value.code == "invalid_response"
        if operation == "sensor":
            page.sensor(script="source", cookies={})
        else:
            page.fwcim(form="#login", timing=TIMING, inputs={})
    assert json.loads(calls[-1].content)["session"] is None


def test_api_key_environment_fallback_and_explicit_key_precedence(api, monkeypatch):
    calls, _ = api
    monkeypatch.setenv("NULLGATE_API_KEY", "environment-key")
    with Nullgate() as ng:
        ng.account()
    with Nullgate("explicit-key") as ng:
        ng.account()
    assert [request.headers["Authorization"] for request in calls] == [
        "Bearer environment-key",
        "Bearer explicit-key",
    ]


@pytest.mark.parametrize(
    "kwargs,code",
    [
        ({"api_key": ""}, "invalid_key"),
        ({"api_key": "bad\nkey"}, "invalid_key"),
        ({"api_key": "test-key", "base_url": "file:///tmp"}, "invalid_url"),
        (
            {"api_key": "test-key", "base_url": "https://key:secret@example.com"},
            "invalid_url",
        ),
        ({"api_key": "test-key", "timeout": 0}, "invalid_request"),
        ({"api_key": "test-key", "timeout": float("inf")}, "invalid_request"),
    ],
)
def test_local_client_validation_uses_nullgate_error(kwargs, code):
    with pytest.raises(NullgateError) as error:
        Nullgate(**kwargs)
    assert error.value.code == code


def test_missing_key_is_rejected_before_allocating_transport(monkeypatch):
    monkeypatch.delenv("NULLGATE_API_KEY", raising=False)
    with pytest.raises(NullgateError) as error:
        Nullgate()
    assert error.value.code == "invalid_key"


@pytest.mark.parametrize("product", ["sensor", "threatmetrix"])
def test_closed_async_client_refuses_new_network_work(api, product):
    calls, _ = api

    async def run():
        ng = AsyncNullgate("test-key")
        page = ng.session(user_agent="browser").page(URL, HTML)
        await ng.aclose()
        with pytest.raises(NullgateError) as error:
            if product == "sensor":
                await page.sensor(script="source", cookies={})
            else:
                async with page.threatmetrix(
                    send=lambda request: None,
                    script_url="https://risk.example/tags.js?org_id=o&session_id=s",
                ):
                    pytest.fail("Closed client started a profile")
        assert error.value.code == "closed"

    asyncio.run(run())
    assert not calls


@pytest.mark.parametrize(
    "operation,selected",
    [
        ("sensor", {"_abck", "bm_sz"}),
        ("sbsd", {"bm_so", "sbsd_o", "bm_s"}),
        ("fwcim", {"session-id", "session-token", "ubid-main"}),
    ],
)
@pytest.mark.parametrize("jar", [False, True])
def test_cookie_selection_matches_server_and_v1_contract(api, operation, selected, jar):
    calls, _ = api
    observed = {
        name: f"observed-{name}"
        for name in (
            "_abck",
            "bm_sz",
            "bm_so",
            "sbsd_o",
            "bm_s",
            "sbsd",
            "_sbsd",
            "session-id",
            "session-token",
            "ubid-main",
            "authentication",
        )
    }
    cookies = observed
    if jar:
        cookies = httpx.Cookies()
        for name, value in observed.items():
            cookies.set(name, value, domain="shop.example", path="/")
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML)
        if operation == "fwcim":
            page.fwcim(form="#login", timing=TIMING, inputs={}, cookies=cookies)
        else:
            getattr(page, operation)(
                script="source", script_url="/protection", cookies=cookies
            )
    assert json.loads(calls[0].content)["cookies"] == {
        name: observed[name] for name in selected
    }
