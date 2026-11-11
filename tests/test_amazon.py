import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event
from typing import cast
from zlib import crc32

import httpx
import pytest

from nullgate import NullgateAPIError, NullgateClient, NullgateClientAsync, Page
from nullgate.akamai import Sensor, SensorParams
from nullgate.amazon import (
    FwcimParams,
    FwcimSolution,
    FwcimSolutionAsync,
    InputObservation,
    _payload,
    observe_input,
)

IDENTITY = "a07aad50-f262-40b1-b187-11532c054bc0"
PAGE = Page(
    "https://example.com/ap/signin",
    '<form id="signin"><input id="email" name="email">'
    '<input id="secret" type="PASSWORD"><textarea name="note"></textarea></form>',
    started_at_ms=1000,
)
PARAMS = FwcimParams(PAGE, {"navigationStart": 1000})
DATA = {"metadata1": "sensitive+metadata%", "send_at": 1.5, "headers": {"X": "Y"}}


def test_observation_summarizes_cesu8_and_optional_canvas_text() -> None:
    observation = observe_input(PAGE, "é🔑", id="email")
    assert observation["checksum"] == crc32(bytes.fromhex("c3a9eda0bdedb491"))
    assert observation["value"]["length"] == 3
    assert "checksum" not in observation["value"]
    assert "text" not in observation
    assert "é🔑" not in repr(observation)
    assert observe_input(PAGE, "note", name="note", include_text=True)["text"] == "note"


@pytest.mark.parametrize(
    "attributes",
    [
        {"id": "secret"},
        {"name": "email", "selector": "#secret"},
        {"selector": "#secret"},
        {"selector": "form"},
        {"selector": "input"},
        {"selector": "["},
        {"id": "missing"},
    ],
)
def test_dom_validation_rejects_passwords_and_bad_identity(attributes: dict) -> None:
    with pytest.raises(ValueError) as error:
        observe_input(PAGE, "never-echo-password", **attributes)
    assert "never-echo-password" not in str(error.value)


def test_selectors_disambiguate_without_bypassing_identity() -> None:
    page = Page(PAGE.url, '<input name="same"><input name="same">')
    with pytest.raises(ValueError):
        observe_input(page, "value", name="same")
    value = observe_input(page, "value", name="same", selector="input:nth-of-type(2)")
    assert value["selector"] == "input:nth-of-type(2)"
    with pytest.raises(ValueError):
        observe_input(page, "value", name="other", selector="input:nth-of-type(2)")


@pytest.mark.parametrize("asynchronous", [False, True])
def test_generation_routes_state_and_preserves_absent_observations(asynchronous: bool):
    requests: list[httpx.Request] = []
    results: list[FwcimSolution | FwcimSolutionAsync] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        amazon = request.url.params["type"] == "fwcim"
        return httpx.Response(
            200,
            headers={
                "X-State-ID": "amazon-state" if amazon else "akamai-state",
                "X-Request-ID": "request-id",
            },
            json=DATA if amazon else {"sensor_data": "sensor", **DATA},
        )

    sensor = SensorParams(Sensor(PAGE, "https://example.com/opaque"), "source")
    params = replace(
        PARAMS,
        inputs=[observe_input(PAGE, "test@example.com", id="email")],
        actions=[],
        referrer="https://example.com/",
        history_length=2,
    )
    transport = httpx.MockTransport(handler)
    if asynchronous:

        async def run() -> None:
            async with NullgateClientAsync("key", transport=transport) as client:
                async with client.open(identity=IDENTITY, user_agent="UA") as session:
                    await session.solve(sensor)
                    results.append(await session.fwcim(params))
                    results.append(await session.fwcim(PARAMS))
                    results.append(await session.fwcim(replace(PARAMS, inputs=[])))
                    await session.solve(sensor)
                    await results[-1].wait()
                with pytest.raises(RuntimeError):
                    await session.fwcim(PARAMS)

        asyncio.run(run())
    else:
        with NullgateClient("key", transport=transport) as client:
            with client.open(identity=IDENTITY, user_agent="UA") as session:
                session.solve(sensor)
                results.append(session.fwcim(params))
                results.append(session.fwcim(PARAMS))
                results.append(session.fwcim(replace(PARAMS, inputs=[])))
                session.solve(sensor)
                results[-1].wait()
            with pytest.raises(RuntimeError):
                session.fwcim(PARAMS)
    assert requests[1].url.host == "amazon.nullgate.club"
    assert requests[1].url.path == f"/v1/{IDENTITY}/generate"
    assert requests[1].headers["X-State-ID"] != "akamai-state"
    assert requests[2].headers["X-State-ID"] == "amazon-state"
    assert requests[-1].headers["X-State-ID"] == "akamai-state"
    assert requests[1].headers["Authorization"] == "Bearer key"
    assert requests[1].headers["User-Agent"] == "UA"
    assert requests[1].headers["X-Nullgate-Error-Format"] == "1"
    body = json.loads(requests[1].content)
    assert body["website"]["document_id"] == PAGE.document_id
    assert body["website"]["started_at_ms"] == 1000
    assert body["website"]["history_length"] == 2
    assert body["actions"] == []
    assert "test@example.com" not in requests[1].content.decode()
    assert "inputs" not in json.loads(requests[2].content)
    assert "actions" not in json.loads(requests[2].content)
    assert json.loads(requests[3].content)["inputs"] == []
    assert results[0].metadata1 == DATA["metadata1"]
    assert results[0].request_id == "request-id"
    assert DATA["metadata1"] not in repr(results[0])


@pytest.mark.parametrize(
    "body,headers",
    [
        ([], {"X-Request-ID": "id"}),
        ({**DATA, "metadata1": 1}, {"X-Request-ID": "id"}),
        ({**DATA, "send_at": True}, {"X-Request-ID": "id"}),
        ({**DATA, "send_at": "nan"}, {"X-Request-ID": "id"}),
        ({**DATA, "headers": {"X": 1}}, {"X-Request-ID": "id"}),
        (DATA, {}),
    ],
)
def test_response_validation(body: object, headers: dict[str, str]) -> None:
    with NullgateClient(
        "key",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json=body, headers=headers)
        ),
    ) as client:
        with client.open(identity=IDENTITY, user_agent="UA") as session:
            with pytest.raises(ValueError):
                session.fwcim(PARAMS)


def test_privacy_validation_happens_before_transport() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=DATA, headers={"X-Request-ID": "id"})

    unsafe_page = Page(PAGE.url, '<input type="password" value="never-transport">')
    tampered = cast(
        InputObservation,
        {
            "attributes": {"id": "secret"},
            "value": {"length": 1, "hash": "0" * 64},
            "text": "never-transport",
        },
    )
    invalid = [
        replace(PARAMS, page=unsafe_page),
        replace(PARAMS, performance_timing={"navigationStart": 999}),
        replace(PARAMS, inputs=[tampered]),
        replace(PARAMS, actions=[{"type": "input", "value": "never-transport"}]),
    ]
    with NullgateClient("key", transport=httpx.MockTransport(handler)) as client:
        with client.open(identity=IDENTITY, user_agent="UA") as session:
            for params in invalid:
                with pytest.raises((TypeError, ValueError)) as error:
                    session.fwcim(params)
                assert "never-transport" not in str(error.value)
    assert requests == []


def test_custom_endpoint_and_original_public_api_error() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(422, json={"detail": "invalid observations"})

    with NullgateClient(
        "key",
        amazon_base_url="https://amazon-api.example/",
        transport=httpx.MockTransport(handler),
    ) as client:
        with client.open(identity=IDENTITY, user_agent="UA") as session:
            with pytest.raises(NullgateAPIError) as error:
                session.fwcim(PARAMS)
            assert error.value.status_code == 422
    assert requests[0].url.host == "amazon-api.example"


@pytest.mark.parametrize(
    "html",
    [
        '<input type="password" value="must-stay-local">',
        '<input type="PASSWORD" type="text" value="must-stay-local">',
        '<input type="password" value="&#109;ust-stay-local">',
        '<input type=" \tPaSsWoRd\n " value="must-stay-local">',
        '<input type="password" value="" value="must-stay-local">',
        '<input type="password" value="must-stay-local" value="">',
        '<input type="password" value="" value="&#109;ust-stay-local" value="">',
    ],
)
def test_html_password_values_are_rejected_without_echo(html: str) -> None:
    with pytest.raises(ValueError) as error:
        observe_input(Page(PAGE.url, html), "value", selector="input")
    assert "must-stay-local" not in str(error.value)
    page = Page(PAGE.url, html, started_at_ms=1000)
    with pytest.raises(ValueError, match="password values"):
        _payload(FwcimParams(page, {"navigationStart": 1000}), None)


@pytest.mark.parametrize("input_type", ["PASSWORD", " password ", "\tPaSsWoRd\n"])
def test_password_summary_is_allowed_but_raw_observation_is_not(
    input_type: str,
) -> None:
    page = Page(
        PAGE.url,
        f'<form id="signin"><input id="secret" type="{input_type}"></form>',
        started_at_ms=1000,
    )
    with pytest.raises(ValueError, match="Raw password"):
        observe_input(page, "must-stay-local", id="secret")
    observation: InputObservation = {
        "attributes": {"id": "secret"},
        "value": {
            "length": 2,
            "hash": "0" * 64,
            "counts": (2, 0, 2, 0),
            "hash31": 3104,
            "trimmed_hash31": 3104,
            "trimmed_length": 2,
        },
    }
    params = replace(PARAMS, page=page, inputs=[observation], form_selector="#signin")
    assert _payload(params, None)["inputs"] == [observation]
    for key, value in (("text", "must-stay-local"), ("checksum", 123)):
        with pytest.raises(ValueError, match="Password text"):
            _payload(
                replace(
                    params, inputs=[cast(InputObservation, {**observation, key: value})]
                ),
                None,
            )


@pytest.mark.parametrize("selector", ["", "[", "input", "form", "#missing", "#outside"])
def test_explicit_form_must_select_one_form_and_contain_inputs(selector: str) -> None:
    page = Page(
        PAGE.url,
        '<form id="inside"><input id="email"></form><form id="outside"></form>',
        started_at_ms=1000,
    )
    params = replace(
        PARAMS,
        page=page,
        form_selector=selector,
        inputs=[observe_input(page, "value", id="email")],
    )
    with pytest.raises(ValueError):
        _payload(params, None)
    assert (
        _payload(replace(params, form_selector="#inside"), None)["form_selector"]
        == "#inside"
    )


def test_nonzero_timing_cannot_precede_navigation_start() -> None:
    for timestamp in (0, 1000, 1001):
        timing = {"navigationStart": 1000, "loadEventEnd": timestamp}
        assert (
            _payload(replace(PARAMS, performance_timing=timing), None)[
                "performance_timing"
            ]
            == timing
        )
    with pytest.raises(ValueError, match="must not precede"):
        _payload(
            replace(
                PARAMS,
                performance_timing={"navigationStart": 1000, "loadEventEnd": 999},
            ),
            None,
        )


@pytest.mark.parametrize(
    "action",
    [
        {"type": {"text": "must-stay-local"}},
        {"target_path": {"value": "must-stay-local"}},
        {"pointer_type": ["must-stay-local"]},
        {"target": True},
        {"trusted": "must-stay-local"},
        {"shift": 1},
        {"x": "must-stay-local"},
        {"time": True},
        {"interval": float("inf")},
        {"touches": [{"x": 1, "y": 2, "value": "must-stay-local"}]},
        {"touches": [{"x": {"value": "must-stay-local"}}]},
        {"touches": {"x": 1}},
        {"acceleration": {"x": "must-stay-local"}},
        {"acceleration_with_gravity": {"x": 1, "text": "must-stay-local"}},
        {"rotation_rate": [1, 2]},
        {"rotation_rate": [1, 2, 3, 4]},
        {"rotation_rate": [1, True, 3]},
        {"rotation_rate": [1, float("nan"), 3]},
        {"acceleration": [1, {"text": "must-stay-local"}, 3]},
        {"acceleration": {"x": 1, "y": 2, "z": 3}},
        {"rotation_rate": {"x": 1}},
        {"input_summary": {"length": 1, "hash": "0" * 64}},
        {"input_summary": [1, [1, 0, 0, "must-stay-local"]]},
        {"input_summary": [True, None]},
        {"input_summary": [1, [-1, 0, 0, 0]]},
    ],
)
def test_nested_action_shapes_reject_raw_payloads_before_transport(
    action: dict,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise AssertionError("Invalid action reached transport")

    with NullgateClient("key", transport=httpx.MockTransport(handler)) as client:
        with client.open(identity=IDENTITY, user_agent="UA") as session:
            with pytest.raises((TypeError, ValueError)) as error:
                session.fwcim(replace(PARAMS, actions=[action]))
            assert "must-stay-local" not in str(error.value)
    assert requests == []


def test_action_shapes_allow_public_redacted_facts() -> None:
    actions = [
        {
            "type": "input",
            "time": 0,
            "target": 1,
            "target_path": "#email",
            "trusted": True,
            "input_summary": [2, [2, 0, 2, 0]],
        },
        {"type": "touchstart", "touches": [{"x": 1.5, "y": 2, "identifier": 1}]},
        {
            "type": "devicemotion",
            "acceleration": [1, None, 2],
            "acceleration_with_gravity": None,
            "rotation_rate": (1, None, 2),
        },
        {"type": "change", "input_summary": [0, None]},
    ]
    assert _payload(replace(PARAMS, actions=actions), None)["actions"] == actions


@pytest.mark.parametrize(
    "html,selector,accepted",
    [
        (
            '<form id="a"><input id="email" form="b"></form><form id="b"></form>',
            "#a",
            True,
        ),
        ('<form id="a"></form><input id="email" form="a">', "#a", False),
        ('<form id="a"><form id="b"><input id="email"></form></form>', "#a", True),
        (
            '<form><input id="email"></form><form><input id="email"></form>',
            "form:nth-of-type(2)",
            True,
        ),
        (
            '<form><input id="email"></form><form><input id="email"></form>',
            "form:nth-of-type(1)",
            False,
        ),
    ],
)
def test_profiler_uses_descendants_and_node_identity(
    html: str, selector: str, accepted: bool
) -> None:
    page = replace(PAGE, html=html)
    input_selector = (
        "form:nth-of-type(2) input" if html.count("<input") == 2 else "input"
    )
    observation = observe_input(page, "value", selector=input_selector)
    params = replace(PARAMS, page=page, inputs=[observation], form_selector=selector)
    if accepted:
        assert _payload(params, None)["inputs"] == [observation]
    else:
        with pytest.raises(ValueError, match="inside"):
            _payload(params, None)


@pytest.mark.parametrize(
    "attributes",
    [
        'type="text" autocomplete="section-login current-password"',
        'autocomplete=" NEW-PASSWORD "',
        'id=" AP_PASSWORD "',
        'name=" PaSsWoRd "',
    ],
)
def test_password_markers_apply_to_html_helpers_and_explicit_observations(
    attributes: str,
) -> None:
    for populated in (False, True):
        page = replace(
            PAGE,
            html=f"<input {attributes}"
            + (' value="must-stay-local">' if populated else ">"),
        )
        with pytest.raises(ValueError) as error:
            observe_input(page, "must-stay-local", selector="input")
        assert "must-stay-local" not in str(error.value)
        observation = cast(
            InputObservation,
            {
                "attributes": {},
                "selector": "input",
                "value": {"length": 1, "hash": "0" * 64},
                "checksum": 123,
            },
        )
        with pytest.raises(ValueError):
            _payload(replace(PARAMS, page=page, inputs=[observation]), None)


@pytest.mark.parametrize(
    "extra",
    [
        {"checksum": "must-stay-local"},
        {"checksum": True},
        {"checksum": -1},
        {"checksum": 2**32},
        {"text": {"raw": "must-stay-local"}},
        {"text": 123},
        {"unknown": "must-stay-local"},
    ],
)
def test_observation_wrapper_types_reject_before_transport(extra: dict) -> None:
    observation = cast(
        InputObservation, {**observe_input(PAGE, "ok", id="email"), **extra}
    )
    with NullgateClient(
        "key",
        transport=httpx.MockTransport(
            lambda _: pytest.fail("Invalid observation reached transport")
        ),
    ) as client:
        with pytest.raises(ValueError) as error:
            client.open(identity=IDENTITY, user_agent="UA").fwcim(
                replace(PARAMS, inputs=[observation])
            )
        assert "must-stay-local" not in str(error.value)


def test_wire_snapshot_uses_actual_dict_storage_not_overridden_views() -> None:
    class HiddenField(dict):
        def keys(self):
            return {"attributes", "value"}

        def items(self):
            return [(key, value) for key, value in super().items() if key != "text"]

        def get(self, key, default=None):
            return default if key == "text" else super().get(key, default)

    unsafe = HiddenField(
        attributes={"id": "secret"},
        value={"length": 1, "hash": "0" * 64},
        text="must-stay-local",
    )
    with pytest.raises(ValueError, match="Password text"):
        _payload(replace(PARAMS, inputs=[cast(InputObservation, unsafe)]), None)
    safe = HiddenField(observe_input(PAGE, "allowed canvas", id="email"))
    safe["text"] = "allowed canvas"
    body = _payload(replace(PARAMS, inputs=[cast(InputObservation, safe)]), None)
    safe["text"] = "changed after snapshot"
    assert json.loads(json.dumps(body))["inputs"][0]["text"] == "allowed canvas"
    assert type(cast(list, body["inputs"])[0]) is dict


@pytest.mark.parametrize("start", [0, -1])
def test_navigation_start_must_be_positive(start: int) -> None:
    with pytest.raises(ValueError):
        _payload(
            replace(
                PARAMS,
                page=replace(PAGE, started_at_ms=start),
                performance_timing={"navigationStart": start},
            ),
            None,
        )


@pytest.mark.parametrize(
    "point",
    [
        {},
        {"x": 1},
        {"y": 1},
        {"x": None, "y": 1},
        {"x": 1, "y": None},
        {"x": 1, "y": 2, "identifier": None},
        {"x": 1, "y": 2, "identifier": 1.5},
        {"x": 1, "y": 2, "identifier": True},
    ],
)
def test_touch_points_require_coordinates_and_integer_identifier(point: dict) -> None:
    with pytest.raises(ValueError):
        _payload(replace(PARAMS, actions=[{"touches": [point]}]), None)
    action = {"touches": [{"x": -1.5, "y": -2, "identifier": -1}]}
    assert _payload(replace(PARAMS, actions=[action]), None)["actions"] == [action]


@pytest.mark.parametrize("close_while_active", [False, True])
def test_sync_amazon_queue_is_independent_and_respects_close(close_while_active: bool):
    entered, release = Event(), Event()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        amazon = request.url.params["type"] == "fwcim"
        if amazon:
            seen.append(request.headers["X-State-ID"])
            if len(seen) == 1:
                entered.set()
                assert release.wait(5)
        return httpx.Response(
            200,
            json=DATA if amazon else {"sensor_data": "sensor", **DATA},
            headers={"X-Request-ID": "id", "X-State-ID": "amazon-next"},
        )

    sensor = SensorParams(Sensor(PAGE, "https://example.com/opaque"), "source")
    with NullgateClient("key", transport=httpx.MockTransport(handler)) as client:
        session = client.open(identity=IDENTITY, user_agent="UA")
        with ThreadPoolExecutor(max_workers=3) as pool:
            first = pool.submit(session.fwcim, PARAMS)
            assert entered.wait(5)
            second = pool.submit(session.fwcim, PARAMS)
            try:
                assert (
                    pool.submit(session.solve, sensor).result(timeout=3).request_id
                    == "id"
                )
                if close_while_active:
                    session.close()
            finally:
                release.set()
            if close_while_active:
                for pending in (first, second):
                    with pytest.raises(RuntimeError, match="closed"):
                        pending.result(timeout=3)
                assert session._amazon_state_id is None
                assert len(seen) == 1
            else:
                first.result(timeout=3)
                second.result(timeout=3)
                assert len(seen) == 2
                assert seen[1] == "amazon-next"


@pytest.mark.parametrize("close_while_active", [False, True])
def test_async_amazon_queue_is_independent_and_respects_close(close_while_active: bool):
    async def run() -> None:
        entered, release = asyncio.Event(), asyncio.Event()
        seen: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            amazon = request.url.params["type"] == "fwcim"
            if amazon:
                seen.append(request.headers["X-State-ID"])
                if len(seen) == 1:
                    entered.set()
                    await release.wait()
            return httpx.Response(
                200,
                json=DATA if amazon else {"sensor_data": "sensor", **DATA},
                headers={"X-Request-ID": "id", "X-State-ID": "amazon-next"},
            )

        sensor = SensorParams(Sensor(PAGE, "https://example.com/opaque"), "source")
        async with NullgateClientAsync(
            "key", transport=httpx.MockTransport(handler)
        ) as client:
            session = client.open(identity=IDENTITY, user_agent="UA")
            first = asyncio.create_task(session.fwcim(PARAMS))
            await asyncio.wait_for(entered.wait(), 3)
            second = asyncio.create_task(session.fwcim(PARAMS))
            try:
                assert (
                    await asyncio.wait_for(session.solve(sensor), 3)
                ).request_id == "id"
                if close_while_active:
                    await session.aclose()
            finally:
                release.set()
            if close_while_active:
                for pending in (first, second):
                    with pytest.raises(RuntimeError, match="closed"):
                        await asyncio.wait_for(pending, 3)
                assert session._amazon_state_id is None
                assert len(seen) == 1
            else:
                await asyncio.wait_for(asyncio.gather(first, second), 3)
                assert len(seen) == 2
                assert seen[1] == "amazon-next"

    asyncio.run(run())


def test_template_content_is_not_a_document_descendant() -> None:
    page = Page(
        PAGE.url,
        '<form id="f"><template><input id="inert"></template>'
        '<input id="active"></form><template><form id="hidden"></form></template>',
        started_at_ms=1000,
    )
    for attributes in ({"id": "inert"}, {"selector": "#inert"}):
        with pytest.raises(ValueError):
            observe_input(page, "safe", **attributes)
    with pytest.raises(ValueError, match="[Ff]orm selector"):
        _payload(
            FwcimParams(page, {"navigationStart": 1000}, form_selector="#hidden"),
            None,
        )
    _payload(
        FwcimParams(
            page,
            {"navigationStart": 1000},
            form_selector="#f",
            inputs=[observe_input(page, "safe", id="active")],
        ),
        None,
    )
    for html in (
        '<template><input type=password value="" value=must-stay-local></template>',
        "<template><textarea autocomplete=current-password>"
        "must-stay-local</textarea></template>",
    ):
        unsafe = Page(PAGE.url, html, started_at_ms=1000)
        with pytest.raises(ValueError, match="password values"):
            _payload(FwcimParams(unsafe, {"navigationStart": 1000}), None)
