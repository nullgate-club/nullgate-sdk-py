import json
from copy import deepcopy

import pytest

from nullgate import Nullgate, NullgateError, prepare_inputs

URL = "https://shop.example/login"
TIMING = {"navigationStart": 1800000000000}
SUMMARY = {
    "length": 3,
    "hash": "992dbff9f92b8812ca4746cf6fdaa2937337d2ed3b7a1be90c6e5d67036194b4",
    "counts": [3, 1, 1, 1],
    "hash31": 64265,
    "trimmed_hash31": 64265,
    "trimmed_length": 3,
}
HTML = '<form id="login"><input id="credential" type="password"></form>'


def generate(page, operation, inputs):
    if operation == "sensor":
        return page.sensor(
            script="source", script_url="/sensor", cookies={}, inputs=inputs
        )
    return page.fwcim(form="#login", timing=TIMING, inputs=inputs)


@pytest.mark.parametrize("operation", ["sensor", "fwcim"])
@pytest.mark.parametrize("kind", ["raw_mapping", "raw_sequence", "prepared"])
@pytest.mark.parametrize(
    "control,identity",
    [
        ('<input id="credential" type=" PASSWORD ">', {"id": "credential"}),
        (
            '<input id="credential" autocomplete="current-password">',
            {"id": "credential"},
        ),
        ('<input name="password">', {"name": "password"}),
        ('<textarea id="ap_password"></textarea>', {"id": "ap_password"}),
    ],
)
def test_password_summaries_keep_v1_wire_shape_but_raw_values_stay_local(
    api, operation, kind, control, identity
):
    calls, _ = api
    fields = [{**identity, "value": "A9!"}]
    if kind == "prepared":
        fields = prepare_inputs(fields)
    elif kind == "raw_mapping":
        fields = {next(iter(identity.values())): "A9!"}
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(
            URL, f'<form id="login">{control}</form>'
        )
        if kind == "prepared":
            generate(page, operation, fields)
        else:
            with pytest.raises(NullgateError) as error:
                generate(page, operation, fields)
            assert error.value.code == "invalid_inputs"
            assert "A9!" not in str(error.value)
    if kind == "prepared":
        assert json.loads(calls[0].content)["inputs"] == [
            {"attributes": identity, "value": SUMMARY}
        ]
        assert b"A9!" not in calls[0].content
    else:
        assert calls == []


@pytest.mark.parametrize("operation", ["sensor", "fwcim"])
@pytest.mark.parametrize(
    "summary",
    [
        {"length": 0, "hash": "0" * 64},
        {
            "length": 2,
            "hash": "0" * 64,
            "counts": [2, 2, 2, 0],
            "hash31": -(2**31),
            "trimmed_hash31": 2**31 - 1,
            "trimmed_length": 2,
        },
    ],
)
def test_prepared_optional_statistics_are_preserved_without_invented_values(
    api, operation, summary
):
    calls, _ = api
    observation = {"attributes": {}, "selector": "#credential", "value": summary}
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML)
        generate(page, operation, [observation])
    assert json.loads(calls[0].content)["inputs"] == [observation]


@pytest.mark.parametrize("operation", ["sensor", "fwcim"])
@pytest.mark.parametrize(
    "change",
    [
        {"length": None},
        {"length": True},
        {"length": 3.0},
        {"length": -1},
        {"hash": "A" * 64},
        {"hash": "0" * 63},
        {"hash": 0},
        {"raw": "A9!"},
        {"value": "A9!"},
        {"hash31": -(2**31) - 1},
        {"hash31": 2**31},
        {"hash31": True},
        {"hash31": 1.0},
        {"hash31": None},
        {"trimmed_hash31": -(2**31) - 1},
        {"trimmed_hash31": 2**31},
        {"trimmed_length": -1},
        {"trimmed_length": 4},
        {"trimmed_length": True},
        {"trimmed_length": 0},
        {"counts": None},
        {"counts": [3, 1, 1]},
        {"counts": [3, 1, 1, 1, 0]},
        {"counts": [2, 1, 1, 1]},
        {"counts": [3, -1, 1, 1]},
        {"counts": [3, 3, 1, 1]},
        {"counts": [3, 1, 3, 1]},
        {"counts": [3, 1, True, 1]},
        {"counts": [3, 1, 1.0, 1]},
        {"counts": "3,1,1,1"},
    ],
)
def test_malformed_prepared_statistics_never_reach_api(api, operation, change):
    calls, _ = api
    observation = {"attributes": {"id": "credential"}, "value": {**SUMMARY, **change}}
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML)
        with pytest.raises(NullgateError) as error:
            generate(page, operation, [observation])
    assert error.value.code == "invalid_inputs"
    assert calls == []


@pytest.mark.parametrize("operation", ["sensor", "fwcim"])
@pytest.mark.parametrize(
    "observation",
    [
        {"attributes": {}},
        {"value": SUMMARY},
        {"attributes": "credential", "value": SUMMARY},
        {"attributes": {"id": 1}, "value": SUMMARY},
        {"attributes": {1: "credential"}, "value": SUMMARY},
        {"attributes": {"value": "A9!"}, "value": SUMMARY},
        {"attributes": {"selector": "#credential"}, "value": SUMMARY},
        {"attributes": {}, "value": {}},
        {"attributes": {}, "value": {"hash": "0" * 64}},
        {"attributes": {}, "value": {"length": 0}},
        {"attributes": {}, "value": "A9!"},
        {"attributes": {}, "value": SUMMARY, "selector": ""},
        {"attributes": {}, "value": SUMMARY, "selector": None},
        {"attributes": {}, "value": SUMMARY, "selector": 1},
        {"attributes": {}, "value": SUMMARY, "raw": "A9!"},
    ],
)
def test_malformed_prepared_fields_never_reach_api(api, operation, observation):
    calls, _ = api
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML)
        with pytest.raises(NullgateError) as error:
            generate(page, operation, [observation])
    assert error.value.code == "invalid_inputs"
    assert calls == []


@pytest.mark.parametrize(
    "extra", [{"text": None}, {"text": "A9!"}, {"checksum": None}, {"checksum": 64265}]
)
def test_amazon_password_summaries_reject_text_and_checksum_presence(api, extra):
    calls, _ = api
    observation = {"attributes": {"id": "credential"}, "value": SUMMARY, **extra}
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML)
        with pytest.raises(NullgateError) as error:
            generate(page, "fwcim", [observation])
    assert error.value.code == "invalid_inputs"
    assert calls == []


def test_amazon_prepared_nonpassword_canvas_facts_preserve_v1_observation(api):
    calls, _ = api
    observation = {
        "attributes": {"id": "credential"},
        "selector": "#credential",
        "value": deepcopy(SUMMARY),
        "checksum": 2**32 - 1,
        "geometry": {"width": 120, "height": 30, "left": -4, "top": 0},
        "text": "A9!",
    }
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(
            URL, '<form id="login"><input id="credential" type="text"></form>'
        )
        generate(page, "fwcim", [observation])
    assert json.loads(calls[0].content)["inputs"] == [observation]
