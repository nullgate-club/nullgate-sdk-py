import json
from uuid import UUID

import pytest

from nullgate import Nullgate, NullgateError

URL = "https://shop.example/login"
HTML = '<form id="login"><input id="email"></form><script src="/sensor"></script>'
DOCUMENT = "00000000-0000-0000-0000-00000000004a"
TIMING = {"navigationStart": 1800000000000}


@pytest.mark.parametrize("operation", ["sensor", "fwcim"])
@pytest.mark.parametrize(
    "observations,expected",
    [
        ({}, {}),
        ({"inputs": None, "actions": None}, {}),
        ({"inputs": []}, {"inputs": []}),
        ({"actions": []}, {"actions": []}),
        ({"inputs": [], "actions": []}, {"inputs": [], "actions": []}),
    ],
)
def test_omitted_observations_preserve_v1_omission_and_empty_arrays(
    api, operation, observations, expected
):
    calls, _ = api
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML)
        if operation == "sensor":
            page.sensor(script="source", cookies={}, **observations)
        else:
            page.fwcim(timing=TIMING, **observations)
    body = json.loads(calls[0].content)
    assert {key: body[key] for key in ("inputs", "actions") if key in body} == expected


@pytest.mark.parametrize(
    "options,expected",
    [
        ({}, {"submitted": True, "referrer": ""}),
        ({"form": None, "history_length": None}, {"submitted": True, "referrer": ""}),
        (
            {
                "form": "#login",
                "submitted": False,
                "referrer": "https://shop.example/cart",
                "history_length": 3,
            },
            {
                "form_selector": "#login",
                "submitted": False,
                "referrer": "https://shop.example/cart",
                "history_length": 3,
            },
        ),
    ],
)
def test_fwcim_generation_options_match_v1_wire_and_defaults(api, options, expected):
    calls, _ = api
    with Nullgate("test-key") as ng:
        ng.session(user_agent="browser").page(URL, HTML).fwcim(timing=TIMING, **options)
    body = json.loads(calls[0].content)
    assert {
        key: body[key]
        for key in ("form_selector", "submitted", "referrer", "history_length")
        if key in body
    } == expected


@pytest.mark.parametrize(
    "options",
    [
        {"submitted": None},
        {"submitted": 1},
        {"submitted": "false"},
        {"referrer": None},
        {"referrer": 1},
        {"history_length": 0},
        {"history_length": True},
        {"history_length": 1.0},
        {"form": ""},
        {"form": ".missing"},
    ],
)
def test_invalid_fwcim_generation_options_stay_local(api, options):
    calls, _ = api
    with Nullgate("test-key") as ng:
        with pytest.raises(NullgateError) as error:
            ng.session(user_agent="browser").page(URL, HTML).fwcim(
                timing=TIMING, **options
            )
    assert error.value.code == "invalid_inputs"
    assert calls == []


@pytest.mark.parametrize("operation", ["sensor", "fwcim"])
@pytest.mark.parametrize(
    "context",
    [
        {},
        {"document_id": DOCUMENT},
        {"started_at_ms": TIMING["navigationStart"]},
        {"document_id": UUID(DOCUMENT), "started_at_ms": TIMING["navigationStart"]},
    ],
)
def test_page_context_controls_wire_identity_and_start_without_changing_defaults(
    api, operation, context
):
    calls, _ = api
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML, **context)
        for _ in range(2):
            if operation == "sensor":
                page.sensor(script="source", cookies={})
            else:
                page.fwcim(timing=TIMING)
    bodies = [json.loads(request.content) for request in calls]
    identifiers = {body["document_id"] for body in bodies}
    starts = {body["started_at_ms"] for body in bodies}
    assert len(identifiers) == len(starts) == 1
    assert str(UUID(bodies[0]["document_id"])) == bodies[0]["document_id"]
    if "document_id" in context:
        assert identifiers == {DOCUMENT}
    if "started_at_ms" in context or operation == "fwcim":
        assert starts == {TIMING["navigationStart"]}
    else:
        assert bodies[0]["started_at_ms"] > 0


@pytest.mark.parametrize(
    "context",
    [
        {"document_id": "invalid"},
        {"started_at_ms": -1},
        {"started_at_ms": True},
        {"started_at_ms": 1.0},
    ],
)
def test_invalid_page_context_is_refused_locally(api, context):
    calls, _ = api
    with Nullgate("test-key") as ng, pytest.raises(NullgateError) as error:
        ng.session(user_agent="browser").page(URL, HTML, **context)
    assert error.value.code == "invalid_page"
    assert calls == []


def test_fwcim_cannot_overwrite_an_explicit_document_start(api):
    calls, _ = api
    with Nullgate("test-key") as ng:
        page = ng.session(user_agent="browser").page(URL, HTML, started_at_ms=1000)
        with pytest.raises(NullgateError) as error:
            page.fwcim(timing=TIMING)
    assert error.value.code == "invalid_inputs"
    assert calls == []


@pytest.mark.parametrize(
    "html,options,challenge,script_url",
    [
        (
            '<script>bazadebezolkohpepadr="123"</script>'
            '<script src="/akam/13/abc"></script>',
            {},
            "123",
            "https://shop.example/akam/13/abc",
        ),
        (
            '<script src="/akam/13/abc"></script>',
            {"challenge": "007"},
            "007",
            "https://shop.example/akam/13/abc",
        ),
        (
            '<script>bazadebezolkohpepadr="1";bazadebezolkohpepadr="2"</script>'
            '<script src="/akam/13/abc"></script>',
            {"challenge": "3"},
            "3",
            "https://shop.example/akam/13/abc",
        ),
        (
            "",
            {"challenge": "0", "script_url": "/observed.js"},
            "0",
            "https://shop.example/observed.js",
        ),
        (
            "",
            {"challenge": "١٢٣", "script_url": "/observed.js"},
            "١٢٣",
            "https://shop.example/observed.js",
        ),
    ],
)
def test_pixel_manual_challenge_matches_observed_or_explicit_script(
    api, html, options, challenge, script_url
):
    calls, _ = api
    with Nullgate("test-key") as ng:
        ng.session(user_agent="browser").page(URL, html).pixel(
            script="source", **options
        )
    body = json.loads(calls[0].content)
    assert body["challenge"] == challenge
    assert body["script_url"] == script_url
    assert "challenge_offset" not in body


@pytest.mark.parametrize(
    "options,html,code",
    [
        ({"challenge": ""}, "", "invalid_request"),
        ({"challenge": 123}, "", "invalid_request"),
        ({"challenge": "-1"}, "", "invalid_request"),
        ({"challenge": "1.0"}, "", "invalid_request"),
        ({"challenge": "1"}, "", "protection_not_found"),
        (
            {"challenge": "1"},
            '<script src="/akam/13/abc"></script><script src="/akam/13/def"></script>',
            "ambiguous_protection",
        ),
    ],
)
def test_pixel_manual_challenge_requires_valid_value_and_unambiguous_source(
    api, options, html, code
):
    calls, _ = api
    with Nullgate("test-key") as ng, pytest.raises(NullgateError) as error:
        ng.session(user_agent="browser").page(URL, html).pixel(
            script="source", **options
        )
    assert error.value.code == code
    assert calls == []


@pytest.mark.parametrize(
    "query",
    [
        "?v=" + DOCUMENT,
        "?v=" + DOCUMENT + "&t=",
        "?v=" + DOCUMENT + "&t=opaque%2Btoken",
    ],
)
def test_sbsd_preserves_url_selected_blocking_mode_without_inventing_a_field(
    api, query
):
    calls, _ = api
    observed = "https://shop.example/guard" + query
    with Nullgate("test-key") as ng:
        ng.session(user_agent="browser").page(URL, "").sbsd(
            script="source", cookies={}, script_url=observed
        )
    body = json.loads(calls[0].content)
    assert body["script_url"] == observed
    assert "blocking" not in body
