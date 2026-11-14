import asyncio
import gzip
import json
from urllib.parse import parse_qs, parse_qsl, urlsplit

import httpx
import pytest

from nullgate import Nullgate, NullgateError, acic
from nullgate.aio import Nullgate as AsyncNullgate
from nullgate.amazon import AcicWaf


def call(asynchronous, method, handler, *args, **kwargs):
    transport = httpx.MockTransport(handler)
    if asynchronous:

        async def run():
            async with AsyncNullgate("test-key", timeout=10, transport=transport) as ng:
                return await getattr(ng, method)(*args, **kwargs)

        return asyncio.run(run())
    with Nullgate("test-key", timeout=10, transport=transport) as ng:
        return getattr(ng, method)(*args, **kwargs)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_pow_sends_compressed_challenge(asynchronous):
    def handler(request):
        assert (request.method, request.url.path) == ("POST", "/amazon/acic/pow")
        assert request.headers["authorization"] == "Bearer test-key"
        assert request.headers["content-type"] == "application/json"
        assert request.headers["content-encoding"] == "gzip"
        assert json.loads(gzip.decompress(request.content)) == {
            "challenge_type": "PROOF_OF_WORK_LEVEL_3",
            "html": "x" * 2048,
            "started_at_ms": 1700000000000,
        }
        return httpx.Response(
            200,
            json={
                "response": '{"data":"proof"}',
                "request_id": "pow-id",
                "send_at": 123.5,
            },
        )

    result = call(
        asynchronous,
        "acic_pow",
        handler,
        "PROOF_OF_WORK_LEVEL_3",
        "x" * 2048,
        started_at_ms=1700000000000,
    )
    assert (result.response, result.request_id, result.send_at) == (
        '{"data":"proof"}',
        "pow-id",
        123.5,
    )


@pytest.mark.parametrize("asynchronous", [False, True])
def test_waf_sends_original_problem_compressed_and_returns_solution(asynchronous):
    problem = {
        "state": "s",
        "key": "k",
        "hmac_tag": "h",
        "assets": {"images": "x" * 2048},
    }

    def handler(request):
        assert (request.method, request.url.path) == ("POST", "/amazon/acic/waf")
        assert request.headers["authorization"] == "Bearer test-key"
        assert request.headers["content-type"] == "application/json"
        assert request.headers["content-encoding"] == "gzip"
        assert json.loads(gzip.decompress(request.content)) == {"problem": problem}
        return httpx.Response(
            200, json={"client_solution": [0, 2, 4, 6, 8], "request_id": "waf-id"}
        )

    result = call(asynchronous, "acic_waf", handler, problem)
    assert result == AcicWaf([0, 2, 4, 6, 8], "waf-id")
    assert result.verification_body(problem, elapsed_seconds=1.25, locale="en-US") == {
        "state": "s",
        "key": "k",
        "hmac_tag": "h",
        "client_solution": [0, 2, 4, 6, 8],
        "metrics": {"solve_time_millis": 1250},
        "locale": "en-US",
    }


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "method,args", [("acic_pow", ("unknown", "html")), ("acic_waf", ({},))]
)
def test_unsupported_is_not_retried(asynchronous, method, args):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            501,
            json={"code": "unsupported", "message": "unsupported", "request_id": "id"},
        )

    with pytest.raises(NullgateError) as error:
        call(asynchronous, method, handler, *args)
    assert (error.value.code, error.value.status, error.value.request_id) == (
        "unsupported",
        501,
        "id",
    )
    assert len(calls) == 1


@pytest.mark.parametrize("asynchronous", [False, True])
def test_pow_waits_until_send_time(asynchronous, monkeypatch):
    delays = []
    monkeypatch.setattr("time.time", lambda: 100.0)
    if asynchronous:
        from nullgate.aio import AcicPow

        async def sleep(delay):
            delays.append(delay)

        monkeypatch.setattr("asyncio.sleep", sleep)
        asyncio.run(AcicPow("proof", 102.5, "id").wait())
    else:
        from nullgate.client import AcicPow

        monkeypatch.setattr("time.sleep", delays.append)
        AcicPow("proof", 102.5, "id").wait()
    assert delays == [2.5]


def bootstrap(mount='"data-iframe-id": "frame"'):
    return f"""<script>acic.setupACIC({{
        "data-ref-id": "cvf",
        "data-challenge-type": "POW",
        "data-callback": function(data) {{ return submitForm(data); }},
        "data-header-footer": false,
        "data-context": '{{"example":"a+b/="}}',
        "data-locale": "en-GB",
        {mount},
        "data-external-id": "external",
        "data-host-config": "prod.EUAmazon",
        "data-use-post-request-method": true
    }});</script>
    <form id="cvf-aamation-challenge-form" method="post" action="verify">
      <input type="hidden" name="same" value="one">
      <input type="hidden" name="same" value="">
      <input type="hidden" name="cvf_aamation_response_token" value="old">
    </form>"""


def test_local_acic_preserves_options_and_current_result():
    setup = acic.discover("https://www.amazon.com/ap/challenge", bootstrap())
    assert setup.service_url == "https://www.amazon.com/aaut/verify/cvf"
    start = setup.start()
    assert start.headers == {
        "Content-Type": "application/json",
        "Origin": "https://www.amazon.com",
        "Referer": "https://www.amazon.com/ap/challenge",
    }
    options = json.loads(start.body)["options"]
    assert json.loads(options)["clientData"] == '{"example":"a+b/="}'
    assert json.loads(options)["forceJsFlush"] is True
    assert parse_qs(urlsplit(start.url).query) == {"options": [options]}
    result = acic.parse_result(
        {
            "AMZ-AAMATION-RESP": json.dumps(
                {
                    "actionType": "WAF",
                    "clientSideContext": "ctx+/=",
                    "sessionToken": "t+/=",
                }
            )
        }
    )
    answer = setup.answer(result, '{"proof":"a+b"}')
    assert answer.headers == start.headers
    assert urlsplit(answer.url).path.endswith("/t%2B%2F%3D")
    assert parse_qs(urlsplit(answer.url).query) == {
        "context": ["ctx+/="],
        "options": [options],
        "response": ['{"proof":"a+b"}'],
    }
    assert json.loads(answer.body) == {
        "context": "ctx+/=",
        "options": options,
        "response": '{"proof":"a+b"}',
        "fwcimBlob": None,
    }
    assert json.loads(result.voucher_response("v+/=")) == {
        "challengeType": "WAF",
        "data": '"v+/="',
    }
    assert "ctx+/=" not in repr(result) and "t+/=" not in repr(result)
    assert "a+b/=" not in repr(setup)


def test_local_acic_continuation_preserves_duplicate_and_blank_fields():
    setup = acic.discover("https://www.amazon.de/ap/challenge", bootstrap())
    result = acic.parse_result(
        {
            "amz-aamation-resp": json.dumps(
                {
                    "actionType": "PASS",
                    "clientSideContext": None,
                    "sessionToken": "final+/=",
                }
            )
        }
    )
    request = setup.continuation(result)
    assert request.url == "https://www.amazon.de/ap/verify"
    assert parse_qsl(request.body.decode(), keep_blank_values=True) == [
        ("same", "one"),
        ("same", ""),
        ("cvf_aamation_response_token", "final+/="),
    ]
    with pytest.raises(ValueError):
        setup.continuation(acic.Result("WAF", None, "token"))


@pytest.mark.parametrize(
    "html",
    [
        bootstrap() + bootstrap(),
        bootstrap().replace('"data-locale": "en-GB",', '"data-locale": dynamic,'),
        bootstrap().replace(
            '"data-locale": "en-GB",', '"data-locale": "en-GB", "data-locale": "fr-FR",'
        ),
    ],
)
def test_local_acic_rejects_ambiguous_or_dynamic_setup(html):
    with pytest.raises(ValueError):
        acic.discover("https://www.amazon.de/ap/challenge", html)


def test_local_acic_absence_and_malformed_header():
    assert acic.discover("https://www.amazon.de/", "<script>nothing()</script>") is None
    assert acic.parse_result({}) is None
    with pytest.raises(ValueError, match="Malformed ACIC result header"):
        acic.parse_result({"amz-aamation-resp": "private secret"})
    setup = acic.discover(
        "https://www.amazon.de/ap/challenge", bootstrap().split("<form")[0]
    )
    with pytest.raises(ValueError, match="form is missing"):
        setup.continuation(acic.Result("PASS", None, "token"))


def test_local_waf_uses_observed_provider_and_rounds():
    html = """<script src="https://p.eu-west-2.captcha.awswaf.com/a/b/captcha.js"></script>
    <script>
    const decoy = Object.assign({"problem":"wrong"}, other);
    const wafInputProperties = Object.assign({"problem":"grid-v2",
      "visualSolutionsRequired":2,"defaultLocale":"fr-FR","id":"opaque+/="},
      wafOnLoadProperty);
    </script>"""
    waf = acic.discover_waf("https://www.amazon.fr/view", html)
    assert waf.locale == "fr-fr"
    assert waf.rounds_required == 2
    assert waf.headers == {
        "Origin": "https://www.amazon.fr",
        "Referer": "https://www.amazon.fr/",
        "Content-Type": "text/plain;charset=UTF-8",
    }
    assert parse_qs(urlsplit(waf.problem_url).query) == {
        "kind": ["visual"],
        "domain": ["www.amazon.fr"],
        "locale": ["fr-fr"],
        "problem": ["grid-v2"],
        "num_solutions_required": ["2"],
        "id": ["opaque+/="],
    }
    assert waf.verification_url({"region": "eu+west"}) == (
        "https://p.eu-west-2.captcha.awswaf.com/a/b/verify?region=eu%2Bwest"
    )
    assert (
        acic.discover_waf(
            "https://www.amazon.fr/", "<script>Object.assign({}, x)</script>"
        )
        is None
    )
    with pytest.raises(ValueError):
        acic.discover_waf(
            "https://www.amazon.fr/",
            html.replace("p.eu-west-2.captcha.awswaf.com", "evil.example"),
        )


def test_local_acic_div_mount_does_not_execute_expression():
    html = bootstrap('"data-div": document.getElementById("mount")')
    setup = acic.discover("https://example.com/challenge", html)
    assert setup.service_url == "https://www.amazon.de/aaut/verify/cvf"
    assert (
        json.loads(json.loads(setup.start().body)["options"])["forceJsFlush"] is False
    )
    with pytest.raises(ValueError):
        acic.discover("https://example.com/challenge", bootstrap('"data-div": null'))


@pytest.mark.parametrize(
    "form",
    [
        'method="get" action="verify"',
        'method="post" action="https://evil.example/verify"',
    ],
)
def test_local_acic_rejects_unsafe_continuation(form):
    html = bootstrap().replace('method="post" action="verify"', form)
    setup = acic.discover("https://www.amazon.de/ap/challenge", html)
    with pytest.raises(ValueError):
        setup.continuation(acic.Result("PASS", None, "token"))


def test_local_waf_rejects_malformed_known_view():
    html = """<script src="https://captcha.awswaf.com/x/captcha.js"></script>
    <script>const wafInputProperties = Object.assign(
    {"problem":"grid","visualSolutionsRequired":2,"defaultLocale":"en-GB",
    "id":"one","id":"two"}, wafOnLoadProperty);</script>"""
    with pytest.raises(ValueError):
        acic.discover_waf("https://www.amazon.de/", html)


def test_bootstrap_preserves_javascript_string_escapes():
    html = bootstrap().replace(
        r"""'{"example":"a+b/="}'""",
        r"""'{"path":"https:\/\/example.test\/","symbol":"\ud83d\ude00"}'""",
    )
    setup = acic.discover("https://www.amazon.de/ap/challenge", html)
    options = json.loads(json.loads(setup.start().body)["options"])
    assert options["clientData"] == (
        '{"path":"https://example.test/","symbol":"\U0001f600"}'
    )
    with pytest.raises(ValueError):
        acic.discover(
            "https://www.amazon.de/ap/challenge",
            bootstrap().replace('"en-GB"', "'en-GB' 'suffix'"),
        )
