import asyncio
import gzip
import json

import httpx
import pytest

from nullgate import Nullgate, NullgateError
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
def test_pow_sends_compressed_html_and_uses_90_second_timeout(asynchronous):
    def handler(request):
        assert (request.method, request.url.path) == ("POST", "/amazon/acic/pow")
        assert request.headers["authorization"] == "Bearer test-key"
        assert request.headers["content-type"] == "application/json"
        assert request.headers["content-encoding"] == "gzip"
        assert json.loads(gzip.decompress(request.content)) == {
            "challenge_type": "PROOF_OF_WORK_LEVEL_3",
            "html": "x" * 2048,
        }
        assert 89 < request.extensions["timeout"]["read"] <= 90
        return httpx.Response(
            200, json={"response": '{"data":"proof"}', "request_id": "pow-id"}
        )

    result = call(
        asynchronous, "acic_pow", handler, "PROOF_OF_WORK_LEVEL_3", "x" * 2048
    )
    assert (result.response, result.request_id) == ('{"data":"proof"}', "pow-id")


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
        assert 9 < request.extensions["timeout"]["read"] <= 10
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
def test_pow_accepts_call_timeout(asynchronous):
    def handler(request):
        assert 19 < request.extensions["timeout"]["read"] <= 20
        return httpx.Response(200, json={"response": "proof", "request_id": "id"})

    call(asynchronous, "acic_pow", handler, "type", "html", timeout=20)
