import asyncio
import gzip
import json
from base64 import b64decode

import httpx
import pytest

from nullgate import Nullgate, NullgateError
from nullgate.aio import Nullgate as AsyncNullgate
from nullgate.classifier import Classification, Classified

LABELS = ["cat", "dog", "bird"]
SMALL = b"\x89PNG\r\n\x1a\n\x00\xff"
LARGE = b"\xff\xd8\xff" + bytes(range(256)) * 8


def classify(asynchronous, handler, images, **kwargs):
    calls = []

    def record(request):
        calls.append(request)
        return handler(request)

    transport = httpx.MockTransport(record)
    if asynchronous:

        async def run():
            async with AsyncNullgate("test-key", transport=transport) as ng:
                return await ng.classify(images, **kwargs)

        return asyncio.run(run()), calls
    with Nullgate("test-key", transport=transport) as ng:
        return ng.classify(images, **kwargs), calls


def sent(request):
    body = request.content
    if request.headers.get("Content-Encoding") == "gzip":
        body = gzip.decompress(body)
    return json.loads(body)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_classify_sends_base64_images_and_returns_one_result_per_image(asynchronous):
    def handler(request):
        return httpx.Response(
            200,
            json={
                "model": "precise",
                "results": [
                    {"label": "dog", "scores": [0.125, 0.75, 0.125]},
                    {"label": "cat", "scores": [1, 0, 0]},
                ],
            },
        )

    result, calls = classify(
        asynchronous, handler, [SMALL, LARGE], labels=LABELS, model="precise"
    )
    (request,) = calls
    assert (request.method, request.url.path) == ("POST", "/classifier/classify")
    assert request.headers["Authorization"] == "Bearer test-key"
    assert request.headers["Content-Encoding"] == "gzip"
    body = sent(request)
    assert set(body) == {"model", "images", "labels"}
    assert body["model"] == "precise"
    assert body["labels"] == LABELS
    assert [b64decode(image, validate=True) for image in body["images"]] == [
        SMALL,
        LARGE,
    ]
    assert result == Classified(
        "precise",
        [
            Classification("dog", [0.125, 0.75, 0.125]),
            Classification("cat", [1.0, 0.0, 0.0]),
        ],
    )


@pytest.mark.parametrize("image", [SMALL, bytearray(SMALL), memoryview(SMALL)])
def test_classify_wraps_one_image_and_leaves_default_model_to_server(image):
    def handler(request):
        return httpx.Response(
            200,
            json={
                "model": "balanced",
                "results": [{"label": "bird", "scores": [0.25, 0.25, 0.5]}],
            },
        )

    result, calls = classify(False, handler, image, labels=tuple(LABELS))
    body = sent(calls[0])
    assert set(body) == {"images", "labels"}
    assert [b64decode(item, validate=True) for item in body["images"]] == [SMALL]
    assert result.model == "balanced"
    assert [item.label for item in result.results] == ["bird"]


@pytest.mark.parametrize(
    "status,code",
    [
        (400, "invalid_request"),
        (402, "insufficient_balance"),
        (413, "invalid_request"),
        (503, "unavailable"),
    ],
)
def test_classify_failure_preserves_public_error_fields(status, code):
    def handler(request):
        return httpx.Response(
            status,
            json={"code": code, "message": "Safe explanation", "request_id": "id"},
        )

    with pytest.raises(NullgateError) as error:
        classify(False, handler, SMALL, labels=LABELS)
    assert (
        error.value.code,
        error.value.message,
        error.value.request_id,
        error.value.status,
    ) == (code, "Safe explanation", "id", status)


@pytest.mark.parametrize(
    "images,labels",
    [
        ([], LABELS),
        ([SMALL] * 33, LABELS),
        (b"", LABELS),
        ([SMALL, "aGVsbG8="], LABELS),
        ("aGVsbG8=", LABELS),
        (SMALL, ["cat"]),
        (SMALL, "cat"),
    ],
    ids=[
        "no-images",
        "too-many-images",
        "empty-image",
        "base64-item",
        "base64-string",
        "one-label",
        "string-labels",
    ],
)
def test_classify_refuses_certainly_invalid_input_before_any_api_call(images, labels):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(500)

    with pytest.raises(NullgateError) as error:
        classify(False, handler, images, labels=labels)
    assert error.value.code == "invalid_request"
    assert error.value.status is None
    assert calls == []


@pytest.mark.parametrize(
    "data",
    [
        {"results": [{"label": "cat", "scores": [1, 0, 0]}]},
        {"model": "balanced", "results": []},
        {"model": "balanced", "results": [{"label": "cat", "scores": [1, 0]}]},
        {"model": "balanced", "results": [{"label": "fox", "scores": [1, 0, 0]}]},
        {"model": "balanced", "results": [{"label": "cat", "scores": [1, "0", 0]}]},
        {"model": "balanced", "results": ["cat"]},
    ],
    ids=[
        "no-model",
        "missing-result",
        "short-scores",
        "unknown-label",
        "text-score",
        "text-result",
    ],
)
def test_classify_rejects_response_that_does_not_match_the_request(data):
    with pytest.raises(NullgateError) as error:
        classify(
            False, lambda request: httpx.Response(200, json=data), SMALL, labels=LABELS
        )
    assert error.value.code == "invalid_response"
