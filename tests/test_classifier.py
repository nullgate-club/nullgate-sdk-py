import asyncio
from email import message_from_bytes

import httpx
import pytest

from nullgate import Nullgate, NullgateError
from nullgate.aio import Nullgate as AsyncNullgate
from nullgate.classifier import Classification, Classified, Match, Matched

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
    head = b"Content-Type: " + request.headers["Content-Type"].encode() + b"\r\n\r\n"
    return [
        (
            part.get_param("name", header="content-disposition"),
            part.get_payload(decode=True),
        )
        for part in message_from_bytes(head + request.content).get_payload()
    ]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_classify_sends_raw_image_parts_and_returns_one_result_per_image(asynchronous):
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
    assert request.headers["Content-Type"].startswith("multipart/form-data; boundary=")
    assert "Content-Encoding" not in request.headers
    parts = sent(request)
    assert sorted(set(name for name, _ in parts)) == ["image", "label", "model"]
    assert [value for name, value in parts if name == "image"] == [SMALL, LARGE]
    assert [value.decode() for name, value in parts if name == "label"] == LABELS
    assert [value for name, value in parts if name == "model"] == [b"precise"]
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

    result, calls = classify(False, handler, image, labels=("кот", "dog", "bird"))
    parts = sent(calls[0])
    assert [(name, value.decode()) for name, value in parts[:-1]] == [
        ("label", "кот"),
        ("label", "dog"),
        ("label", "bird"),
    ]
    assert parts[-1] == ("image", SMALL)
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


def match(asynchronous, handler, images, *, queries):
    transport = httpx.MockTransport(handler)
    if asynchronous:

        async def run():
            async with AsyncNullgate("test-key", transport=transport) as ng:
                return await ng.match(images, queries=queries)

        return asyncio.run(run())
    with Nullgate("test-key", transport=transport) as ng:
        return ng.match(images, queries=queries)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_match_sends_raw_parts_and_preserves_image_and_query_order(asynchronous):
    def handler(request):
        assert (request.method, request.url.path) == ("POST", "/classifier/match")
        assert request.headers["Authorization"] == "Bearer test-key"
        assert request.headers["Content-Type"].startswith(
            "multipart/form-data; boundary="
        )
        assert "Content-Encoding" not in request.headers
        parts = sent(request)
        assert sorted(set(name for name, _ in parts)) == ["image", "query"]
        assert [value for name, value in parts if name == "image"] == [SMALL, LARGE]
        assert [value.decode() for name, value in parts if name == "query"] == [
            "кот",
            "dog",
        ]
        return httpx.Response(
            200, json={"results": [{"scores": [0.9, 0.8]}, {"scores": [0, 1]}]}
        )

    result = match(asynchronous, handler, [SMALL, LARGE], queries=["кот", "dog"])
    assert result == Matched([Match([0.9, 0.8]), Match([0.0, 1.0])])


@pytest.mark.parametrize(
    "images,queries",
    [
        ([], ["cat"]),
        ([SMALL] * 33, ["cat"]),
        (b"", ["cat"]),
        ([SMALL, "bad"], ["cat"]),
        ("bad", ["cat"]),
        (SMALL, []),
        (SMALL, "cat"),
    ],
)
def test_match_rejects_certain_invalid_inputs_without_request(images, queries):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(500)

    with pytest.raises(NullgateError) as error:
        match(False, handler, images, queries=queries)
    assert error.value.code == "invalid_request"
    assert calls == []


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"results": []},
        {"results": ["bad"]},
        {"results": [{"scores": []}]},
        {"results": [{"scores": ["0.5"]}]},
        {"results": [{"scores": [True]}]},
        {"results": [{"scores": [-0.1]}]},
        {"results": [{"scores": [1.1]}]},
    ],
)
def test_match_rejects_invalid_response(data):
    with pytest.raises(NullgateError) as error:
        match(
            False,
            lambda request: httpx.Response(200, json=data),
            SMALL,
            queries=["cat"],
        )
    assert error.value.code == "invalid_response"


@pytest.mark.parametrize(
    "status,code",
    [
        (401, "unauthorized"),
        (402, "insufficient_balance"),
        (413, "invalid_request"),
        (503, "unavailable"),
    ],
)
def test_match_preserves_server_error(status, code):
    def handler(request):
        return httpx.Response(
            status,
            json={"code": code, "message": "Safe explanation", "request_id": "id"},
        )

    with pytest.raises(NullgateError) as error:
        match(False, handler, SMALL, queries=["cat"])
    assert (
        error.value.code,
        error.value.message,
        error.value.request_id,
        error.value.status,
    ) == (code, "Safe explanation", "id", status)
