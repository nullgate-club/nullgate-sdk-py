from typing import assert_type

from nullgate import (
    Nullgate,
    NullgateError,
    PreparedInput,
    TargetRequest,
    TargetResponse,
    prepare_inputs,
)
from nullgate.aio import Nullgate as AsyncNullgate


def sync_example(ng: Nullgate, html: str) -> None:
    page = ng.session(user_agent="browser").page(
        "https://shop.example",
        html,
        document_id="00000000-0000-0000-0000-00000000004a",
        started_at_ms=1,
    )
    prepared = prepare_inputs([{"id": "password", "value": "local-only"}])
    assert_type(prepared, list[PreparedInput])
    page.sensor(script="source", cookies={}, inputs=prepared)
    page.fwcim(
        timing={"navigationStart": 1},
        inputs=prepared,
        submitted=False,
        referrer="https://shop.example/cart",
        history_length=2,
    )
    assert_type(page.sensor_url, str | None)
    request = page.sensor(script="source", cookies={"_abck": "value"})
    assert_type(request.body, str)
    request.wait()
    assert_type(request.report(), bool)
    assert_type(ng.report(request.request_id), bool)
    page.pixel(script="source", script_url="/pixel", challenge="123")


async def async_example(ng: AsyncNullgate, html: str) -> None:
    page = ng.session(user_agent="browser").page(
        "https://shop.example",
        html,
        document_id=None,
        started_at_ms=1,
    )
    prepared = prepare_inputs([{"id": "password", "value": "local-only"}])
    await page.sensor(script="source", cookies={}, inputs=prepared)
    await page.fwcim(
        timing={"navigationStart": 1},
        inputs=prepared,
        submitted=False,
        referrer="",
        history_length=2,
    )
    request = await page.sensor(script="source", cookies={})
    await request.wait()
    assert_type(await request.report(), bool)
    assert_type(await ng.report(request.request_id), bool)
    await page.pixel(script="source", script_url="/pixel", challenge="123")

    def send(request: TargetRequest) -> TargetResponse:
        return TargetResponse(200, {}, b"body")

    async with page.threatmetrix(send=send, inputs=prepared, actions=[]) as profile:
        await profile.pagehide()
        assert_type(await profile.report(), bool)
    collector = {
        "url": "https://collector.example/observed.js",
        "org_id": "org",
        "session_id": "visit",
    }
    async with page.threatmetrix(send=send, collector=collector) as profile:
        await profile.pagehide()


def handle(error: NullgateError) -> tuple[str, str, str | None, int | None]:
    return error.code, error.message, error.request_id, error.status
