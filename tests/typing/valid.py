from typing import assert_type

from nullgate import Nullgate, NullgateError, TargetRequest, TargetResponse
from nullgate.aio import Nullgate as AsyncNullgate


def sync_example(ng: Nullgate, html: str) -> None:
    page = ng.session(user_agent="browser").page("https://shop.example", html)
    assert_type(page.sensor_url, str | None)
    request = page.sensor(script="source", cookies={"_abck": "value"})
    assert_type(request.body, str)
    request.wait()


async def async_example(ng: AsyncNullgate, html: str) -> None:
    page = ng.session(user_agent="browser").page("https://shop.example", html)
    request = await page.sensor(script="source", cookies={})
    await request.wait()

    def send(request: TargetRequest) -> TargetResponse:
        return TargetResponse(200, {}, b"body")

    async with page.threatmetrix(send=send) as profile:
        await profile.pagehide()
    collector = {
        "url": "https://collector.example/observed.js",
        "org_id": "org",
        "session_id": "visit",
    }
    async with page.threatmetrix(send=send, collector=collector) as profile:
        await profile.pagehide()


def handle(error: NullgateError) -> tuple[str, str, str | None, int | None]:
    return error.code, error.message, error.request_id, error.status
