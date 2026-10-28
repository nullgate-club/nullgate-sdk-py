import asyncio
from uuid import UUID

import httpx
import pytest

import nullgate.solution as solution_module
from nullgate import NullgateClient, NullgateClientAsync, Page
from nullgate.akamai import Pixel, PixelParams


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_wait_uses_absolute_send_at_and_never_sleeps_for_past_submission(
    asynchronous: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    delays: list[float] = []
    now = [100.0]
    monkeypatch.setattr(solution_module.time, "time", lambda: now[0])
    params = PixelParams(
        Pixel(
            Page("https://target.example/", ""),
            "https://target.example/akam/13/abc",
            "123",
        ),
        "source",
    )

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "url": "https://target.example/post",
                "body": "pixel",
                "headers": {},
                "send_at": 101.25,
            },
            headers={"X-Request-ID": "1" * 32},
        )

    def run_sync() -> None:
        monkeypatch.setattr(solution_module.time, "sleep", delays.append)
        with NullgateClient("secret", transport=httpx.MockTransport(handle)) as client:
            with client.open(identity=UUID(int=1), user_agent="UA") as session:
                solution = session.solve(params)
                solution.wait()
                now[0] = 102.0
                solution.wait()

    async def run_async() -> None:
        async def sleep(delay: float) -> None:
            delays.append(delay)

        monkeypatch.setattr(solution_module.asyncio, "sleep", sleep)
        async with NullgateClientAsync(
            "secret", transport=httpx.MockTransport(handle)
        ) as client:
            async with client.open(identity=UUID(int=1), user_agent="UA") as session:
                solution = await session.solve(params)
                await solution.wait()
                now[0] = 102.0
                await solution.wait()

    asyncio.run(run_async()) if asynchronous else run_sync()
    assert delays == [1.25]
