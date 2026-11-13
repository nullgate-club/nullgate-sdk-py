"""Synchronous facade over the async implementation and its owned event loop."""

import asyncio
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime
from types import TracebackType
from typing import Any, Self
from uuid import UUID

import httpx

from . import aio
from .amazon import AcicPow, AcicWaf
from .classifier import Classified, Image, Matched
from .profile import Profile, _ProfileLoop
from .target import TargetFetch


@dataclass(frozen=True, slots=True)
class Request:
    url: str
    body: str = field(repr=False)
    headers: dict[str, str]
    send_at: float
    request_id: str
    _reporter: Callable[[str], bool] = field(repr=False, kw_only=True)

    def wait(self) -> None:
        time.sleep(max(0.0, self.send_at - time.time()))

    def report(self) -> bool:
        return self._reporter(self.request_id)


@dataclass(frozen=True, slots=True)
class Fwcim:
    metadata1: str = field(repr=False)
    headers: dict[str, str]
    send_at: float
    request_id: str
    _reporter: Callable[[str], bool] = field(repr=False, kw_only=True)

    def wait(self) -> None:
        time.sleep(max(0.0, self.send_at - time.time()))

    def report(self) -> bool:
        return self._reporter(self.request_id)


class _SyncTransport(httpx.AsyncBaseTransport):
    def __init__(self, transport: httpx.BaseTransport) -> None:
        self._transport = transport

    async def __aenter__(self) -> Self:
        await asyncio.to_thread(self._transport.__enter__)
        return self

    def _send(self, request: httpx.Request) -> httpx.Response:
        response = self._transport.handle_request(request)
        try:
            response.read()
        finally:
            response.close()
        response.stream = httpx.ByteStream(response.content)
        return response

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        work = asyncio.create_task(asyncio.to_thread(self._send, request))
        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError:
            await asyncio.gather(work, return_exceptions=True)
            raise

    async def aclose(self) -> None:
        await asyncio.to_thread(self._transport.close)


class Nullgate:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = "https://api.nullgate.club",
        timeout: float = 30,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._async = aio.Nullgate(
            api_key,
            base_url=base_url,
            timeout=timeout,
            transport=_SyncTransport(transport) if transport is not None else None,
        )
        self._loop = _ProfileLoop()
        self._closed = False

    def session(
        self,
        *,
        user_agent: str,
        profile: UUID | str | None = None,
        timezone: str | None = None,
    ) -> "Session":
        return Session(
            self,
            self._async.session(
                user_agent=user_agent, profile=profile, timezone=timezone
            ),
        )

    def report(self, request_id: str) -> bool:
        return self._loop.run(self._async.report(request_id))

    def account(self) -> dict[str, Any]:
        return self._loop.run(self._async.account())

    def usage(
        self,
        *,
        interval: str = "hour",
        start: str | datetime | None = None,
        end: str | datetime | None = None,
    ) -> dict[str, Any]:
        return self._loop.run(
            self._async.usage(interval=interval, start=start, end=end)
        )

    def classify(
        self,
        images: Image | Sequence[Image],
        *,
        labels: Sequence[str],
        model: str | None = None,
    ) -> Classified:
        """Score each image against every label; one result per image."""
        return self._loop.run(self._async.classify(images, labels=labels, model=model))

    def match(
        self, images: Image | Sequence[Image], *, queries: Sequence[str]
    ) -> Matched:
        """Score each image against every query; one result per image."""
        return self._loop.run(self._async.match(images, queries=queries))

    def acic_pow(
        self, challenge_type: str, html: str, *, timeout: float = 90
    ) -> AcicPow:
        """Generate the response for the current ACIC proof-of-work challenge."""
        return self._loop.run(
            self._async.acic_pow(challenge_type, html, timeout=timeout)
        )

    def acic_waf(
        self, problem: Mapping[str, object], *, timeout: float | None = None
    ) -> AcicWaf:
        """Generate image indexes for an original AWS WAF problem."""
        return self._loop.run(self._async.acic_waf(problem, timeout=timeout))

    def close(self) -> None:
        if not self._closed:
            try:
                self._loop.run(self._async.aclose())
            finally:
                self._loop.close()
                self._closed = True

    def __enter__(self) -> Self:
        self._loop.run(self._async.__aenter__())
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class Session:
    def __init__(self, client: Nullgate, active: aio.Session) -> None:
        self._client, self._active = client, active

    def page(
        self,
        url: str,
        html: str,
        *,
        document_id: UUID | str | None = None,
        started_at_ms: int | None = None,
    ) -> "Page":
        return Page(
            self._client,
            self._active.page(
                url, html, document_id=document_id, started_at_ms=started_at_ms
            ),
        )


class Page:
    def __init__(self, client: Nullgate, active: aio.Page) -> None:
        self._client, self._active = client, active

    @property
    def sensor_url(self) -> str | None:
        return self._active.sensor_url

    @property
    def pixel_url(self) -> str | None:
        return self._active.pixel_url

    @property
    def sbsd_url(self) -> str | None:
        return self._active.sbsd_url

    def sensor(
        self,
        *,
        script: str,
        cookies: object,
        inputs: aio.Inputs | None = None,
        actions: Sequence[Mapping[str, object]] | None = None,
        script_url: str | None = None,
    ) -> Request:
        value = self._client._loop.run(
            self._active.sensor(
                script=script,
                cookies=cookies,
                inputs=inputs,
                actions=actions,
                script_url=script_url,
            )
        )
        return Request(
            value.url,
            value.body,
            value.headers,
            value.send_at,
            value.request_id,
            _reporter=self._client.report,
        )

    def pixel(
        self,
        *,
        script: str,
        script_url: str | None = None,
        challenge: str | None = None,
    ) -> Request:
        value = self._client._loop.run(
            self._active.pixel(
                script=script, script_url=script_url, challenge=challenge
            )
        )
        return Request(
            value.url,
            value.body,
            value.headers,
            value.send_at,
            value.request_id,
            _reporter=self._client.report,
        )

    def sbsd(
        self, *, script: str, cookies: object, script_url: str | None = None
    ) -> Request:
        value = self._client._loop.run(
            self._active.sbsd(script=script, cookies=cookies, script_url=script_url)
        )
        return Request(
            value.url,
            value.body,
            value.headers,
            value.send_at,
            value.request_id,
            _reporter=self._client.report,
        )

    def fwcim(
        self,
        *,
        form: str | None = None,
        timing: Mapping[str, int],
        inputs: aio.Inputs | None = None,
        actions: Sequence[Mapping[str, object]] | None = None,
        cookies: object = None,
        submitted: bool = True,
        referrer: str = "",
        history_length: int | None = None,
    ) -> Fwcim:
        value = self._client._loop.run(
            self._active.fwcim(
                form=form,
                timing=timing,
                inputs=inputs,
                actions=actions,
                cookies=cookies,
                submitted=submitted,
                referrer=referrer,
                history_length=history_length,
            )
        )
        return Fwcim(
            value.metadata1,
            value.headers,
            value.send_at,
            value.request_id,
            _reporter=self._client.report,
        )

    def threatmetrix(
        self,
        *,
        send: TargetFetch,
        script_url: str | None = None,
        collector: Mapping[str, str] | None = None,
        proxy: str | None = None,
        inputs: aio.Inputs | None = None,
        actions: Sequence[Mapping[str, object]] | None = None,
    ) -> AbstractContextManager[Profile]:
        return _ProfileContext(
            self, send, script_url, collector, proxy, inputs, actions
        )


class _ProfileContext(AbstractContextManager[Profile]):
    def __init__(
        self,
        page: Page,
        send: TargetFetch,
        script_url: str | None,
        collector: Mapping[str, str] | None,
        proxy: str | None,
        inputs: aio.Inputs | None,
        actions: Sequence[Mapping[str, object]] | None,
    ) -> None:
        self._client = page._client
        self._context = page._active.threatmetrix(
            send=send,
            script_url=script_url,
            collector=collector,
            proxy=proxy,
            inputs=inputs,
            actions=actions,
        )

    def __enter__(self) -> Profile:
        active = self._client._loop.run(self._context.__aenter__())
        return Profile(active, self._client._loop)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._client._loop.run(self._context.__aexit__(exc_type, exc, tb))
