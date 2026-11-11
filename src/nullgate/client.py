"""Synchronous facade over the async implementation and its owned event loop."""

import time
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime
from types import TracebackType
from typing import Any, Self
from uuid import UUID

from . import aio
from .profile import Profile, _ProfileLoop
from .target import TargetFetch


@dataclass(frozen=True, slots=True)
class Request:
    url: str
    body: str = field(repr=False)
    headers: dict[str, str]
    send_at: float
    request_id: str

    def wait(self) -> None:
        time.sleep(max(0.0, self.send_at - time.time()))


@dataclass(frozen=True, slots=True)
class Fwcim:
    metadata1: str = field(repr=False)
    headers: dict[str, str]
    send_at: float
    request_id: str

    def wait(self) -> None:
        time.sleep(max(0.0, self.send_at - time.time()))


class Nullgate:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = "https://api.nullgate.club",
        timeout: float = 30,
    ) -> None:
        self._async = aio.Nullgate(api_key, base_url=base_url, timeout=timeout)
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

    def close(self) -> None:
        if not self._closed:
            try:
                self._loop.run(self._async.aclose())
            finally:
                self._loop.close()
                self._closed = True

    def __enter__(self) -> Self:
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

    def page(self, url: str, html: str) -> "Page":
        return Page(self._client, self._active.page(url, html))


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
            value.url, value.body, value.headers, value.send_at, value.request_id
        )

    def pixel(self, *, script: str, script_url: str | None = None) -> Request:
        value = self._client._loop.run(
            self._active.pixel(script=script, script_url=script_url)
        )
        return Request(
            value.url, value.body, value.headers, value.send_at, value.request_id
        )

    def sbsd(
        self, *, script: str, cookies: object, script_url: str | None = None
    ) -> Request:
        value = self._client._loop.run(
            self._active.sbsd(script=script, cookies=cookies, script_url=script_url)
        )
        return Request(
            value.url, value.body, value.headers, value.send_at, value.request_id
        )

    def fwcim(
        self,
        *,
        form: str,
        timing: Mapping[str, int],
        inputs: aio.Inputs,
        actions: Sequence[Mapping[str, object]] | None = None,
        cookies: object = None,
    ) -> Fwcim:
        value = self._client._loop.run(
            self._active.fwcim(
                form=form,
                timing=timing,
                inputs=inputs,
                actions=actions,
                cookies=cookies,
            )
        )
        return Fwcim(value.metadata1, value.headers, value.send_at, value.request_id)

    def threatmetrix(
        self,
        *,
        send: TargetFetch,
        script_url: str | None = None,
        collector: Mapping[str, str] | None = None,
        proxy: str | None = None,
    ) -> AbstractContextManager[Profile]:
        return _ProfileContext(self, send, script_url, collector, proxy)


class _ProfileContext(AbstractContextManager[Profile]):
    def __init__(
        self,
        page: Page,
        send: TargetFetch,
        script_url: str | None,
        collector: Mapping[str, str] | None,
        proxy: str | None,
    ) -> None:
        self._client = page._client
        self._context = page._active.threatmetrix(
            send=send, script_url=script_url, collector=collector, proxy=proxy
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
