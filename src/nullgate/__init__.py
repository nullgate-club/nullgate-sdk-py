"""Sync and async HTTPX clients for Nullgate."""

from collections.abc import Generator, Mapping, Sequence
from typing import Any, TypedDict, cast
from uuid import UUID

import httpx

from .cookies import abck_counters, is_enough
from .html import get_pixel_challenge
from .inputs import prepare_inputs

_BASE_URL = "https://akamai.nullgate.club"

__all__ = [
    "AsyncSession",
    "PixelResponse",
    "SensorDataResponse",
    "Session",
    "async_open_session",
    "abck_counters",
    "get_pixel_challenge",
    "is_enough",
    "open_session",
    "prepare_inputs",
]


class PixelResponse(TypedDict):
    """Pixel body and earliest target POST time in Unix seconds."""

    url: str
    body: str
    send_at: float
    headers: dict[str, str]


class SensorDataResponse(TypedDict):
    """Sensor body and earliest target POST time in Unix seconds."""

    sensor_data: str
    send_at: float
    headers: dict[str, str]


class _StateAuth(httpx.Auth):
    def __init__(self) -> None:
        self._state_id: str | None = None

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        if self._state_id is None:
            request.headers.pop("X-State-ID", None)
        else:
            request.headers["X-State-ID"] = self._state_id
        response = yield request
        state_id = response.headers.get("X-State-ID")
        if state_id is not None:
            self._state_id = state_id


def _pixel_payload(
    website: Mapping[str, str],
    script: Mapping[str, str],
    challenge: str,
    timezone: str | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "website": dict(website),
        "script": dict(script),
        "challenge": challenge,
    }
    if timezone is not None:
        payload["timezone"] = timezone
    return payload


def _sensor_payload(
    website: Mapping[str, str],
    script: Mapping[str, str],
    cookies: Mapping[str, str] | None,
    inputs: Sequence[Mapping[str, str]] | None,
    actions: Sequence[Mapping[str, object]] | None,
    timezone: str | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "website": dict(website),
        "script": dict(script),
        "cookies": dict(cookies or {}),
    }
    if timezone is not None:
        payload["timezone"] = timezone
    if actions is not None:
        payload["actions"] = [dict(action) for action in actions]
    if inputs is not None:
        payload["inputs"] = prepare_inputs(inputs)
    return payload


class Session(httpx.Client):
    """Native HTTPX client; use open_session() to enable state continuation."""

    def __init__(
        self, *, uuid: UUID | str, api_key: str | None = None, **kwargs: Any
    ) -> None:
        self.uuid = uuid if isinstance(uuid, UUID) else UUID(uuid)
        super().__init__(**kwargs)
        if api_key is not None:
            self.headers["Authorization"] = f"Bearer {api_key}"

    def pixel(
        self,
        *,
        website: Mapping[str, str],
        script: Mapping[str, str],
        user_agent: str,
        challenge: str,
        timezone: str | None = None,
    ) -> PixelResponse:
        """Generate a pixel for the supplied website and explicit challenge."""
        response = self.post(
            f"/v1/{self.uuid}/generate",
            params={"type": "pixel"},
            headers={"User-Agent": user_agent},
            json=_pixel_payload(website, script, challenge, timezone),
        )
        response.raise_for_status()
        return cast(PixelResponse, response.json())

    def sensor_data(
        self,
        *,
        website: Mapping[str, str],
        script: Mapping[str, str],
        user_agent: str,
        cookies: Mapping[str, str] | None = None,
        inputs: Sequence[Mapping[str, str]] | None = None,
        actions: Sequence[Mapping[str, object]] | None = None,
        timezone: str | None = None,
    ) -> SensorDataResponse:
        """Send website HTML and summaries of explicitly supplied input values."""
        response = self.post(
            f"/v1/{self.uuid}/generate",
            params={"type": "akamai"},
            headers={"User-Agent": user_agent},
            json=_sensor_payload(website, script, cookies, inputs, actions, timezone),
        )
        response.raise_for_status()
        return cast(SensorDataResponse, response.json())


class AsyncSession(httpx.AsyncClient):
    """Native async HTTPX client; use async_open_session() for continuation."""

    def __init__(
        self, *, uuid: UUID | str, api_key: str | None = None, **kwargs: Any
    ) -> None:
        self.uuid = uuid if isinstance(uuid, UUID) else UUID(uuid)
        super().__init__(**kwargs)
        if api_key is not None:
            self.headers["Authorization"] = f"Bearer {api_key}"

    async def pixel(
        self,
        *,
        website: Mapping[str, str],
        script: Mapping[str, str],
        user_agent: str,
        challenge: str,
        timezone: str | None = None,
    ) -> PixelResponse:
        """Generate a pixel for the supplied website and explicit challenge."""
        response = await self.post(
            f"/v1/{self.uuid}/generate",
            params={"type": "pixel"},
            headers={"User-Agent": user_agent},
            json=_pixel_payload(website, script, challenge, timezone),
        )
        response.raise_for_status()
        return cast(PixelResponse, response.json())

    async def sensor_data(
        self,
        *,
        website: Mapping[str, str],
        script: Mapping[str, str],
        user_agent: str,
        cookies: Mapping[str, str] | None = None,
        inputs: Sequence[Mapping[str, str]] | None = None,
        actions: Sequence[Mapping[str, object]] | None = None,
        timezone: str | None = None,
    ) -> SensorDataResponse:
        """Send website HTML and summaries of explicitly supplied input values."""
        response = await self.post(
            f"/v1/{self.uuid}/generate",
            params={"type": "akamai"},
            headers={"User-Agent": user_agent},
            json=_sensor_payload(website, script, cookies, inputs, actions, timezone),
        )
        response.raise_for_status()
        return cast(SensorDataResponse, response.json())


def open_session(
    base_url: str = _BASE_URL,
    *,
    uuid: UUID | str,
    api_key: str | None = None,
    **kwargs: Any,
) -> Session:
    """Create a stateful client; send requests sequentially within its context."""
    return Session(
        uuid=uuid, api_key=api_key, base_url=base_url, auth=_StateAuth(), **kwargs
    )


def async_open_session(
    base_url: str = _BASE_URL,
    *,
    uuid: UUID | str,
    api_key: str | None = None,
    **kwargs: Any,
) -> AsyncSession:
    """Create a stateful async client; await requests sequentially."""
    return AsyncSession(
        uuid=uuid, api_key=api_key, base_url=base_url, auth=_StateAuth(), **kwargs
    )
