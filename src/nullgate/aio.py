"""Async API. Local session and page creation never perform network calls."""

import asyncio
import math
import os
import time
from collections.abc import Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import datetime
from types import TracebackType
from typing import Any, Self, cast
from urllib.parse import urljoin, urlsplit, urlunsplit
from uuid import UUID, uuid4

import httpx

from . import amazon
from .akamai.inputs import _prepare_actions, _prepared_input, prepare_inputs
from .errors import NullgateError, _retry_after
from .html import Candidate, discover
from .models import Page as Document
from .profile import ProfileAsync, _collector
from .target import Target, TargetFetch

__all__ = ["Nullgate", "NullgateError"]

Inputs = Mapping[str, str] | Sequence[Mapping[str, object]]


def _url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError
        _ = parsed.port
    except ValueError:
        raise NullgateError(
            "Expected an absolute HTTP(S) URL without credentials", code="invalid_url"
        ) from None
    return value


def _validate_generated(data: dict[str, Any], *, target_request: bool) -> None:
    try:
        value = data["request"] if target_request else data
        if not isinstance(value, dict):
            raise ValueError
        headers, send_at = value["headers"], value["send_at"]
        if not isinstance(headers, dict) or not all(
            isinstance(name, str) and isinstance(content, str)
            for name, content in headers.items()
        ):
            raise ValueError
        if type(send_at) not in (int, float) or not math.isfinite(send_at):
            raise ValueError
        if not all(
            isinstance(data[key], str) and data[key]
            for key in ("session", "request_id")
        ):
            raise ValueError
        if target_request:
            if not isinstance(value["url"], str) or not isinstance(value["body"], str):
                raise ValueError
            _url(value["url"])
        elif not isinstance(value["metadata1"], str):
            raise ValueError
    except (KeyError, TypeError, ValueError, NullgateError):
        raise NullgateError(
            "Invalid generation response", code="invalid_response"
        ) from None


def _cookies(cookies: object, names: set[str], url: str) -> dict[str, str]:
    jar = getattr(cookies, "jar", cookies)
    if isinstance(jar, Mapping):
        return {
            name: value
            for name, value in jar.items()
            if name in names and isinstance(value, str)
        }
    parsed = urlsplit(url)
    result: dict[str, str] = {}
    try:
        for cookie in cast(Any, jar):
            domain = cookie.domain.lstrip(".")
            path = cookie.path or "/"
            host = parsed.hostname or ""
            matches = host == domain or (
                cookie.domain_specified and host.endswith("." + domain)
            )
            request_path = parsed.path or "/"
            path_matches = request_path == path or request_path.startswith(
                path if path.endswith("/") else path + "/"
            )
            if (
                cookie.name in names
                and matches
                and path_matches
                and (not cookie.secure or parsed.scheme == "https")
                and not cookie.is_expired()
            ):
                result[cookie.name] = cookie.value
    except (TypeError, AttributeError):
        raise NullgateError(
            "cookies must be a mapping or cookie jar", code="invalid_cookies"
        ) from None
    return result


@dataclass(frozen=True, slots=True)
class Request:
    url: str
    body: str = field(repr=False)
    headers: dict[str, str]
    send_at: float
    request_id: str

    async def wait(self) -> None:
        await asyncio.sleep(max(0.0, self.send_at - time.time()))


@dataclass(frozen=True, slots=True)
class Fwcim:
    metadata1: str = field(repr=False)
    headers: dict[str, str]
    send_at: float
    request_id: str

    async def wait(self) -> None:
        await asyncio.sleep(max(0.0, self.send_at - time.time()))


class Nullgate:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = "https://api.nullgate.club",
        timeout: float = 30,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        key = os.environ.get("NULLGATE_API_KEY") if api_key is None else api_key
        if not key or not key.strip() or any(char in key for char in "\r\n"):
            raise NullgateError(
                "Set NULLGATE_API_KEY or pass api_key", code="invalid_key"
            )
        if not math.isfinite(timeout) or timeout <= 0:
            raise NullgateError(
                "timeout must be positive and finite", code="invalid_request"
            )
        parsed = urlsplit(_url(base_url))
        if parsed.query or parsed.fragment:
            raise NullgateError(
                "base_url cannot contain a query or fragment", code="invalid_url"
            )
        self._base_url = base_url.rstrip("/")
        self._key = key
        self._timeout = timeout
        self._http = httpx.AsyncClient(
            timeout=timeout,
            transport=transport,
            trust_env=False,
            follow_redirects=False,
        )
        self._profiles: set[ProfileAsync] = set()

    def session(
        self,
        *,
        user_agent: str,
        profile: UUID | str | None = None,
        timezone: str | None = None,
    ) -> "Session":
        return Session(self, user_agent, profile, timezone)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + self._timeout
        for attempt in range(3):
            if self._http.is_closed:
                raise NullgateError("Nullgate is closed", code="closed")
            try:
                response = await self._http.request(
                    method,
                    self._base_url + path,
                    headers={"Authorization": f"Bearer {self._key}"},
                    json=payload,
                    params=params,
                    timeout=max(0.001, deadline - time.monotonic()),
                )
            except httpx.HTTPError:
                raise NullgateError(
                    "Nullgate API transport failed", code="transport_error"
                ) from None
            try:
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError
            except ValueError:
                raise NullgateError(
                    "Invalid API response",
                    code="invalid_response",
                    status=response.status_code,
                ) from None
            if response.is_success:
                return cast(dict[str, Any], data)
            error = NullgateError(
                str(data.get("message", "Nullgate API request failed")).replace(
                    self._key, "[redacted]"
                ),
                code=str(data.get("code", "invalid_response")),
                request_id=data.get("request_id"),
                status=response.status_code,
            )
            delay = _retry_after(response.headers.get("Retry-After"))
            if (
                error.code != "maintenance"
                or attempt == 2
                or delay is None
                or time.monotonic() + delay >= deadline
            ):
                raise error
            await asyncio.sleep(delay)
        raise AssertionError("Unreachable retry")

    async def account(self) -> dict[str, Any]:
        return await self._request("GET", "/account")

    async def usage(
        self,
        *,
        interval: str = "hour",
        start: str | datetime | None = None,
        end: str | datetime | None = None,
    ) -> dict[str, Any]:
        params = {"interval": interval}
        for name, value in (("start", start), ("end", end)):
            if value is not None:
                params[name] = (
                    value.isoformat() if isinstance(value, datetime) else value
                )
        return await self._request("GET", "/account/usage", params=params)

    async def aclose(self) -> None:
        for profile in tuple(self._profiles):
            await profile.aclose()
        await self._http.aclose()

    async def __aenter__(self) -> Self:
        await self._http.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


class Session:
    def __init__(
        self,
        client: Nullgate,
        user_agent: str,
        profile: UUID | str | None,
        timezone: str | None,
    ) -> None:
        if (
            not isinstance(user_agent, str)
            or not user_agent.strip()
            or any(c in user_agent for c in "\r\n")
        ):
            raise NullgateError("user_agent must be nonempty", code="invalid_request")
        try:
            self._profile = (
                str(UUID(str(profile))) if profile is not None else str(uuid4())
            )
        except ValueError:
            raise NullgateError(
                "profile must be a UUID", code="invalid_request"
            ) from None
        self._client = client
        self._user_agent = user_agent
        self._timezone = timezone
        self._sessions: dict[str, str] = {}
        self._locks = {
            product: asyncio.Lock() for product in ("akamai", "amazon", "threatmetrix")
        }

    def page(self, url: str, html: str) -> "Page":
        try:
            document = Document(_url(url), html)
            amazon._document(document)
            return Page(self, document)
        except (ValueError, TypeError) as exc:
            raise NullgateError(str(exc), code="invalid_page") from None

    def _common(self, page: Document, product: str) -> dict[str, object]:
        values: dict[str, object] = {
            "profile": self._profile,
            "session": self._sessions.get(product),
            "user_agent": self._user_agent,
            "url": page.url,
            "html": page.html,
            "document_id": page.document_id,
            "started_at_ms": page.started_at_ms,
        }
        if self._timezone is not None:
            values["timezone"] = self._timezone
        return values


class Page:
    def __init__(self, session: Session, document: Document) -> None:
        self._session = session
        self._document = document
        self._candidates, self._pixel_challenges = discover(document)

    def _candidate(self, kind: str, script_url: str | None = None) -> Candidate | None:
        candidates = [
            c
            for c in self._candidates
            if c.kind == kind
            and (script_url is None or c.url == urljoin(self._document.url, script_url))
        ]
        if kind == "pixel" and script_url is not None:
            url = _url(urljoin(self._document.url, script_url))
            candidates = [
                Candidate(kind, url, challenge) for challenge in self._pixel_challenges
            ]
        if len(candidates) > 1:
            raise NullgateError(
                "Choose script_url from: "
                + ", ".join(
                    c.url + (f" (challenge {c.challenge})" if c.challenge else "")
                    for c in candidates
                ),
                code="ambiguous_protection",
            )
        if script_url is not None and kind != "pixel":
            return Candidate(kind, _url(urljoin(self._document.url, script_url)))
        return candidates[0] if candidates else None

    @property
    def sensor_url(self) -> str | None:
        c = self._candidate("sensor")
        return c.url if c else None

    @property
    def pixel_url(self) -> str | None:
        c = self._candidate("pixel")
        return c.url if c else None

    @property
    def sbsd_url(self) -> str | None:
        c = self._candidate("sbsd")
        return c.url if c else None

    def _inputs(
        self, inputs: Inputs | None, *, amazon_inputs: bool = False
    ) -> list[dict[str, object]]:
        observations: list[dict[str, object]] = []
        try:
            document = amazon._document(self._document)
            if isinstance(inputs, Mapping):
                fields: list[Mapping[str, object]] = []
                for key, text in inputs.items():
                    identity = "id" if document.find(id=key) is not None else "name"
                    fields.append({identity: key, "value": text})
            else:
                fields = list(inputs or [])
            for raw in fields:
                if "attributes" in raw or isinstance(raw.get("value"), Mapping):
                    if amazon_inputs:
                        if not raw.keys() <= {
                            "attributes",
                            "value",
                            "selector",
                            "checksum",
                            "geometry",
                            "text",
                        }:
                            raise ValueError("Unsupported prepared Amazon input fields")
                        base = _prepared_input(
                            {
                                key: item
                                for key, item in raw.items()
                                if key in {"attributes", "value", "selector"}
                            }
                        )
                        observation_data: dict[str, object] = dict(base)
                        observation_data.update(
                            {
                                key: raw[key]
                                for key in ("checksum", "geometry", "text")
                                if key in raw
                            }
                        )
                        observations.append(observation_data)
                    else:
                        observations.append(dict(_prepared_input(raw)))
                    continue
                field = dict(raw)
                value = field.pop("value", "")
                if not isinstance(value, str):
                    raise ValueError("Input value must be a string")
                identity_fields: dict[str, str] = {}
                for key in ("id", "name", "selector"):
                    if key in field:
                        if not isinstance(field[key], str):
                            raise ValueError("Input identity must contain strings")
                        identity_fields[key] = cast(str, field[key])
                node = amazon._input_node(
                    document,
                    {
                        key: value
                        for key, value in identity_fields.items()
                        if key != "selector"
                    },
                    identity_fields.get("selector"),
                )
                if amazon._password_control(node) or amazon._password_control(
                    cast(Any, field)
                ):
                    raise ValueError("Raw password observations are not allowed")
                observation = amazon.observe_input(
                    self._document,
                    value,
                    id=identity_fields.get("id"),
                    name=identity_fields.get("name"),
                    selector=identity_fields.get("selector"),
                )
                if amazon_inputs:
                    if not field.keys() <= {
                        "id",
                        "name",
                        "selector",
                        "geometry",
                        "text",
                    }:
                        raise ValueError("Unsupported Amazon input fields")
                    if "geometry" in field:
                        observation["geometry"] = cast(
                            amazon.Geometry, field["geometry"]
                        )
                    if "text" in field:
                        if field["text"] != value:
                            raise ValueError("Input text must equal its observed value")
                        observation["text"] = value
                    observations.append(dict(observation))
                else:
                    if any(not isinstance(value, str) for value in field.values()):
                        raise ValueError("Input attributes must contain strings")
                    observations.append(
                        dict(
                            prepare_inputs(
                                [cast(dict[str, str], {**field, "value": value})]
                            )[0]
                        )
                    )
            return observations
        except (ValueError, TypeError, AttributeError) as exc:
            raise NullgateError(str(exc), code="invalid_inputs") from None

    async def _generate(
        self,
        kind: str,
        *,
        script: str,
        script_url: str | None,
        cookies: object = None,
        inputs: Inputs | None = None,
        actions: Sequence[Mapping[str, object]] | None = None,
    ) -> Request:
        candidate = self._candidate(kind, script_url)
        if candidate is None:
            raise NullgateError(
                f"No {kind} script found. Pass script_url", code="protection_not_found"
            )
        session = self._session
        async with session._locks["akamai"]:
            payload = session._common(self._document, "akamai")
            payload.update(script_url=candidate.url, script=script)
            if kind == "pixel":
                payload["challenge"] = candidate.challenge
            else:
                names = (
                    {"_abck", "bm_sz"}
                    if kind == "sensor"
                    else {"bm_so", "sbsd_o", "bm_s"}
                )
                payload["cookies"] = _cookies(cookies or {}, names, self._document.url)
            if kind == "sensor":
                payload["inputs"] = self._inputs(inputs)
                try:
                    payload["actions"] = _prepare_actions(actions or [])
                except (ValueError, TypeError) as exc:
                    raise NullgateError(str(exc), code="invalid_actions") from None
            data = await session._client._request(
                "POST", f"/akamai/{kind}", payload=payload
            )
            try:
                _validate_generated(data, target_request=True)
                request = data["request"]
                # Same names and order as the TypeScript SDK.
                headers = {
                    **request["headers"],
                    "origin": urlunsplit(
                        (*urlsplit(self._document.url)[:2], "", "", "")
                    ),
                    "referer": self._document.url,
                }
                result = Request(
                    _url(request["url"]),
                    request["body"],
                    headers,
                    float(request["send_at"]),
                    data["request_id"],
                )
                session._sessions["akamai"] = data["session"]
                return result
            except (KeyError, TypeError, ValueError):
                raise NullgateError(
                    "Invalid generation response", code="invalid_response"
                ) from None

    async def sensor(
        self,
        *,
        script: str,
        cookies: object,
        inputs: Inputs | None = None,
        actions: Sequence[Mapping[str, object]] | None = None,
        script_url: str | None = None,
    ) -> Request:
        return await self._generate(
            "sensor",
            script=script,
            cookies=cookies,
            inputs=inputs,
            actions=actions,
            script_url=script_url,
        )

    async def pixel(self, *, script: str, script_url: str | None = None) -> Request:
        return await self._generate("pixel", script=script, script_url=script_url)

    async def sbsd(
        self, *, script: str, cookies: object, script_url: str | None = None
    ) -> Request:
        return await self._generate(
            "sbsd", script=script, cookies=cookies, script_url=script_url
        )

    async def fwcim(
        self,
        *,
        form: str,
        timing: Mapping[str, int],
        inputs: Inputs,
        actions: Sequence[Mapping[str, object]] | None = None,
        cookies: object = None,
    ) -> Fwcim:
        session = self._session
        try:
            document = Document(
                self._document.url,
                self._document.html,
                document_id=self._document.document_id,
                started_at_ms=timing["navigationStart"],
            )
            observations = cast(
                list[amazon.InputObservation], self._inputs(inputs, amazon_inputs=True)
            )
            values = amazon._payload(
                amazon._Params(
                    document,
                    timing,
                    cookies=_cookies(
                        cookies or {},
                        {"session-id", "session-token", "ubid-main"},
                        document.url,
                    ),
                    form_selector=form,
                    inputs=observations,
                    actions=actions or [],
                ),
                session._timezone,
            )
            website = cast(dict[str, object], values.pop("website"))
            values.update(website)
        except (ValueError, TypeError, KeyError) as exc:
            raise NullgateError(str(exc), code="invalid_inputs") from None
        async with session._locks["amazon"]:
            payload = session._common(document, "amazon")
            payload.update(values)
            data = await session._client._request(
                "POST", "/amazon/fwcim", payload=payload
            )
            try:
                _validate_generated(data, target_request=False)
                result = Fwcim(
                    data["metadata1"],
                    data["headers"],
                    float(data["send_at"]),
                    data["request_id"],
                )
                session._sessions["amazon"] = data["session"]
                return result
            except (KeyError, TypeError, ValueError):
                raise NullgateError(
                    "Invalid generation response", code="invalid_response"
                ) from None

    def threatmetrix(
        self,
        *,
        send: TargetFetch,
        script_url: str | None = None,
        collector: Mapping[str, str] | None = None,
        proxy: str | None = None,
    ) -> AbstractAsyncContextManager[ProfileAsync]:
        return _ProfileContext(self, send, script_url, collector, proxy)


class _ProfileContext(AbstractAsyncContextManager[ProfileAsync]):
    def __init__(
        self,
        page: Page,
        send: TargetFetch,
        script_url: str | None,
        collector: Mapping[str, str] | None,
        proxy: str | None,
    ) -> None:
        self._page, self._send, self._script_url, self._proxy = (
            page,
            send,
            script_url,
            proxy,
        )
        self._collector = collector
        self._active: ProfileAsync | None = None

    async def __aenter__(self) -> ProfileAsync:
        page, session = self._page, self._page._session
        if session._client._http.is_closed:
            raise NullgateError("Nullgate is closed", code="closed")
        if self._collector is not None:
            if self._script_url is not None:
                raise NullgateError(
                    "Pass collector or script_url, not both", code="invalid_request"
                )
            entry: dict[str, object] = {"collector": _collector(self._collector)}
        else:
            candidate = page._candidate("threatmetrix", self._script_url)
            if candidate is None:
                raise NullgateError(
                    "No ThreatMetrix tags.js found. Pass script_url or collector",
                    code="protection_not_found",
                )
            entry = {"tags_url": candidate.url}
        async with session._locks["threatmetrix"]:
            start = session._common(page._document, "threatmetrix")
            start.update(type="start", at_ms=time.time_ns() // 1_000_000, **entry)
            parsed = urlsplit(session._client._base_url)
            url = urlunsplit(
                (
                    "wss" if parsed.scheme == "https" else "ws",
                    parsed.netloc,
                    parsed.path + "/threatmetrix/profile",
                    "",
                    "",
                )
            )

            def on_state(value: str) -> None:
                session._sessions["threatmetrix"] = value

            def on_close() -> None:
                session._client._profiles.discard(active)

            try:
                target = Target(self._send, proxy=self._proxy)
            except (ValueError, TypeError) as exc:
                raise NullgateError(str(exc), code="invalid_request") from None
            active = ProfileAsync(
                url=url,
                api_key=session._client._key,
                start=start,
                target=target,
                on_state=on_state,
                on_close=on_close,
                open_timeout=session._client._timeout,
            )
            self._active = active
            session._client._profiles.add(active)
            await active._start()
            return active

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._active is not None:
            await self._active.aclose()
