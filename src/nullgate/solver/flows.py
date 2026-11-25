"""Target-side Akamai and ThreatMetrix solve flows."""

from collections.abc import Mapping
from urllib.parse import unquote, urljoin, urlsplit

from ..aio import Page, Request, Session
from ..akamai import abck_counters, is_enough
from ..errors import NullgateError
from .models import SolveError
from .transport import Transport


def _abck(transport: Transport, url: str) -> str | None:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    candidates = []
    for cookie in transport.cookies.jar:
        domain = cookie.domain.lstrip(".").lower()
        cookie_path = cookie.path or "/"
        matches_domain = host == domain or (
            cookie.domain_specified and host.endswith("." + domain)
        )
        matches_path = path == cookie_path or path.startswith(
            cookie_path if cookie_path.endswith("/") else cookie_path + "/"
        )
        if (
            cookie.name == "_abck"
            and matches_domain
            and matches_path
            and (not cookie.secure or parsed.scheme == "https")
            and not cookie.is_expired()
        ):
            candidates.append(cookie)
    if not candidates:
        return None
    return max(candidates, key=lambda cookie: len(cookie.path or "/")).value


def _accepted(value: str | None) -> bool:
    parts = unquote(value).split("~") if value is not None else []
    return len(parts) >= 2 and parts[1] == "0"


async def _page(session: Session, transport: Transport, url: str) -> tuple[Page, str]:
    response = await transport.request("GET", url, navigation=True)
    if not (200 <= response.status_code < 300 or response.status_code == 403):
        raise SolveError("target_error", "Target page request failed", stage="page")
    return session.page(str(response.url), response.text), str(response.url)


async def _script(transport: Transport, url: str) -> str:
    response = await transport.request("GET", url)
    if not 200 <= response.status_code < 300:
        raise SolveError("target_error", "Target script request failed", stage="script")
    return response.text


async def _post(transport: Transport, request: Request) -> None:
    await request.wait()
    response = await transport.request(
        "POST", request.url, headers=request.headers, body=request.body
    )
    if not 200 <= response.status_code < 300:
        raise SolveError("target_error", "Target submission failed", stage="target")


async def akamai(
    session: Session,
    transport: Transport,
    url: str,
    *,
    script_url: str | None = None,
    pixel_iframe: bool = False,
) -> None:
    stage = "page"
    try:
        page, page_url = await _page(session, transport, url)
        sbsd_url = page.sbsd_url
        if sbsd_url is not None:
            stage = "script"
            source = await _script(transport, sbsd_url)
            stage = "generate"
            request = await page.sbsd(
                script=source, cookies=transport.cookies, script_url=sbsd_url
            )
            stage = "target"
            await _post(transport, request)
            stage = "page"
            page, page_url = await _page(session, transport, page_url)
            if page.sbsd_url is not None:
                raise SolveError(
                    "solve_failed", "Unsupported SBSD challenge", stage="page"
                )

        sensor_url = urljoin(page_url, script_url) if script_url else page.sensor_url
        if sensor_url is None:
            raise SolveError(
                "protection_not_found", "Akamai sensor not found", stage="page"
            )
        stage = "script"
        source = await _script(transport, sensor_url)
        pixel_url = page.pixel_url

        cookie = _abck(transport, page_url)
        responses = 0
        generation = abck_counters(cookie)[1]
        if _accepted(cookie):
            return
        for index in range(4):
            if is_enough(cookie, response_count=responses):
                break
            stage = "generate"
            request = await page.sensor(
                script=source, cookies=transport.cookies, script_url=sensor_url
            )
            stage = "target"
            await _post(transport, request)
            responses += 1
            if index == 0 and pixel_url is not None:
                stage = "script"
                pixel_source = await _script(transport, pixel_url)
                stage = "generate"
                pixel = await page.pixel(
                    script=pixel_source, script_url=pixel_url, iframe=pixel_iframe
                )
                stage = "target"
                await _post(transport, pixel)
            cookie = _abck(transport, page_url)
            next_generation = abck_counters(cookie)[1]
            if next_generation != generation:
                responses = 0
                generation = next_generation
            if _accepted(cookie):
                return
        raise SolveError(
            "solve_failed", "Akamai cookie was not accepted", stage="target"
        )
    except NullgateError as exc:
        raise SolveError(
            exc.code,
            "Akamai generation failed",
            stage=stage,
            cause=type(exc.__cause__).__name__ if exc.__cause__ else None,
            request_id=exc.request_id,
            status=exc.status,
        ) from None


async def threatmetrix(
    session: Session,
    transport: Transport,
    url: str,
    *,
    script_url: str | None = None,
    collector: Mapping[str, str] | None = None,
) -> None:
    stage = "page"
    try:
        page, _ = await _page(session, transport, url)
        stage = "profile"
        async with page.threatmetrix(
            send=transport.send,
            proxy=transport.proxy,
            script_url=script_url,
            collector=collector,
        ) as profile:
            await profile.pagehide()
    except NullgateError as exc:
        raise SolveError(
            exc.code,
            "ThreatMetrix profile failed",
            stage=stage,
            cause=type(exc.__cause__).__name__ if exc.__cause__ else None,
            request_id=exc.request_id,
            status=exc.status,
        ) from None
