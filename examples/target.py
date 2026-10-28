"""Run with Python 3.11+, the Git-installed SDK, and wreq==0.13.0."""

from __future__ import annotations

import asyncio
import os
from datetime import timedelta
from email.message import Message
from http.client import HTTPResponse
from http.cookiejar import CookieJar, DefaultCookiePolicy
from http.cookies import SimpleCookie
from io import BytesIO
from typing import TYPE_CHECKING, cast
from urllib.parse import urlsplit
from urllib.request import Request
from urllib.response import addinfourl
from uuid import UUID

from wreq import (
    Client,
    Emulation,
    Jar,
    Method,
    Platform,
    Profile,
    Proxy,
    Response,
    redirect,
)

from nullgate import NullgateClientAsync, Page, SolutionAsync
from nullgate.akamai import (
    Pixel,
    PixelParams,
    Sbsd,
    SbsdParams,
    Sensor,
    SensorParams,
    abck_counters,
    is_enough,
)

if TYPE_CHECKING:
    from wreq import Request as TargetRequest

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)


def remember_cookies(store: CookieJar, response: Response) -> None:
    # wreq's name lookup is not a document.cookie projection. Let stdlib own scope.
    hops = [(hop.previous, hop.headers) for hop in response.history]
    hops.append((response.url, response.headers))
    for url, headers in hops:
        message = Message()
        for value in headers.get_all("set-cookie"):
            message.add_header("Set-Cookie", bytes(value).decode("latin-1"))
        with addinfourl(BytesIO(), message, url) as wrapped:
            store.extract_cookies(cast(HTTPResponse, wrapped), Request(url))


def visible_cookies(store: CookieJar, url: str) -> dict[str, str]:
    visible = CookieJar(
        policy=DefaultCookiePolicy(
            strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain
        )
    )
    for cookie in store:
        # CookieJar retains the original spelling of nonstandard attributes.
        if not any(name.lower() == "httponly" for name in vars(cookie)["_rest"]):
            visible.set_cookie(cookie)
    request = Request(url)
    visible.add_cookie_header(request)
    names = [
        part.partition("=")[0].strip()
        for part in request.get_header("Cookie", "").split(";")
        if part.strip()
    ]
    if len(names) != len(set(names)):
        raise ValueError("Ambiguous cookie names; select the intended document scope")
    parsed = SimpleCookie()
    parsed.load(request.get_header("Cookie", ""))
    return {name: morsel.value for name, morsel in parsed.items()}


async def main() -> None:
    url = os.environ["TARGET_URL"]
    identity = UUID(os.environ["NULLGATE_IDENTITY"])
    report_failures = os.environ.get("REPORT_FAILURES") == "1"
    request_options: TargetRequest = {}
    if proxy := os.environ.get("TARGET_PROXY"):
        request_options["proxy"] = Proxy.all(proxy)

    target = Client(
        emulation=Emulation(Profile.Chrome146, Platform.Windows),
        user_agent=USER_AGENT,
        cookie_provider=Jar(),
        no_proxy=True,
        redirect=redirect.Policy.limited(5),
        timeout=timedelta(seconds=30),
    )
    observations = CookieJar(
        policy=DefaultCookiePolicy(
            strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain
        )
    )

    async def fetch(
        method: Method, destination: str, options: TargetRequest | None = None
    ) -> tuple[Response, str]:
        response = await target.request(
            method, destination, **(request_options | (options or {}))
        )
        remember_cookies(observations, response)
        return response, await response.text()

    async def deliver(solution: SolutionAsync, page: Page) -> None:
        await solution.wait()
        origin = urlsplit(page.url)
        response, _ = await fetch(
            Method.POST,
            solution.url,
            {
                "body": solution.body,
                "headers": {
                    "Referer": page.url,
                    "Origin": f"{origin.scheme}://{origin.netloc}",
                    **solution.headers,
                },
                "redirect": redirect.Policy.none(),
            },
        )
        print(f"POST HTTP {response.status.as_int()} request_id={solution.request_id}")
        if response.status.as_int() in (403, 429) and report_failures:
            await solution.report()
        response.raise_for_status()

    client = NullgateClientAsync(
        os.environ["NULLGATE_API_KEY"],
        base_url=os.environ.get("NULLGATE_BASE_URL", "https://akamai.nullgate.club"),
        analytics_url=os.environ.get(
            "ANALYTICS_URL", "https://analytics.nullgate.club"
        ),
    )
    async with target, client:
        response, html = await fetch(Method.GET, url)
        page = Page(url=response.url, html=html)
        while True:
            protections = client.find_protections(page)
            if not protections:
                response.raise_for_status()
                print("No supported protection remains in the supplied HTML.")
                return
            if len({type(item) for item in protections}) != len(protections):
                raise ValueError("Multiple candidates; select the intended protection")

            params: SensorParams | PixelParams | SbsdParams
            navigated = False
            # State belongs to this document, never to the navigation that follows.
            async with client.open(identity=identity, user_agent=USER_AGENT) as session:
                for protection in protections:
                    source, script = await fetch(
                        Method.GET,
                        protection.script_url,
                        {"headers": {"Referer": page.url}},
                    )
                    source.raise_for_status()
                    match protection:
                        case Sensor():
                            response_count = 0
                            generation = abck_counters(
                                visible_cookies(observations, page.url).get("_abck")
                            )[1]
                            for _ in range(4):
                                cookies = visible_cookies(observations, page.url)
                                cookie = cookies.get("_abck")
                                current_generation = abck_counters(cookie)[1]
                                if (
                                    current_generation >= 0
                                    and current_generation != generation
                                ):
                                    generation = current_generation
                                    response_count = 0
                                if is_enough(cookie, response_count=response_count):
                                    break
                                params = SensorParams(
                                    protection,
                                    script,
                                    cookies={
                                        name: value
                                        for name, value in cookies.items()
                                        if name in {"_abck", "bm_sz"}
                                    },
                                )
                                solution = await session.solve(params)
                                await deliver(solution, page)
                                response_count += 1
                            else:
                                cookie = visible_cookies(observations, page.url).get(
                                    "_abck"
                                )
                                current_generation = abck_counters(cookie)[1]
                                if (
                                    current_generation >= 0
                                    and current_generation != generation
                                ):
                                    response_count = 0
                                if not is_enough(cookie, response_count=response_count):
                                    if report_failures:
                                        await solution.report()
                                    raise RuntimeError(
                                        "No cookie clearance after four submissions; "
                                        "this ceiling is not a success signal."
                                    )
                        case Pixel():
                            params = PixelParams(protection, script)
                            await deliver(await session.solve(params), page)
                        case Sbsd():
                            params = SbsdParams(
                                protection,
                                script,
                                cookies=visible_cookies(observations, page.url),
                            )
                            solution = await session.solve(params)
                            await deliver(solution, page)
                            if protection.blocking:
                                response, html = await fetch(Method.GET, page.url)
                                response.raise_for_status()
                                next_page = Page(url=response.url, html=html)
                                if any(
                                    isinstance(item, Sbsd) and item.blocking
                                    for item in client.find_protections(next_page)
                                ):
                                    if report_failures:
                                        await solution.report()
                                    raise RuntimeError(
                                        "The blocking SBSD challenge remains"
                                    )
                                page = next_page
                                navigated = True
                                break
                        case _:
                            continue
            if not navigated:
                print("Submissions completed; verify the target action separately.")
                return


if __name__ == "__main__":
    asyncio.run(main())
