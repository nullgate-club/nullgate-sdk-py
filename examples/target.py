"""One generation or profiling document with Python 3.11+ and wreq==0.13.0."""

import asyncio
import os
from urllib.parse import urlsplit
from uuid import uuid4

from wreq import Client, Emulation, Jar, Platform, Profile, Proxy, redirect

from nullgate import (
    NullgateClientAsync,
    Page,
    ThreatMetrix,
    ThreatMetrixParams,
    WreqTarget,
)
from nullgate.akamai import Pixel, PixelParams, Sbsd, SbsdParams, Sensor, SensorParams

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)


async def main() -> None:
    jar = Jar()
    proxy = os.environ.get("TARGET_PROXY") or None
    target = Client(
        emulation=Emulation(Profile.Chrome146, Platform.Windows),
        user_agent=USER_AGENT,
        cookie_provider=jar,
        proxies=[Proxy.all(proxy)] if proxy else [],
        no_proxy=proxy is None,
        redirect=redirect.Policy.none(),
    )
    client = NullgateClientAsync(
        os.environ["NULLGATE_API_KEY"],
        base_url=os.environ.get("NULLGATE_BASE_URL", "https://akamai.nullgate.club"),
        profile_base_url=os.environ.get(
            "NULLGATE_PROFILE_BASE_URL", "https://threatmetrix.nullgate.club"
        ),
        analytics_url=os.environ.get(
            "ANALYTICS_URL", "https://analytics.nullgate.club"
        ),
    )
    async with target, client:
        response = await target.get(os.environ["TARGET_URL"])
        page = Page(url=response.url, html=await response.text())
        protections = client.find_protections(page)
        if not protections:
            print(
                f"GET HTTP {response.status.as_int()}: no supported protection found."
            )
            response.raise_for_status()
            return
        [protection] = protections
        if isinstance(protection, ThreatMetrix):
            async with client.open(
                identity=os.environ.get("NULLGATE_IDENTITY") or uuid4(),
                user_agent=USER_AGENT,
            ) as session:
                async with await session.profile(
                    ThreatMetrixParams(protection), WreqTarget(target, proxy=proxy)
                ) as profile:
                    print(
                        f"Profiling startup delivered request_id={profile.request_id}"
                    )
                    # This example deliberately leaves the document here.
                    await profile.pagehide()
            return
        source = await target.get(protection.script_url, headers={"Referer": page.url})
        source.raise_for_status()
        script = await source.text()

        params: PixelParams | SensorParams | SbsdParams
        match protection:
            case Pixel():
                params = PixelParams(protection, script)
            case Sensor():
                params = SensorParams(
                    protection,
                    script,
                    cookies={
                        name: cookie.value
                        for name in ("_abck", "bm_sz")
                        if (cookie := jar.get(name, page.url)) is not None
                        if not cookie.http_only
                    },
                )
            case Sbsd():
                params = SbsdParams(
                    protection,
                    script,
                    cookies={
                        name: cookie.value
                        for name in ("bm_so", "sbsd_o", "bm_s")
                        if (cookie := jar.get(name, page.url)) is not None
                        if not cookie.http_only
                    },
                )

        async with client.open(
            identity=os.environ.get("NULLGATE_IDENTITY") or uuid4(),
            user_agent=USER_AGENT,
        ) as session:
            solution = await session.solve(params)
            await solution.wait()
            origin = urlsplit(page.url)
            result = await target.post(
                solution.url,
                body=solution.body,
                headers={
                    "Referer": page.url,
                    "Origin": f"{origin.scheme}://{origin.netloc}",
                    **solution.headers,
                },
            )
            print(
                f"POST HTTP {result.status.as_int()} request_id={solution.request_id}"
            )
            print(await result.text())
            result.raise_for_status()


if __name__ == "__main__":
    asyncio.run(main())
