"""An explicitly direct/proxied profiling document with wreq's blocking client."""

import os
from datetime import timedelta
from uuid import uuid4

from wreq import Emulation, Jar, Platform, Profile, Proxy, redirect
from wreq.blocking import Client

from nullgate import (
    F,
    NullgateClient,
    Page,
    ThreatMetrix,
    ThreatMetrixParams,
    WreqTarget,
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)


def main() -> None:
    proxy = os.environ.get("TARGET_PROXY") or None
    with (
        Client(
            emulation=Emulation(Profile.Chrome146, Platform.Windows),
            user_agent=USER_AGENT,
            cookie_provider=Jar(),
            proxies=[Proxy.all(proxy)] if proxy else [],
            no_proxy=proxy is None,
            redirect=redirect.Policy.none(),
            timeout=timedelta(seconds=30),
        ) as http,
        NullgateClient(
            os.environ["NULLGATE_API_KEY"],
            profile_base_url=os.environ.get(
                "NULLGATE_PROFILE_BASE_URL", "https://threatmetrix.nullgate.club"
            ),
        ) as client,
        client.open(
            identity=os.environ.get("NULLGATE_IDENTITY") or uuid4(),
            user_agent=USER_AGENT,
        ) as session,
    ):
        with http.get(os.environ["TARGET_URL"]) as response:
            page = Page(response.url, response.text())
        [protection] = client.find_protections(page, where=F.provider == "threatmetrix")
        if not isinstance(protection, ThreatMetrix):
            raise TypeError("Expected a ThreatMetrix protection")
        with session.profile(
            ThreatMetrixParams(protection), WreqTarget(http, proxy=proxy)
        ) as profile:
            print(f"Profiling startup delivered request_id={profile.request_id}")
            # Keep the handle alive during document activity; departure is explicit.
            profile.pagehide()


if __name__ == "__main__":
    main()
