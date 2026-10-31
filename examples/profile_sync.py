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
    ThreatMetrixCollector,
    ThreatMetrixParams,
    WreqTarget,
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)


def main() -> None:
    proxy = os.environ.get("TARGET_PROXY") or None
    collector_url = os.environ.get("TMX_COLLECTOR_URL")
    entry_values = (
        collector_url,
        os.environ.get("TMX_ORG_ID"),
        os.environ.get("TMX_SESSION_ID"),
    )
    if any(value is not None for value in entry_values) and not all(
        value and value.strip() for value in entry_values
    ):
        raise ValueError(
            "Set TMX_COLLECTOR_URL, TMX_ORG_ID and TMX_SESSION_ID together"
        )
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
        if collector_url is not None:
            protection: ThreatMetrix | ThreatMetrixCollector = ThreatMetrixCollector(
                page,
                collector_url,
                os.environ["TMX_ORG_ID"],
                os.environ["TMX_SESSION_ID"],
            )
        else:
            [found] = client.find_protections(page, where=F.provider == "threatmetrix")
            if not isinstance(found, ThreatMetrix):
                raise TypeError("Expected a ThreatMetrix protection")
            protection = found
        with session.profile(
            ThreatMetrixParams(protection), WreqTarget(http, proxy=proxy)
        ) as profile:
            print(f"Profiling startup delivered request_id={profile.request_id}")
            # Keep the handle alive during document activity; departure is explicit.
            profile.pagehide()


if __name__ == "__main__":
    main()
