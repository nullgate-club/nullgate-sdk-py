"""Explicit collector entry for Kleinanzeigen's wenkse wrapper; no JS execution.

Set TARGET_URL, NULLGATE_API_KEY and optionally TARGET_PROXY/TMX_SESSION_ID.
The URL algorithm follows the public threatmetrix.js wrapper, not SDK discovery.
"""

import os
from datetime import timedelta
from math import floor
from random import random
from uuid import uuid4

from wreq import Emulation, Jar, Platform, Profile, Proxy, redirect
from wreq.blocking import Client

from nullgate import (
    NullgateClient,
    Page,
    ThreatMetrixCollector,
    ThreatMetrixParams,
    WreqTarget,
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)
ORG_ID = "181rzcrc"


def _base36(value: int) -> str:
    digits = []
    while value:
        value, digit = divmod(value, 36)
        digits.append("0123456789abcdefghijklmnopqrstuvwxyz"[digit])
    return "".join(reversed(digits))


def collector_url(session_id: str) -> str:
    """Port of the wrapper's URL builder for joke(session_id, '94')."""
    lower = 78_364_164_096
    span = 2_742_745_743_359

    def draw() -> int:
        return floor(random() * span)

    def token() -> str:
        return _base36(draw() + lower)

    first, second = draw(), draw()
    second = (second - second % 256 + 6 + first) % span
    org_key = _base36((885_187_064_159 + first) % span + lower) + _base36(
        second + lower
    )
    path = token() + _base36(first + lower)
    session_key = token() + token()
    extra_key = token() + token()
    return (
        f"https://dfme.kleinanzeigen.de/{path}.js?{org_key}={ORG_ID}"
        f"&{session_key}={session_id}&{extra_key}=94"
    )


def main() -> None:
    proxy = os.environ.get("TARGET_PROXY") or None
    # Use the same value in sessionStorage and the site's hidden form field.
    session_id = os.environ.get("TMX_SESSION_ID") or str(uuid4())
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
            response.raise_for_status()
            page = Page(response.url, response.text())
        protection = ThreatMetrixCollector(
            page, collector_url(session_id), ORG_ID, session_id
        )
        with session.profile(
            ThreatMetrixParams(protection), WreqTarget(http, proxy=proxy)
        ) as profile:
            print(f"Profiling startup delivered request_id={profile.request_id}")
            profile.wait_collected()
            # Application requests must use this session_id in ulp-wenkse-session-id.
            # This example performs no login; leaving its document is explicit.
            profile.pagehide()


if __name__ == "__main__":
    main()
