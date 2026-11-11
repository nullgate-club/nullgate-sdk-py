"""Set TARGET_URL and NULLGATE_API_KEY; optional TARGET_PROXY and TMX_SESSION_ID."""

import os
from math import floor
from random import random
from uuid import uuid4

import httpx

from nullgate import Nullgate, TargetRequest, TargetResponse

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
    """Port of the site's threatmetrix.js wrapper for joke(session_id, '94')."""
    lower, span = 78_364_164_096, 2_742_745_743_359

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
    session_key, extra_key = token() + token(), token() + token()
    return (
        f"https://dfme.kleinanzeigen.de/{path}.js?{org_key}={ORG_ID}"
        f"&{session_key}={session_id}&{extra_key}=94"
    )


def main() -> None:
    proxy = os.environ.get("TARGET_PROXY") or None
    session_id = os.environ.get("TMX_SESSION_ID") or str(uuid4())
    with (
        Nullgate() as ng,
        httpx.Client(
            headers={"User-Agent": USER_AGENT},
            proxy=proxy,
            trust_env=False,
            follow_redirects=False,
            timeout=30,
        ) as http,
    ):

        def my_send(request: TargetRequest) -> TargetResponse:
            headers = dict(request.headers)
            if request.credentials == "omit":
                headers = {
                    key: value
                    for key, value in headers.items()
                    if key.lower() != "cookie"
                }
                with httpx.Client(
                    headers={"User-Agent": USER_AGENT},
                    proxy=proxy,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=30,
                ) as isolated:
                    response = isolated.request(
                        request.method,
                        request.url,
                        headers=headers,
                        content=request.body,
                    )
            else:
                response = http.request(
                    request.method, request.url, headers=headers, content=request.body
                )
            return TargetResponse(
                response.status_code, dict(response.headers), response.content
            )

        response = http.get(os.environ["TARGET_URL"])
        response.raise_for_status()
        page = ng.session(user_agent=USER_AGENT).page(str(response.url), response.text)
        with page.threatmetrix(
            send=my_send,
            proxy=proxy,
            collector={
                "url": collector_url(session_id),
                "org_id": ORG_ID,
                "session_id": session_id,
            },
        ) as profile:
            print(f"Profiling startup delivered request_id={profile.request_id}")
            profile.wait_collected()
            # Use session_id in sessionStorage and ulp-wenkse-session-id in your app.
            # This example performs no login. Leaving the document is explicit.
            profile.pagehide()


if __name__ == "__main__":
    main()
