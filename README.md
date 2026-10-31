<img src="https://raw.githubusercontent.com/nullgate-club/nullgate-sdk-py/main/assets/logo.svg" alt="Nullgate" width="280">

# Nullgate Python SDK

Typed sync and async clients, local protection discovery, document sessions,
ready-to-send Akamai solutions and active ThreatMetrix profiles. Your HTTP client
owns target requests and cookies; private collectors stay on the service.

The defaults are `https://akamai.nullgate.club` for generation,
`https://threatmetrix.nullgate.club` for profiling, and
`https://analytics.nullgate.club` for optional diagnostic reports.

## Install

Python 3.11–3.15 and Git are required. Install from public GitHub, not PyPI;
`wreq` below is an optional target adapter, not a required SDK import.

```sh
python -m pip install "git+https://github.com/nullgate-club/nullgate-sdk-py.git" "wreq==0.13.0"
export NULLGATE_API_KEY='your-account-key'
export TARGET_URL='https://your-target.example/page'
```

Optional: set `NULLGATE_IDENTITY` to reuse a profile UUID; otherwise the example
creates a fresh UUID. `ANALYTICS_URL` overrides the reporting endpoint.
`NULLGATE_PROFILE_BASE_URL` overrides the profiling endpoint for local verification.
`TARGET_PROXY` optionally selects the same proxy for target HTTP and TURN;
unset/empty explicitly means direct. The API WebSocket never adopts that proxy
or environment proxy settings.
Never send your Nullgate API key to the target site.

## Run one generation

Save this as `target.py` and run `python target.py`. The same script is in
[`examples/target.py`](examples/target.py).

```python
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
        analytics_url=os.environ.get("ANALYTICS_URL", "https://analytics.nullgate.club"),
    )
    async with target, client:
        response = await target.get(os.environ["TARGET_URL"])
        page = Page(url=response.url, html=await response.text())
        protections = client.find_protections(page)
        if not protections:
            print(f"GET HTTP {response.status.as_int()}: no supported protection found.")
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
                    print(f"Profiling startup delivered request_id={profile.request_id}")
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
            identity=os.environ.get("NULLGATE_IDENTITY") or uuid4(), user_agent=USER_AGENT
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
            print(f"POST HTTP {result.status.as_int()} request_id={solution.request_id}")
            print(await result.text())
            result.raise_for_status()


if __name__ == "__main__":
    asyncio.run(main())
```

`solution.wait()` respects the server's earliest send time. Send `solution.body`
unchanged; do not JSON-encode it again. Keep the Chrome 146/Windows preset,
User-Agent and profile identity coherent.

The example reads only the named, non-HttpOnly cookies exposed by native
`Jar.get(name, page.url)`, not a full browser cookie capture. In wreq 0.13 that
getter matches domains exactly, so it can omit parent-domain cookies even when
the target transport sends them. It does not reconstruct cookie scope.

One POST is one generation, not proof of clearance. If the target requires more
sensor generations, keep the session and target jar, pass the current cookie
values and solve again. For blocking SBSD, fetch the original page again and
check the result. A new Akamai document needs a new session; reuse the identity
and jar. TMX keeps service storage keys within its session across new Pages.

## Discovery

`Page(url=..., html=...)` contains the document you fetched. Both client methods
and `nullgate.html.find_protections` are synchronous and local: they do not fetch
scripts or execute JavaScript. Sensor detection is a same-origin extensionless
classic-script heuristic; the service validates the source you supply.
ThreatMetrix discovery recognizes active `script[src]` URLs ending in `/tags.js`
with exactly one nonempty `org_id` and `session_id`, including cross-origin URLs.
Ambiguity is checked across all supported providers, not separately per provider.

Discovery returns a list: no candidates gives `[]`, one gives a single-element
list. More than one raises `AmbiguousProtectionError`, a `ValueError` exported
from `nullgate`. Filtering runs before that check:

```python
from nullgate import F

protections = client.find_protections(page, where=F.kind == "sensor")
candidates = client.find_protections(page, panic=False)
```

`panic=False` retains every candidate in document order, including duplicate
occurrences and their provenance. It never picks or deduplicates for you. Use an
explicit filter to select a candidate, and `match` to narrow its concrete type.
`NullgateClient` offers the same flow synchronously with `with` and no `await`.

## Active ThreatMetrix profiles

Unlike `solve`, `session.profile` returns a live document handle, not a POST
instruction. Startup has been delivered when it returns; background collectors,
target HTTP operations and TURN allocation lifetimes continue until the service
releases them or you close the handle. This is not evidence of target acceptance.

`ThreatMetrixParams` accepts the same optional `inputs` and `actions` observations
as `SensorParams`, using the existing `InputValue`/`prepare_inputs` vocabulary.
Input values are summarized locally; raw input/change action strings are rejected
before opening the paid socket. `None` omits a collection; explicit `[]` is sent
as `[]`. No keystrokes or field observations are recorded automatically.

```python
from nullgate import F, ThreatMetrix, ThreatMetrixParams, WreqTarget

[protection] = client.find_protections(page, where=F.provider == "threatmetrix")
if not isinstance(protection, ThreatMetrix):
    raise TypeError("Expected ThreatMetrix")

# http is your existing wreq.Client, configured for the same proxy/direct route.
target = WreqTarget(http, proxy=None)  # Required explicit direct choice.
async with await session.profile(ThreatMetrixParams(protection), target) as profile:
    print(profile.request_id)
    # Perform the document's application activity while this handle remains alive.
    await profile.pagehide()  # Samples wall-clock milliseconds at actual departure.
```

`await profile.pagehide(at_ms=..., persisted=True)` forwards a persisted departure
without implicitly closing. `await profile.aclose()` only cancels source work;
it never invents pagehide. Session/client close also closes their owned profiles,
but never the caller's target HTTP client. For explicit lifetime completion,
`await profile.wait_collected()` waits for `collected` and raises on failure.
`profile.is_collected` is false after failure or closure. A service-side failure
after startup is available as `profile.error` and is raised by `pagehide`,
`wait_collected`, or `raise_for_error`.

Synchronous code uses `NullgateClient`, `with session.profile(...) as profile`,
`profile.pagehide()`, `profile.wait_collected()` and `profile.close()`, without
`await`. A dedicated client-owned event-loop thread services its socket and
TURN between calls. See [`examples/profile_sync.py`](examples/profile_sync.py);
[`examples/target.py`](examples/target.py) supports both Akamai and TMX.

For a caller-resolved collector, skip discovery and keep the original page:

```python
from nullgate import ThreatMetrixCollector

protection = ThreatMetrixCollector(page, collector_url, org_id, session_id)
async with await session.profile(ThreatMetrixParams(protection), target) as profile:
    # Keep this handle for the document's lifetime.
    await profile.pagehide()
```

The URL must be absolute HTTP(S); it is sent unchanged with explicit organization
and session IDs, even when its query keys are opaque. Resolve site-specific wrappers
in your application; do not fabricate a tags script or use a `noscript` fallback.
Use the same session ID in any associated form field, not the Nullgate state ID.
The sync profile example accepts `TMX_COLLECTOR_URL`, `TMX_ORG_ID` and
`TMX_SESSION_ID` together. HTTP, proxy, cookie and lifecycle ownership are unchanged.

[`examples/kleinanzeigen.py`](examples/kleinanzeigen.py) shows a caller-owned port
of the current public `wenkse` URL builder. Run it with `TARGET_URL` and
`NULLGATE_API_KEY`; optionally reuse `TMX_SESSION_ID` and set `TARGET_PROXY`.
It waits for collection, then explicitly leaves, without attempting login.
The site-specific builder is example code, not a parser or execution dependency
of the SDK; inspect/update it if that site's wrapper changes.

For a different maintained HTTP provider, use `Target(fetch, proxy=...)`.
The callback accepts a `TargetRequest` (`role`, `url`, `method`, `headers`,
raw `body: bytes | None`, and `credentials`) and returns a
`TargetResponse(status, headers, body: bytes)`. It must enforce credentials:
`include` uses your real jar; `omit` neither sends nor retains cookies.
Return non-2xx statuses unchanged and close your response resources.

The callback may also be `async def`. Blocking callbacks run off the socket
reader; set finite HTTP deadlines because Python cannot kill a running thread.
The caller's callback owns HTTP proxy selection; `Target.proxy` is used only
locally for TURN and is never sent to Nullgate. Supported TURN proxy URLs use
`http`, `socks4`, or `socks5` with an explicit port. Unsupported or malformed
proxy settings fail before a paid profile is opened, with no direct fallback.
TURN uses aioice's TCP Allocate/Refresh/release; no host or UDP socket candidates
are opened. Network allocation failure is missing evidence, not a fabricated IP.

`WreqTarget` accepts `wreq.Client` or `wreq.blocking.Client` from wreq 0.13.0.
It uses a fresh request-level provider Jar for `credentials="omit"`, so it does
not mutate or replace your global jar. Raw response bytes are base64-encoded
directly on the wire; invalid UTF-8 and HTTP errors are preserved.

## Errors and reports

`NullgateAPIError` retains `status_code`, `detail`, `request_id`, and the original
HTTPX request/response. Transport and malformed-response errors remain distinct.
Profiling has separate `ProfileServiceError`, `ProfileProtocolError`,
`ProfileTransportError`, and `ProfileClosedError` exceptions, all inheriting
`ProfileError` and retaining `request_id`, `status_code` (when known) and `detail`.
They do not invent an HTTPX Response or a successful Solution.

After an actual target failure, call `await solution.report()`,
`await profile.report()` or `await client.report(request_id)`; omit `await` in sync
code. Reports send only
the request ID to analytics, without account authorization or target cookies.
They do not retry or refund generation. `True` means HTTP delivery succeeded,
not report acceptance; network failures return `False`. Cancellation and local
programming errors propagate.

## Develop

```sh
make setup
make format
make check
make build
```

The gate checks formatting, typing and behavior, including the target example.
CI runs `make setup`, `make check` and `make build` on Python 3.11 and 3.15.
Builds produce local archives without publishing. More SDK documentation is at
[Quickstart](https://docs.nullgate.club/en/quickstart).
