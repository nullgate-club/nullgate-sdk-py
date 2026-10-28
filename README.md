<img src="https://raw.githubusercontent.com/nullgate-club/nullgate-sdk-py/main/assets/logo.svg" alt="Nullgate" width="280">

# Nullgate Python SDK

Typed sync and async clients, local protection discovery, document sessions and
ready-to-send solutions. Your HTTP client owns target requests and cookies.

The `next` branch requires the updated backend, including `X-Request-ID` and
analytics reporting. Until backend cutover, point `NULLGATE_BASE_URL` at an
updated preview deployment. The existing `main` branch remains compatible with
the old production API.

## Install

Python 3.11–3.15 and Git are required. Install from public GitHub, not PyPI;
`wreq` is the target transport used below, not an SDK dependency.

```sh
python -m pip install "git+https://github.com/nullgate-club/nullgate-sdk-py.git@next" "wreq==0.13.0"
export NULLGATE_API_KEY='your-account-key'
export NULLGATE_BASE_URL='https://your-preview-api.example'
export TARGET_URL='https://your-target.example/page'
```

Optional: set `NULLGATE_IDENTITY` to reuse a profile UUID; otherwise the example
creates a fresh UUID. `ANALYTICS_URL` overrides the reporting endpoint.
Never send your Nullgate API key to the target site.

## Run one generation

Save this as `target.py` and run `python target.py`. The same script is in
[`examples/target.py`](examples/target.py).

```python
import asyncio
import os
from urllib.parse import urlsplit
from uuid import uuid4

from wreq import Client, Emulation, Jar, Platform, Profile, redirect

from nullgate import NullgateClientAsync, Page
from nullgate.akamai import Pixel, PixelParams, Sbsd, SbsdParams, Sensor, SensorParams

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)


async def main() -> None:
    jar = Jar()
    target = Client(
        emulation=Emulation(Profile.Chrome146, Platform.Windows),
        user_agent=USER_AGENT,
        cookie_provider=jar,
        no_proxy=True,
        redirect=redirect.Policy.none(),
    )
    client = NullgateClientAsync(
        os.environ["NULLGATE_API_KEY"],
        base_url=os.environ.get("NULLGATE_BASE_URL", "https://akamai.nullgate.club"),
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
check the result. A new document needs a new session; reuse the identity and jar.

## Discovery

`Page(url=..., html=...)` contains the document you fetched. Both client methods
and `nullgate.html.find_protections` are synchronous and local: they do not fetch
scripts or execute JavaScript. Sensor detection is a same-origin extensionless
classic-script heuristic; the service validates the source you supply.

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

## Errors and reports

`NullgateAPIError` retains `status_code`, `detail`, `request_id`, and the original
HTTPX request/response. Transport and malformed-response errors remain distinct.

After an actual target failure, call `await solution.report()` or
`await client.report(request_id)`; omit `await` in sync code. Reports send only
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
