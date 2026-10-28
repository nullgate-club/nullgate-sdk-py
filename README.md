<img src="https://raw.githubusercontent.com/nullgate-club/nullgate-sdk-py/main/assets/logo.svg" alt="Nullgate" width="280">

# Nullgate Python SDK

Typed synchronous and asynchronous clients, local protection discovery, isolated
sessions, ready-to-send solutions, and optional failure reports.

The `next` branch requires the updated Nullgate backend, including `X-Request-ID`
and analytics reporting. Until the backend cutover, use an updated preview
deployment via `base_url` and `analytics_url` (the target example reads
`NULLGATE_BASE_URL` and `ANALYTICS_URL`). Do not use this branch against the old
production API. The existing `main` branch remains compatible with that API until
the coordinated server upgrade.

## Install from GitHub

Python 3.11–3.15:

```sh
python -m pip install "git+https://github.com/nullgate-club/nullgate-sdk-py.git@next"
```

Import the package as `nullgate`. This SDK is source-installed from public GitHub;
it is not released to PyPI. Git must be available when pip installs it.

## Open a session

Create the client once. Open an independent session for each document while
reusing your identity and target cookie jar across navigation.

```python
import os
from uuid import UUID

from nullgate import NullgateClientAsync, Page
from nullgate.akamai import Pixel, PixelParams, Sbsd, SbsdParams, Sensor, SensorParams

async def generate(page: Page, scripts: dict[str, str], cookies: dict[str, str]):
    async with NullgateClientAsync(
        os.environ["NULLGATE_API_KEY"],
        base_url=os.environ["NULLGATE_BASE_URL"],
        analytics_url=os.environ["ANALYTICS_URL"],
    ) as client:
        async with client.open(
            identity=UUID(os.environ["NULLGATE_IDENTITY"]),
            user_agent=os.environ["USER_AGENT"],
        ) as session:
            for protection in client.find_protections(page):
                script = scripts[protection.script_url]
                match protection:
                    case Sensor():
                        params = SensorParams(protection, script, cookies=cookies)
                    case Pixel():
                        params = PixelParams(protection, script)
                    case Sbsd():
                        params = SbsdParams(protection, script, cookies=cookies)
                    case _:
                        continue
                yield await session.solve(params)
```

`Page(url=..., html=...)` contains the page you fetched. Discovery is local: it
does not download scripts or run the producer. Results preserve ambiguous
candidates; select the matching protection rather than assuming the first script
is genuine. Use `F` filters when useful, and `match` to narrow concrete types.

`NullgateClient` provides the same flow synchronously with `with`; its methods,
solutions and sessions do not require `await`.

## Send a solution

A solution contains `method`, `url`, `headers`, exact string `body`, absolute Unix
`send_at`, and the server's `request_id`. Await `solution.wait()`, then send the
body unchanged with your target HTTP client. Do not JSON-encode it again.

Your target client owns transport settings, redirects and cookies. Never send
your Nullgate API key to the target site. The SDK's HTTPX connection is for the
Nullgate API, not a browser impersonation transport.

[The complete example](examples/target.py) uses Python `wreq==0.13.0` with Chrome
146/Windows, scoped script-visible cookie observations and a persistent target
cookie jar:

```sh
python -m pip install wreq==0.13.0
export NULLGATE_API_KEY='your-account-key'
export NULLGATE_IDENTITY='your-persistent-profile-uuid'
export TARGET_URL='https://your-target.example/page'
python examples/target.py
```

Optional environment variables are `TARGET_PROXY`, `NULLGATE_BASE_URL` and
`ANALYTICS_URL`. `REPORT_FAILURES=1` enables best-effort reports for observed
failures in the example. No credentials or target captures are bundled.

Keep the transport preset, User-Agent and generated identity coherent. A client
preset does not change the network stack of your proxy exit or guarantee target
access. A sensor submission ceiling is not clearance. A successful SBSD POST is
not blocking clearance: re-fetch the original page and check its actual result.

## Errors and reports

`NullgateAPIError` retains `status_code`, `detail`, `request_id`, and the original
HTTPX request/response. Transport and malformed-response errors remain distinct.

After an actual target failure, call `await solution.report()` or
`await client.report(request_id)`. In sync code omit `await`. Reporting sends only
the request ID to analytics, without account authorization or target cookies.
It does not retry or refund the operation. `True` means HTTP delivery succeeded,
not that a report was accepted: repeated, unknown, expired and rate-limited IDs
receive the same quiet acknowledgement. Network failures return `False`;
cancellation and local programming errors are not swallowed.

## Develop

```sh
make setup
make format
make check
make build
```

The gate checks formatting, typing and behavioral tests, including type-checking
the target example; `make build` produces local distribution archives without
publishing. CI runs `make setup`, `make check` and `make build` on Python 3.11 and
3.15. Canonical SDK-first documentation is at
[docs.nullgate.club](https://docs.nullgate.club).
