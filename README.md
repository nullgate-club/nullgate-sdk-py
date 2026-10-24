<img src="https://raw.githubusercontent.com/nullgate-club/nullgate-sdk-py/main/assets/logo.svg" alt="Nullgate" width="280">

# Python SDK

![Python 3.11–3.15](https://img.shields.io/badge/Python-3.11%E2%80%933.15-3776AB)
![Typed](https://img.shields.io/badge/Types-Typed-28A36A)

Generate Akamai sensor and pixel payloads, with sync and async clients.

[Documentation](https://docs.nullgate.club) · [Python guide](https://docs.nullgate.club/examples/python) · [Repository](https://github.com/nullgate-club/nullgate-sdk-py) · [Issues](https://github.com/nullgate-club/nullgate-sdk-py/issues)

## Install

```sh
python -m pip install nullgate-sdk-py
```

Import as `nullgate`. Your `api_key` is the secret account UUID; the separate,
required `uuid` selects a browser profile.

## Generate sensor data

Fetch the page, discover its sensor script, then fetch that script with your
target client.

```python
import json
import os
import time
from uuid import uuid4

import httpx
from nullgate import get_sensor_script_url, open_session

user_agent = os.environ["USER_AGENT"]
page_url = "https://shop.example/login"

with (
    httpx.Client(headers={"User-Agent": user_agent}, follow_redirects=True) as target,
    open_session(uuid=uuid4(), api_key=os.environ["NULLGATE_API_KEY"]) as api,
):
    page = target.get(page_url)
    page.raise_for_status()
    script_url = get_sensor_script_url(page.text, str(page.url))
    if script_url is None:
        raise ValueError("The page has no sensor script")
    source = target.get(script_url)
    source.raise_for_status()
    website = {"url": str(page.url), "html": page.text}
    script = {"source": str(source.url), "text": source.text}

    result = api.sensor_data(
        website=website,
        script=script,
        user_agent=user_agent,
        cookies=dict(target.cookies),
    )
    time.sleep(max(0, result["send_at"] - time.time()))
    response = target.post(
        script["source"],
        content=json.dumps({"sensor_data": result["sensor_data"]}),
        headers={
            **result["headers"],
            "Content-Type": "text/plain;charset=UTF-8",
            "Referer": website["url"],
        },
    )
    response.raise_for_status()
```

`sensor_data()` returns a `SensorDataResponse` typed dictionary containing
`sensor_data`, `headers`, and `send_at`. The latter is the earliest target POST
time, in Unix seconds. Wait until then before sending the payload. Generation
alone does not establish that the target accepted it.

The default API URL is `https://akamai.nullgate.club`. To use another endpoint,
pass it as the first argument to `open_session()` or `async_open_session()`.
Both factories accept HTTPX options such as `timeout`, `headers`, and `proxy`.

### Async

Use `async_open_session()` in an async function. With the same fetched `website`,
`script`, and User-Agent, the call is:

```python
import asyncio

from nullgate import async_open_session

async with async_open_session(
    uuid=uuid4(), api_key=os.environ["NULLGATE_API_KEY"]
) as api:
    result = await api.sensor_data(
        website=website, script=script, user_agent=user_agent
    )
    await asyncio.sleep(max(0, result["send_at"] - time.time()))
```

### Pixel

`pixel()` requires a page-specific `challenge` and the matching pixel script:

```python
from nullgate import get_pixel_challenge, get_pixel_script_url

pixel_url = get_pixel_script_url(website["html"], website["url"])
challenge = get_pixel_challenge(website["html"])
if pixel_url is not None and challenge is not None:
    source = target.get(pixel_url)
    source.raise_for_status()
    pixel_script = {"source": str(source.url), "text": source.text}
    pixel = api.pixel(
        website=website,
        script=pixel_script,
        user_agent=user_agent,
        challenge=challenge,
    )
    time.sleep(max(0, pixel["send_at"] - time.time()))
    response = target.post(
        pixel["url"], content=pixel["body"], headers=pixel["headers"]
    )
    response.raise_for_status()
```

Skip pixel generation when no challenge is present. Its `PixelResponse` typed
dictionary contains `url`, `body`, `headers`, and `send_at`. Async clients expose
both methods with the same arguments; await the result.

### Script discovery

`get_sensor_script_url(html, page_url)` and `get_pixel_script_url(html, page_url)`
return absolute URLs or `None`. They resolve relative paths and `<base href>`,
preserve query strings, and ignore modules, inactive markup and other origins.

Pixel URLs match `/akam/13/<hex>`. Sensor discovery selects the unique remaining
classic script. Multiple candidates raise `ValueError`; select the URL explicitly
in that case. These helpers do not fetch or execute JavaScript.

## State and inputs

Reuse one `open_session()` client for sequential generation calls. It carries
`X-State-ID` forward automatically; a new client starts fresh state. Idle state
expires after five minutes. Keep the profile UUID, User-Agent, and timezone
consistent within a session. The optional `timezone` is an IANA name such as
`Europe/Berlin`; new state defaults to UTC.

`sensor_data()` accepts only the inputs your application fills, for example:

```python
inputs = [{"name": "email", "type": "email", "value": "hello@example.com"}]
```

Pass this as `inputs=inputs`. Values are hashed locally into summaries before
sending. `inputs=None` keeps previous declarations; `inputs=[]` clears them.
Page HTML is sent as supplied, including any values already embedded in it.

Explicit `actions` replace automatic interactions; `actions=[]` disables them.
Event times are elapsed milliseconds from the document start.
`is_enough(abck, response_count=...)` checks the target cookie's sensor stop
signal, not whether a login or other target action succeeded.

## Errors

Generation methods raise `httpx.HTTPStatusError` for unsuccessful API responses.
Inspect `error.response` for the status and response body. Network failures and
timeouts propagate as HTTPX exceptions, including `httpx.RequestError` and
`httpx.TimeoutException`.

| Status | Meaning |
| --- | --- |
| 400 / 422 | Invalid request or unsupported source |
| 401 | Missing, invalid, or disabled account key |
| 402 | Insufficient balance |
| 503 | Service temporarily unavailable |

## Development

With [uv](https://docs.astral.sh/uv/) installed, run from the repository root:

```sh
make setup
make format
make check
make build
```

`check` runs Ruff, mypy, and pytest. `build` writes a wheel and source distribution
to `dist/`. Use `make PYTHON=3.15 setup check build` to select another supported
Python version.
