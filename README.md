# Nullgate Python SDK 2

Prepare protection requests. Your HTTP client sends them. Python 3.11+.

```sh
pip install git+https://github.com/nullgate-club/nullgate-sdk-py
export NULLGATE_API_KEY=ng_your_key
export TARGET_URL=https://your-target.example/login
```

```python
import os
import httpx
from nullgate import Nullgate

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
url = os.environ["TARGET_URL"]
with Nullgate() as ng, httpx.Client(headers={"User-Agent": UA}) as http:
    session = ng.session(user_agent=UA)
    html = http.get(url).text
    page = session.page(url, html)
    assert page.sensor_url is not None
    sensor = page.sensor(script=http.get(page.sensor_url).text, cookies=http.cookies)
    sensor.wait()
    http.post(sensor.url, content=sensor.body, headers=sensor.headers)
```

Amazon: `page.fwcim(form="#signin", timing=performance_timing, inputs={"ap_email": email})` returns `metadata1`.
ThreatMetrix: `async with page.threatmetrix(send=my_send) as tmx:` then `await tmx.pagehide()`.
For wrapper scripts, pass `collector={"url": url, "org_id": org, "session_id": visit}` instead of `script_url`; see `examples/kleinanzeigen.py`.
Images: `ng.classify(images, labels=[...])` takes raw JPEG/PNG/WebP bytes, one image or up to 32, and returns one result per image.

```python
from pathlib import Path

with Nullgate() as ng:
    classified = ng.classify(Path("photo.jpg").read_bytes(), labels=["cat", "dog"], model="fast")
    print(classified.results[0].label, classified.results[0].scores)
```

`scores` follow the order of `labels`; `model` is `fast`, `balanced` (default) or `precise`.

```python
with Nullgate() as ng:
    matched = ng.match(Path("photo.jpg").read_bytes(), queries=["a cat", "a dog"])
    print(matched.results[0].scores)
```

Match scores are independent probabilities in query order, not a distribution that sums to one.
Errors: catch `NullgateError` and inspect `code`, `message`, `request_id`, and `status`; maintenance retries are automatic.
Action `value` fields cannot contain strings, regardless of event type; sensor calls reject them with `invalid_actions`.
Pass `transport=` to inject an HTTPX API transport (sync or async); it never handles target requests or ThreatMetrix sockets.
Use `from nullgate import prepare_inputs, PreparedInput`; pass prepared `inputs` to sensor or FWCIM, including password summaries without raw values.
Use `from nullgate.akamai import is_enough, abck_counters` to stop ordinary sensor sends; this does not prove target acceptance.
Omitted `inputs`/`actions` preserve collection defaults; `[]` sends an explicitly empty collection. Call `result.report()` after a target failure; `True` means HTTP delivery only.
Keep passing `script` to `page.sensor`; the SDK uploads it only until the server retains it, and retries once if needed.
The SDK uses gzip for bodies of at least 1024 bytes from the first request; transports see compressed bytes, and HTTP 415 disables compression.
`classify` and `match` send images as raw `multipart/form-data` parts and never use gzip.

Use `from nullgate.aio import Nullgate` for async network methods and `await result.wait()`.
Runnable scripts: `examples/akamai.py`, `examples/amazon.py`, `examples/threatmetrix.py`, `examples/kleinanzeigen.py`.
Run development checks with `make check`.

[Documentation and callback recipes](https://docs.nullgate.club)
