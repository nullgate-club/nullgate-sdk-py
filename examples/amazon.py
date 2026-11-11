import os
import time

import httpx

from nullgate import Nullgate

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)
url, email = os.environ["TARGET_URL"], os.environ["AMAZON_EMAIL"]
with Nullgate() as ng, httpx.Client(headers={"User-Agent": UA}) as http:
    start = time.time_ns() // 1_000_000
    response = http.get(url)
    end = time.time_ns() // 1_000_000
    performance_timing = {
        "navigationStart": start,
        "fetchStart": start,
        "responseEnd": end,
    }
    page = ng.session(user_agent=UA).page(url, response.text)
    fwcim = page.fwcim(
        form="#signin",
        timing=performance_timing,
        inputs={"ap_email": email},
        cookies=http.cookies,
    )
    form = {"ap_email": email, "metadata1": fwcim.metadata1}
    fwcim.wait()
    http.post(url, data=form, headers=fwcim.headers)
