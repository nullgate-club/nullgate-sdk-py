import os

import httpx

from nullgate import Nullgate

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)
url = os.environ["TARGET_URL"]
with Nullgate() as ng, httpx.Client(headers={"User-Agent": UA}) as http:
    session = ng.session(user_agent=UA)
    html = http.get(url).text
    page = session.page(url, html)
    assert page.sensor_url is not None
    sensor = page.sensor(script=http.get(page.sensor_url).text, cookies=http.cookies)
    sensor.wait()
    http.post(sensor.url, content=sensor.body, headers=sensor.headers)
