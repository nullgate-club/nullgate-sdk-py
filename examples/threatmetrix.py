import asyncio
import os

import httpx

from nullgate import TargetRequest, TargetResponse
from nullgate.aio import Nullgate

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)


async def main() -> None:
    async with (
        Nullgate() as ng,
        httpx.AsyncClient(headers={"User-Agent": UA}, follow_redirects=False) as http,
    ):

        async def my_send(request: TargetRequest) -> TargetResponse:
            if request.credentials == "omit":
                async with httpx.AsyncClient(headers={"User-Agent": UA}) as isolated:
                    response = await isolated.request(
                        request.method,
                        request.url,
                        headers=request.headers,
                        content=request.body,
                    )
            else:
                response = await http.request(
                    request.method,
                    request.url,
                    headers=request.headers,
                    content=request.body,
                )
            return TargetResponse(
                response.status_code, dict(response.headers), response.content
            )

        url = os.environ["TARGET_URL"]
        page = ng.session(user_agent=UA).page(url, (await http.get(url)).text)
        async with page.threatmetrix(send=my_send) as tmx:
            await tmx.pagehide()


if __name__ == "__main__":
    asyncio.run(main())
