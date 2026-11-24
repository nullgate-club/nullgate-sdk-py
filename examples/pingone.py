"""Set TARGET_URL and PINGONE_SCRIPT_URL to the page and its PingOne SDK script."""

import os

import httpx

from nullgate import Nullgate, TargetRequest, TargetResponse

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
)


def main() -> None:
    url = os.environ.get("TARGET_URL", "https://identity.example/login")
    script_url = os.environ["PINGONE_SCRIPT_URL"]
    with Nullgate() as ng, httpx.Client(headers={"User-Agent": UA}) as http:
        page_response = http.get(url)
        page_response.raise_for_status()
        script_response = http.get(script_url)
        script_response.raise_for_status()
        page = ng.session(user_agent=UA).page(url, page_response.text)

        def send(request: TargetRequest) -> TargetResponse:
            response = http.request(
                request.method,
                request.url,
                headers=request.headers,
                content=request.body,
            )
            return TargetResponse(
                response.status_code, dict(response.headers), response.content
            )

        result = page.protect(script=script_response.text, send=send)
        # Submit result.data with the identity provider's login request.
        print(result.sdk_version, result.device_id, result.request_id)


if __name__ == "__main__":
    main()
