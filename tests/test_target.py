import asyncio
from typing import Literal

import pytest

from nullgate import Target, TargetRequest, TargetResponse, WreqTarget


@pytest.mark.parametrize("asynchronous", [False, True], ids=["blocking", "async"])
def test_wreq_omit_neither_sends_nor_persists_cookies_in_the_callers_jar(
    asynchronous: bool,
) -> None:
    from wreq import Client, Jar
    from wreq.blocking import Client as BlockingClient

    async def scenario() -> None:
        received: dict[str, bytes | None] = {}
        binary = b"\xff\x00\xfe"

        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            request = await reader.readuntil(b"\r\n\r\n")
            first, *headers = request.split(b"\r\n")
            path = first.split(b" ")[1].decode("ascii")
            cookies = next(
                (
                    line.partition(b":")[2].strip()
                    for line in headers
                    if line.lower().startswith(b"cookie:")
                ),
                None,
            )
            received[path] = cookies
            writer.write(
                b"HTTP/1.1 418 Teapot\r\nContent-Length: 3\r\n"
                b"Set-Cookie: omitted=value; Path=/\r\nConnection: close\r\n\r\n"
                + binary
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async with await asyncio.start_server(handler, "127.0.0.1", 0) as server:
            base = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
            jar = Jar()
            jar.add("existing=caller; Path=/", base)
            client = (
                Client(
                    cookie_provider=jar,
                    headers={"Cookie": "default-header=private"},
                    no_proxy=True,
                )
                if asynchronous
                else BlockingClient(
                    cookie_provider=jar,
                    headers={"Cookie": "default-header=private"},
                    no_proxy=True,
                )
            )
            try:
                target = WreqTarget(client, proxy=None)
                for credentials in ("omit", "include"):
                    mode: Literal["include", "omit"] = credentials
                    result = await target._fetch(
                        TargetRequest(
                            "resource", f"{base}/{mode}", "GET", {}, None, mode
                        )
                    )
                    assert result.status == 418
                    assert result.body == binary
                    if mode == "omit":
                        assert jar.get("omitted", base) is None
                        assert jar.get("existing", base) is not None
                assert received["/omit"] is None
                assert received["/include"] == b"existing=caller"
            finally:
                client.close()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "proxy",
    [
        "http://user:private-password@proxy.example",
        "socks5://proxy.example:0",
        "https://user:private-password@proxy.example:443",
        "socks5://user:private-password@proxy.example:1080/path",
    ],
)
def test_invalid_turn_proxy_is_rejected_locally_without_echoing_secrets(
    proxy: str,
) -> None:
    with pytest.raises(ValueError) as failure:
        Target(lambda request: TargetResponse(200, {}, b""), proxy=proxy)
    assert "private-password" not in str(failure.value)


def test_target_repr_omits_callback_and_proxy_credentials() -> None:
    target = Target(
        lambda request: TargetResponse(200, {}, b""),
        proxy="socks5://user:private-password@proxy.example:1080",
    )
    assert "private-password" not in repr(target)
