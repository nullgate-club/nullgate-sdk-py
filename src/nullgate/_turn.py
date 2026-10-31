"""A single aioice TURN/TCP allocation, with optional python-socks dialing."""

import asyncio
from contextlib import suppress
from dataclasses import dataclass, field

from aioice.candidate import Candidate, candidate_foundation, candidate_priority
from aioice.turn import (
    DEFAULT_ALLOCATION_LIFETIME,
    DEFAULT_CHANNEL_REFRESH_TIME,
    TurnClientTcpProtocol,
)
from python_socks.async_.asyncio import Proxy


@dataclass(frozen=True, slots=True)
class _TurnServer:
    host: str
    port: int
    username: str = field(repr=False)
    credential: str = field(repr=False)


class _TurnProtocol(TurnClientTcpProtocol):
    def __init__(self, server: _TurnServer) -> None:
        super().__init__(
            (server.host, server.port),
            server.username,
            server.credential,
            DEFAULT_ALLOCATION_LIFETIME,
            DEFAULT_CHANNEL_REFRESH_TIME,
        )
        self.closed: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.closed.done():
            self.closed.set_result(None)


class _TurnAllocation:
    def __init__(self, server: _TurnServer, proxy: str | None) -> None:
        self._server = server
        self._proxy = proxy
        self._protocol: _TurnProtocol | None = None
        self._transport: asyncio.Transport | None = None

    async def open(self) -> dict[str, object]:
        loop = asyncio.get_running_loop()
        started = loop.time()
        server = self._server
        async with asyncio.timeout(4):
            if self._proxy is None:
                transport, protocol = await loop.create_connection(
                    lambda: _TurnProtocol(server), host=server.host, port=server.port
                )
            else:
                sock = await Proxy.from_url(self._proxy).connect(
                    dest_host=server.host, dest_port=server.port, timeout=4
                )
                try:
                    transport, protocol = await loop.create_connection(
                        lambda: _TurnProtocol(server), sock=sock
                    )
                except BaseException:
                    sock.close()
                    raise
            self._transport = transport
            self._protocol = protocol
            host, port = await protocol.connect()
        elapsed_ms = (loop.time() - started) * 1000
        # TURN/TCP describes the control stream; Allocate requests a UDP relay.
        candidate = Candidate(
            foundation=candidate_foundation("relay", "udp", host),
            component=1,
            transport="udp",
            priority=candidate_priority(1, "relay"),
            host=host,
            port=port,
            type="relay",
        )
        return {
            "candidates": [
                {"value": "candidate:" + candidate.to_sdp(), "elapsed_ms": elapsed_ms}
            ],
            "complete_at_ms": elapsed_ms,
        }

    async def wait_for_release(self, release: asyncio.Event) -> None:
        protocol = self._protocol
        if protocol is None:
            raise RuntimeError("TURN allocation is not open")
        released = asyncio.create_task(release.wait())
        waiters: list[asyncio.Future[None] | asyncio.Task[bool]] = [
            released,
            protocol.closed,
        ]
        if protocol.refresh_task is not None:
            waiters.append(protocol.refresh_task)
        try:
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
            if not release.is_set():
                raise OSError("TURN allocation ended before release")
        finally:
            released.cancel()
            await asyncio.gather(released, return_exceptions=True)

    async def aclose(self) -> None:
        protocol, transport = self._protocol, self._transport
        self._protocol = None
        self._transport = None
        if protocol is None or transport is None:
            return
        refresh = protocol.refresh_task
        try:
            with suppress(Exception):
                async with asyncio.timeout(4):
                    if (
                        not transport.is_closing()
                        and protocol.relayed_address is not None
                    ):
                        await protocol.delete()
        finally:
            transport.close()
            if refresh is not None:
                refresh.cancel()
                await asyncio.gather(refresh, return_exceptions=True)
            with suppress(TimeoutError):
                async with asyncio.timeout(4):
                    await protocol.closed
