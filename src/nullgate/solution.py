"""Ready target POSTs; target transport and cookies remain caller-owned."""

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True, slots=True)
class Solution:
    url: str
    headers: dict[str, str]
    body: str = field(repr=False)
    send_at: float
    request_id: str
    _reporter: Callable[[str], bool] = field(repr=False, kw_only=True)
    method: Literal["POST"] = field(default="POST", init=False)

    def wait(self) -> None:
        """Wait until the absolute earliest target submission time."""
        delay = self.send_at - time.time()
        if delay > 0:
            time.sleep(delay)

    def report(self) -> bool:
        """Report delivery only, not target failure attribution or archive status."""
        return self._reporter(self.request_id)


@dataclass(frozen=True, slots=True)
class SolutionAsync:
    url: str
    headers: dict[str, str]
    body: str = field(repr=False)
    send_at: float
    request_id: str
    _reporter: Callable[[str], Awaitable[bool]] = field(repr=False, kw_only=True)
    method: Literal["POST"] = field(default="POST", init=False)

    async def wait(self) -> None:
        """Wait until the absolute earliest target submission time."""
        delay = self.send_at - time.time()
        if delay > 0:
            await asyncio.sleep(delay)

    async def report(self) -> bool:
        """Report delivery only, without refunding or retrying generation."""
        return await self._reporter(self.request_id)
