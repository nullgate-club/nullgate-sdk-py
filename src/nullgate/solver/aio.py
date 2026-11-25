"""Asynchronous client for the local HTTP API."""

from typing import Unpack

import httpx

from .client import _MAX_RESPONSE, decode, payload, settings, transport_error
from .models import Request, Result, SolveError


class Solver:
    """Call the local server with an async context manager."""

    def __init__(
        self, base_url: str = "http://127.0.0.1:8191", *, timeout: float = 190
    ) -> None:
        self._url, timeout = settings(base_url, timeout)
        self._http = httpx.AsyncClient(timeout=timeout, trust_env=False)

    async def solve(self, **options: Unpack[Request]) -> Result:
        if self._http.is_closed:
            raise SolveError("closed", "Solver is closed", stage="validate")
        body = payload(options)
        try:
            async with self._http.stream("POST", self._url, json=body) as response:
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(content) + len(chunk) > _MAX_RESPONSE:
                        raise SolveError(
                            "invalid_response",
                            "Local HTTP API response exceeds 4 MiB",
                            stage="response",
                        )
                    content.extend(chunk)
                return decode(response, content, options["type"], options["url"])
        except httpx.HTTPError as error:
            raise transport_error(error) from None
        except (TypeError, ValueError):
            raise SolveError(
                "invalid_request",
                "Solve options must contain JSON values",
                stage="validate",
            ) from None

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "Solver":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()
