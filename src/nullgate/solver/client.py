"""Synchronous client for the local HTTP API, without native dependencies."""

import json
import math
from typing import Any, Unpack, cast

import httpx

from .models import Options, Product, Request, Result, SolveError, http_url

_MAX_RESPONSE = 4 * 1024 * 1024


def settings(base_url: str, timeout: float) -> tuple[str, float]:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise SolveError(
            "invalid_request", "timeout must be positive", stage="validate"
        )
    base_url = http_url(base_url)
    parsed = httpx.URL(base_url)
    if parsed.query or parsed.fragment:
        raise SolveError(
            "invalid_request",
            "base_url cannot contain query or fragment",
            stage="validate",
        )
    return base_url.rstrip("/") + "/solve", timeout


def payload(options: Request) -> dict[str, Any]:
    try:
        value = Options(**cast(dict[str, Any], options))
    except TypeError:
        raise SolveError(
            "invalid_request",
            "Provide type and url; reject unknown fields",
            stage="validate",
        ) from None
    return {key: item for key, item in vars(value).items() if item is not None}


def decode(
    response: httpx.Response, content: bytearray, product: Product, url: str
) -> Result:
    def invalid() -> SolveError:
        return SolveError(
            "invalid_response",
            "Local HTTP API returned an invalid response",
            stage="response",
            status=response.status_code,
        )

    try:
        value = json.loads(content)
    except (ValueError, UnicodeError):
        raise invalid() from None
    if not isinstance(value, dict):
        raise invalid()
    if not response.is_success:
        if not all(
            isinstance(value.get(key), str) and value[key]
            for key in ("code", "message", "stage")
        ):
            raise invalid()
        raise SolveError(
            value["code"],
            value["message"],
            stage=value["stage"],
            request_id=value.get("request_id")
            if isinstance(value.get("request_id"), str)
            else None,
            cause=value.get("cause") if isinstance(value.get("cause"), str) else None,
            status=response.status_code,
        )
    result = value.get("result")
    if not isinstance(value.get("cookies"), list) or not isinstance(result, dict):
        raise invalid()
    try:
        Options(type=product, url=url, cookies=value["cookies"])
    except SolveError:
        raise invalid() from None
    if (
        product == "akamai"
        and result.get("accepted") is not True
        or product == "threatmetrix"
        and result.get("collected") is not True
        or product == "pingone"
        and not all(
            isinstance(result.get(key), str) and result[key]
            for key in ("data", "device_id", "sdk_version", "request_id")
        )
        or product == "amazon_acic"
        and (
            result.get("status") != "PASS"
            or not isinstance(result.get("url"), str)
            or type(result.get("status_code")) is not int
            or not 200 <= result["status_code"] < 300
        )
    ):
        raise invalid()
    return cast(Result, value)


def transport_error(error: httpx.HTTPError) -> SolveError:
    if isinstance(error, httpx.TimeoutException):
        return SolveError(
            "timeout",
            "Local HTTP API request exceeded its deadline",
            stage="transport",
            cause=type(error).__name__,
        )
    return SolveError(
        "transport_error",
        "Cannot reach the local HTTP API; start nullgate-http-api first",
        stage="transport",
        cause=type(error).__name__,
    )


class Solver:
    """Call the local server. The server, not this client, owns the API key."""

    def __init__(
        self, base_url: str = "http://127.0.0.1:8191", *, timeout: float = 190
    ) -> None:
        self._url, timeout = settings(base_url, timeout)
        self._http = httpx.Client(timeout=timeout, trust_env=False)

    def solve(self, **options: Unpack[Request]) -> Result:
        if self._http.is_closed:
            raise SolveError("closed", "Solver is closed", stage="validate")
        body = payload(options)
        try:
            with self._http.stream("POST", self._url, json=body) as response:
                content = bytearray()
                for chunk in response.iter_bytes():
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

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "Solver":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
