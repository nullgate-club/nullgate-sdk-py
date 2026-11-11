"""One error type for API, transport, and local failures."""

import math
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime


def _retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            seconds = max(
                0.0, (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
            )
        except (ValueError, TypeError, OverflowError):
            return None
    return seconds if math.isfinite(seconds) and seconds >= 0 else None


class NullgateError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: str = "invalid_request",
        request_id: str | None = None,
        status: int | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.request_id = request_id
        self.status = status
        super().__init__(message)
