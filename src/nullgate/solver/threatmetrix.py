"""Complete target-side ThreatMetrix profiling."""

from collections.abc import Mapping

from ..aio import Session
from ..errors import NullgateError
from . import document
from .models import SolveError
from .transport import Transport


async def solve(
    session: Session,
    transport: Transport,
    url: str,
    *,
    script_url: str | None = None,
    collector: Mapping[str, str] | None = None,
) -> None:
    stage = "page"
    try:
        page, _ = await document.load(session, transport, url)
        stage = "profile"
        async with page.threatmetrix(
            send=transport.send,
            proxy=transport.proxy,
            script_url=script_url,
            collector=collector,
        ) as profile:
            await profile.pagehide()
    except NullgateError as exc:
        raise SolveError(
            exc.code,
            "ThreatMetrix profile failed",
            stage=stage,
            cause=type(exc.__cause__).__name__ if exc.__cause__ else None,
            request_id=exc.request_id,
            status=exc.status,
        ) from None
