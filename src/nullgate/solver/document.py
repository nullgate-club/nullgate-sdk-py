"""Fetch the target document and its script sources."""

from ..aio import Page, Session
from .models import SolveError
from .transport import Transport


async def load(session: Session, transport: Transport, url: str) -> tuple[Page, str]:
    response = await transport.request("GET", url, navigation=True)
    if not (200 <= response.status_code < 300 or response.status_code == 403):
        raise SolveError("target_error", "Target page request failed", stage="page")
    return session.page(str(response.url), response.text), str(response.url)


async def script(transport: Transport, url: str) -> str:
    response = await transport.request("GET", url)
    if not 200 <= response.status_code < 300:
        raise SolveError("target_error", "Target script request failed", stage="script")
    return response.text
