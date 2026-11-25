"""PingOne Signals generation through the caller's target transport."""

import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from ..aio import Session
from ..html import _Scripts
from . import document
from .models import SolveError, http_url
from .transport import Transport


async def solve(
    session: Session,
    transport: Transport,
    url: str,
    *,
    html: str | None = None,
    script_url: str | None = None,
    pingone: dict[str, Any] | None = None,
) -> dict[str, object]:
    options = pingone if pingone is not None else {}
    allowed = {
        "sdk_config",
        "jwt_device_attributes",
        "jwt_agent_payload",
        "client_token",
        "token_host",
        "behavioral",
    }
    if not isinstance(options, dict) or options.keys() - allowed:
        raise SolveError("invalid_request", "Invalid pingone options", stage="validate")
    page, page_url = await document.load(session, transport, url, html=html)
    if script_url is None:
        parser = _Scripts(html if html is not None else page._document.html)
        parser.feed(html if html is not None else page._document.html)
        base = urljoin(page_url, parser.base or "")
        candidates = []
        for reference, _ in parser.sources:
            candidate = urljoin(base, reference.raw_source)
            path = urlsplit(candidate).path.rsplit("/", 1)[-1]
            if re.fullmatch(r"signals-sdk(?:-[\w.]+)?\.js", path, re.IGNORECASE):
                candidates.append(candidate)
        candidates = list(dict.fromkeys(candidates))
        if len(candidates) != 1:
            raise SolveError(
                "protection_not_found",
                "PingOne SDK not uniquely identified in HTML; provide script_url",
                stage="page",
            )
        script_url = candidates[0]
    source = await document.script(transport, http_url(urljoin(page_url, script_url)))
    result = await page.protect(script=source, send=transport.send, **options)
    return {
        "data": result.data,
        "sdk_version": result.sdk_version,
        "device_id": result.device_id,
        "request_id": result.request_id,
    }
