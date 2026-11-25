"""Complete the ACIC challenge using the caller's transport and cookies."""

import json
import time
from urllib.parse import urljoin, urlsplit

import httpx

from .. import acic
from ..aio import Session
from ..errors import NullgateError
from ..target import TargetRequest
from . import document
from .models import SolveError
from .transport import Transport

_POW = {
    "PROOF_OF_WORK_LEVEL_3",
    "PROOF_OF_WORK_LEVEL_3_CHAIN_WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_2",
}
_WAF = {
    "WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_2",
    "WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_3",
}


def _ok(response: httpx.Response, stage: str) -> None:
    if not response.is_success:
        raise SolveError(
            "target_error",
            "ACIC target request failed",
            stage=stage,
            status=response.status_code,
        )


async def _send(transport: Transport, request: TargetRequest) -> httpx.Response:
    response = await transport.request(
        request.method,
        request.url,
        headers=request.headers,
        body=request.body,
        credentials=request.credentials == "include",
    )
    _ok(response, "target")
    return response


async def _continue(transport: Transport, request: TargetRequest) -> httpx.Response:
    method, url, body = request.method, request.url, request.body
    headers = dict(request.headers)
    for _ in range(11):
        response = await transport.request(
            method,
            url,
            headers=headers,
            body=body,
            credentials=request.credentials == "include",
            navigation=True,
        )
        if response.status_code not in (301, 302, 303, 307, 308):
            _ok(response, "continuation")
            return response
        location = response.headers.get("location")
        if not location:
            raise SolveError(
                "solve_failed",
                "Continuation redirect has no location",
                stage="continuation",
            )
        next_url = urljoin(str(response.url), location)
        if (
            urlsplit(next_url).netloc != urlsplit(url).netloc
            or urlsplit(next_url).scheme != urlsplit(url).scheme
        ):
            headers = {
                k: v
                for k, v in headers.items()
                if k.lower()
                not in {
                    "authorization",
                    "proxy-authorization",
                    "cookie",
                    "origin",
                    "referer",
                }
            }
        if response.status_code in (301, 302, 303) and method != "GET":
            method, body = "GET", None
            headers = {
                k: v
                for k, v in headers.items()
                if k.lower() not in {"content-type", "content-length"}
            }
        url = next_url
    raise SolveError(
        "solve_failed", "Too many continuation redirects", stage="continuation"
    )


async def _waf(
    session: Session, transport: Transport, state: acic.Result, response: httpx.Response
) -> str:
    waf = acic.discover_waf(str(response.url), response.text)
    if waf is None or waf.rounds_required not in (2, 3):
        raise SolveError(
            "solve_failed", "Unsupported WAF view or round policy", stage="waf"
        )
    fetched = await transport.request(
        "GET", waf.problem_url, headers=waf.headers, credentials=False
    )
    _ok(fetched, "waf")
    problem = fetched.json()
    seen: set[str] = set()
    for _ in range(waf.rounds_required):
        if not isinstance(problem, dict) or not all(
            key in problem for key in ("state", "key", "hmac_tag")
        ):
            raise SolveError("solve_failed", "Invalid WAF problem", stage="waf")
        verification_url = waf.verification_url(problem)
        fingerprint = json.dumps(problem, sort_keys=True, separators=(",", ":"))
        if fingerprint in seen:
            raise SolveError("solve_failed", "WAF repeated a problem", stage="waf")
        seen.add(fingerprint)
        presented_at = time.monotonic()
        selection = await session._client.acic_waf(problem)
        body = selection.verification_body(
            problem, elapsed_seconds=time.monotonic() - presented_at, locale=waf.locale
        )
        verified = await transport.request(
            "POST",
            verification_url,
            headers=waf.headers,
            body=json.dumps(body),
            credentials=False,
        )
        _ok(verified, "waf")
        result = verified.json()
        if not isinstance(result, dict) or result.get("success") is False:
            raise SolveError("solve_failed", "AWS rejected the WAF answer", stage="waf")
        voucher = result.get("captcha_voucher")
        if isinstance(voucher, str) and voucher:
            return state.voucher_response(voucher)
        if result.get("success") is not True or not isinstance(
            result.get("problem"), dict
        ):
            raise SolveError("solve_failed", "AWS rejected the WAF answer", stage="waf")
        problem = result["problem"]
    raise SolveError(
        "solve_failed", "AWS returned no voucher within its round policy", stage="waf"
    )


async def solve(
    session: Session, transport: Transport, url: str, *, html: str | None = None
) -> dict[str, object]:
    stage = "page"
    try:
        page, page_url = await document.load(session, transport, url, html=html)
        setup = acic.discover(page_url, page._document.html)
        if setup is None:
            raise SolveError(
                "protection_not_found", "ACIC challenge not found", stage="page"
            )
        stage = "target"
        response = await _send(transport, setup.start())
        seen: set[str] = set()
        while True:
            state = acic.parse_result(response.headers)
            if state is None:
                raise SolveError(
                    "solve_failed", "Amazon returned no ACIC result", stage="target"
                )
            if state.action_type == "PASS":
                stage = "continuation"
                final = await _continue(transport, setup.continuation(state))
                return {
                    "status": "PASS",
                    "url": str(final.url),
                    "status_code": final.status_code,
                }
            if state.action_type in _POW:
                kind = "pow"
            elif state.action_type in _WAF:
                kind = "waf"
            else:
                raise SolveError(
                    "solve_failed", "Unsupported ACIC stage", stage="target"
                )
            if kind in seen:
                raise SolveError(
                    "solve_failed", "ACIC repeated a stage", stage="target"
                )
            seen.add(kind)
            if kind == "pow":
                stage = "generate"
                proof = await session._client.acic_pow(state.action_type, response.text)
                await proof.wait()
                answer = proof.response
            else:
                stage = "waf"
                answer = await _waf(session, transport, state, response)
            stage = "target"
            response = await _send(transport, setup.answer(state, answer))
    except NullgateError as exc:
        raise SolveError(
            exc.code,
            "ACIC generation failed",
            stage=stage,
            request_id=exc.request_id,
            status=exc.status,
        ) from None
    except (ValueError, TypeError, KeyError):
        raise SolveError(
            "solve_failed", "Invalid ACIC challenge or response", stage=stage
        ) from None
