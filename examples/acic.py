"""Complete ACIC PoW/WAF through caller-owned Amazon and AWS HTTP clients."""

import argparse
import json
import os
import time

import httpx

from nullgate import Nullgate, TargetRequest, acic

POW_TYPES = {
    "PROOF_OF_WORK_LEVEL_3",
    "PROOF_OF_WORK_LEVEL_3_CHAIN_WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_2",
}
WAF_TYPES = {
    "WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_2",
    "WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_3",
}


def solve_acic(
    ng: Nullgate,
    amazon: httpx.Client,
    aws: httpx.Client,
    entry: httpx.Response,
) -> httpx.Response:
    """Handle an ACIC page, or return a page without ACIC unchanged."""
    setup = acic.discover(str(entry.url), entry.text)
    if setup is None:
        return entry

    def send(request: TargetRequest) -> httpx.Response:
        response = amazon.request(
            request.method,
            request.url,
            headers=request.headers,
            content=request.body,
            follow_redirects=False,
        )
        if response.status_code != 200:
            raise RuntimeError(f"ACIC returned HTTP {response.status_code}")
        return response

    response = send(setup.start())
    seen = set()
    while True:
        state = acic.parse_result(response.headers)
        if state is None:
            raise RuntimeError("Amazon returned no ACIC result header")
        if state.action_type == "PASS":
            request = setup.continuation(state)
            return amazon.request(
                request.method,
                request.url,
                headers=request.headers,
                content=request.body,
                follow_redirects=True,
            )
        if state.action_type in seen:
            raise RuntimeError("ACIC repeated a stage; stop instead of paying again")
        seen.add(state.action_type)
        if state.action_type in POW_TYPES:
            proof = ng.acic_pow(state.action_type, response.text)
            proof.wait()
            answer = proof.response
        elif state.action_type in WAF_TYPES:
            waf = acic.discover_waf(str(response.url), response.text)
            if waf is None or waf.rounds_required not in (2, 3):
                raise RuntimeError("Unsupported WAF view or round policy")
            problem_response = aws.get(waf.problem_url, headers=waf.headers)
            problem_response.raise_for_status()
            problem = problem_response.json()
            presented_at = time.monotonic()
            for _ in range(waf.rounds_required):
                selection = ng.acic_waf(problem)
                body = selection.verification_body(
                    problem,
                    elapsed_seconds=time.monotonic() - presented_at,
                    locale=waf.locale,
                )
                verified = aws.post(
                    waf.verification_url(problem),
                    headers=waf.headers,
                    content=json.dumps(body),
                )
                verified.raise_for_status()
                result = verified.json()
                voucher = result.get("captcha_voucher")
                if isinstance(voucher, str) and voucher:
                    answer = state.voucher_response(voucher)
                    break
                if result.get("success") is not True or not isinstance(
                    result.get("problem"), dict
                ):
                    raise RuntimeError("AWS rejected the WAF answer")
                problem = result["problem"]
                presented_at = time.monotonic()
            else:
                raise RuntimeError("AWS returned no voucher within its round policy")
        else:
            raise RuntimeError("Unsupported ACIC stage")
        response = send(setup.answer(state, answer))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Fresh Amazon ACIC entry-page URL")
    args = parser.parse_args()
    headers = {"User-Agent": os.environ.get("USER_AGENT", "Mozilla/5.0")}
    with (
        Nullgate() as ng,
        httpx.Client(headers=headers, timeout=30, follow_redirects=True) as amazon,
        httpx.Client(headers=headers, timeout=30) as aws,
    ):
        response = solve_acic(ng, amazon, aws, amazon.get(args.url))
        print(f"Final HTTP {response.status_code}")


if __name__ == "__main__":
    main()
