"""Generate an ACIC proof or WAF selection from files supplied by the caller."""

import argparse
import json
import time
from pathlib import Path

from nullgate import Nullgate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("pow", "waf"))
    parser.add_argument(
        "file", type=Path, help="Challenge HTML or original AWS problem JSON"
    )
    parser.add_argument("--challenge-type", help="ACIC actionType, required for PoW")
    parser.add_argument("--locale", default="en-US")
    args = parser.parse_args()
    if args.kind == "pow" and not args.challenge_type:
        parser.error("--challenge-type is required for PoW")
    with Nullgate() as ng:
        if args.kind == "pow":
            proof = ng.acic_pow(args.challenge_type, args.file.read_text())
            print(proof.response)
        else:
            problem = json.loads(args.file.read_text())
            presented_at = time.monotonic()
            selection = ng.acic_waf(problem)
            body = selection.verification_body(
                problem,
                elapsed_seconds=time.monotonic() - presented_at,
                locale=args.locale,
            )
            print(json.dumps(body))


if __name__ == "__main__":
    main()
