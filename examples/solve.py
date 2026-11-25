"""Start nullgate-http-api, then set TARGET_URL and USER_AGENT."""

import os

from nullgate.solver import Solver


def main() -> None:
    with Solver() as solver:
        response = solver.solve(
            type="akamai",
            url=os.environ["TARGET_URL"],
            user_agent=os.environ["USER_AGENT"],
            proxy=os.environ.get("TARGET_PROXY"),
            session="account-1",
        )
        print(response["cookies"])


if __name__ == "__main__":
    main()
