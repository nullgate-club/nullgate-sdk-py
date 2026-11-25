"""Solve a page with your own API key, user agent, and optional proxy."""

import asyncio
import os

from nullgate.solver import Solver


async def main() -> None:
    async with Solver() as solver:
        cookies = await solver.solve(
            type="akamai",
            url=os.environ["TARGET_URL"],
            user_agent=os.environ["USER_AGENT"],
            proxy=os.environ.get("TARGET_PROXY"),
        )
        print(cookies)


if __name__ == "__main__":
    asyncio.run(main())
