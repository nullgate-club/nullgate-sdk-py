"""Compile-time consumers for narrowing and synchronous/asynchronous boundaries."""

from typing import assert_type
from uuid import UUID

from nullgate import (
    F,
    NullgateClient,
    NullgateClientAsync,
    NullgateSession,
    NullgateSessionAsync,
    Page,
    Profile,
    ProfileAsync,
    Protection,
    Solution,
    SolutionAsync,
    Target,
    ThreatMetrix,
    ThreatMetrixParams,
)
from nullgate.akamai import Pixel, PixelParams, Sbsd, SbsdParams, Sensor, SensorParams
from nullgate.html import find_protections


def sync_consumer(client: NullgateClient, page: Page, source: str) -> None:
    found = client.find_protections(page, where=F.provider == "akamai", panic=False)
    # Runtime F filtering does not claim to narrow the static union.
    assert_type(found, list[Protection])
    assert_type(find_protections(page, panic=False), list[Protection])
    assert_type(client.open(identity=UUID(int=1), user_agent="UA"), NullgateSession)
    with client.open(identity=str(UUID(int=1)), user_agent="UA") as session:
        for protection in found:
            match protection:
                case Pixel():
                    assert_type(protection, Pixel)
                    assert_type(
                        session.solve(PixelParams(protection, source)), Solution
                    )
                case Sensor():
                    assert_type(protection, Sensor)
                    assert_type(
                        session.solve(SensorParams(protection, source)), Solution
                    )
                case Sbsd():
                    assert_type(protection, Sbsd)
                    assert_type(protection.blocking, bool)
                    assert_type(session.solve(SbsdParams(protection, source)), Solution)


async def async_consumer(client: NullgateClientAsync, page: Page, source: str) -> None:
    assert_type(client.find_protections(page, panic=True), list[Protection])
    assert_type(
        client.open(identity=UUID(int=1), user_agent="UA"), NullgateSessionAsync
    )
    async with client.open(identity=UUID(int=1), user_agent="UA") as session:
        for protection in client.find_protections(
            page, where=F.provider == "akamai", panic=False
        ):
            match protection:
                case Pixel():
                    assert_type(protection, Pixel)
                    result = await session.solve(PixelParams(protection, source))
                    assert_type(result, SolutionAsync)
                case Sensor():
                    assert_type(protection, Sensor)
                    assert_type(
                        await session.solve(SensorParams(protection, source)),
                        SolutionAsync,
                    )
                case Sbsd():
                    assert_type(protection, Sbsd)
                    assert_type(
                        await session.solve(SbsdParams(protection, source)),
                        SolutionAsync,
                    )


def sync_profile_consumer(client: NullgateClient, page: Page, target: Target) -> None:
    with client.open(identity=UUID(int=1), user_agent="UA") as session:
        for protection in client.find_protections(page, panic=False):
            if isinstance(protection, ThreatMetrix):
                with session.profile(ThreatMetrixParams(protection), target) as profile:
                    assert_type(profile, Profile)
                    profile.pagehide(persisted=True)


async def async_profile_consumer(
    client: NullgateClientAsync, page: Page, target: Target
) -> None:
    async with client.open(identity=UUID(int=1), user_agent="UA") as session:
        for protection in client.find_protections(page, panic=False):
            if isinstance(protection, ThreatMetrix):
                async with await session.profile(
                    ThreatMetrixParams(protection), target
                ) as profile:
                    assert_type(profile, ProfileAsync)
                    await profile.pagehide(persisted=True)
