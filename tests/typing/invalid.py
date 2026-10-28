"""Intentionally invalid consumers, checked by test_typing.py, never executed."""

from nullgate import (
    NullgateClient,
    NullgateClientAsync,
    NullgateSession,
    NullgateSessionAsync,
    Page,
)
from nullgate.akamai import Pixel, PixelParams, Sbsd, SbsdParams, Sensor, SensorParams
from nullgate.html import find_protections


def wrong_pairings(pixel: Pixel, sensor: Sensor, sbsd: Sbsd) -> None:
    PixelParams(sensor, "source")
    SensorParams(sbsd, "source")
    SbsdParams(pixel, "source")
    PixelParams(pixel, {"source": "a URL is not script text"})


def wrong_sync(
    session: NullgateSession, client: NullgateClient, page: Page, pixel: Pixel
) -> None:
    session.solve(pixel)
    client.find_protections(page, where=lambda item: True)
    client.find_protections(page, panic="false")
    find_protections(page, panic="false")


async def wrong_async(
    session: NullgateSessionAsync, client: NullgateClientAsync, page: Page, pixel: Pixel
) -> None:
    await session.solve(pixel)
    client.find_protections(page, where=lambda item: True)
    client.find_protections(page, panic="false")
