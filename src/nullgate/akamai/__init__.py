"""Supported Akamai protections, generation inputs, and local cookie helpers."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import ClassVar, Literal, TypeAlias
from urllib.parse import urlsplit

from ..models import Page, ScriptReference
from .cookies import abck_counters, is_enough
from .inputs import InputValue, PreparedInput, prepare_inputs

__all__ = [
    "InputValue",
    "Pixel",
    "PixelParams",
    "PreparedInput",
    "Sbsd",
    "SbsdParams",
    "Sensor",
    "SensorParams",
    "abck_counters",
    "is_enough",
    "prepare_inputs",
]


@dataclass(frozen=True, slots=True)
class Pixel:
    page: Page
    script_url: str
    challenge: str
    provenance: ScriptReference | None = field(default=None, kw_only=True)
    challenge_offset: int | None = field(default=None, kw_only=True)
    provider: ClassVar[Literal["akamai"]] = "akamai"
    kind: ClassVar[Literal["pixel"]] = "pixel"


@dataclass(frozen=True, slots=True)
class Sensor:
    """An extensionless classic-script candidate, or caller-identified Sensor."""

    page: Page
    script_url: str
    provenance: ScriptReference | None = field(default=None, kw_only=True)
    provider: ClassVar[Literal["akamai"]] = "akamai"
    kind: ClassVar[Literal["sensor"]] = "sensor"


@dataclass(frozen=True, slots=True)
class Sbsd:
    page: Page
    script_url: str
    provenance: ScriptReference | None = field(default=None, kw_only=True)
    provider: ClassVar[Literal["akamai"]] = "akamai"
    kind: ClassVar[Literal["sbsd"]] = "sbsd"

    @property
    def blocking(self) -> bool:
        """The source URL's t parameter is present, even if its value is empty."""
        return any(
            part.partition("=")[0] == "t"
            for part in urlsplit(self.script_url).query.split("&")
        )


@dataclass(frozen=True, slots=True)
class PixelParams:
    protection: Pixel
    script: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.protection, Pixel):
            raise TypeError("PixelParams requires a Pixel protection")


@dataclass(frozen=True, slots=True)
class SensorParams:
    protection: Sensor
    script: str = field(repr=False)
    cookies: Mapping[str, str] | None = field(default=None, repr=False)
    inputs: Sequence[Mapping[str, str]] | None = field(default=None, repr=False)
    actions: Sequence[Mapping[str, object]] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.protection, Sensor):
            raise TypeError("SensorParams requires a Sensor protection")


@dataclass(frozen=True, slots=True)
class SbsdParams:
    protection: Sbsd
    script: str = field(repr=False)
    cookies: Mapping[str, str] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.protection, Sbsd):
            raise TypeError("SbsdParams requires an Sbsd protection")


Protection: TypeAlias = Pixel | Sensor | Sbsd
Params: TypeAlias = PixelParams | SensorParams | SbsdParams
