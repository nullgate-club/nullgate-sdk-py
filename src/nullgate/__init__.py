"""Typed provider-neutral generation clients; target HTTP stays caller-owned."""

from magic_filter import F

from .akamai import Protection
from .client import (
    NullgateAPIError,
    NullgateClient,
    NullgateClientAsync,
    NullgateSession,
    NullgateSessionAsync,
)
from .html import AmbiguousProtectionError
from .models import Page, ScriptReference
from .solution import Solution, SolutionAsync

__all__ = [
    "AmbiguousProtectionError",
    "F",
    "NullgateAPIError",
    "NullgateClient",
    "NullgateClientAsync",
    "NullgateSession",
    "NullgateSessionAsync",
    "Page",
    "Protection",
    "ScriptReference",
    "Solution",
    "SolutionAsync",
]
