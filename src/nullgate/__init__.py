"""Typed provider-neutral generation clients; target HTTP stays caller-owned."""

from magic_filter import F

from .client import (
    NullgateAPIError,
    NullgateClient,
    NullgateClientAsync,
    NullgateSession,
    NullgateSessionAsync,
)
from .html import AmbiguousProtectionError, Protection
from .models import Page, ScriptReference
from .profile import (
    Profile,
    ProfileAsync,
    ProfileClosedError,
    ProfileError,
    ProfileProtocolError,
    ProfileServiceError,
    ProfileTransportError,
)
from .solution import Solution, SolutionAsync
from .target import Target, TargetRequest, TargetResponse, WreqTarget
from .threatmetrix import ThreatMetrix, ThreatMetrixParams

__all__ = [
    "AmbiguousProtectionError",
    "F",
    "NullgateAPIError",
    "NullgateClient",
    "NullgateClientAsync",
    "NullgateSession",
    "NullgateSessionAsync",
    "Page",
    "Profile",
    "ProfileAsync",
    "ProfileClosedError",
    "ProfileError",
    "ProfileProtocolError",
    "ProfileServiceError",
    "ProfileTransportError",
    "Protection",
    "ScriptReference",
    "Solution",
    "SolutionAsync",
    "Target",
    "TargetRequest",
    "TargetResponse",
    "ThreatMetrix",
    "ThreatMetrixParams",
    "WreqTarget",
]
