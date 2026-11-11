"""Typed provider-neutral generation clients; target HTTP stays caller-owned."""

from magic_filter import F

from .amazon import FwcimParams, FwcimSolution, FwcimSolutionAsync
from .client import (
    NullgateAPIError,
    NullgateClient,
    NullgateClientAsync,
    NullgateSession,
    NullgateSessionAsync,
)
from .errors import ErrorInfo, ErrorTarget, TransportCause
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
from .threatmetrix import ThreatMetrix, ThreatMetrixCollector, ThreatMetrixParams

__all__ = [
    "AmbiguousProtectionError",
    "ErrorInfo",
    "ErrorTarget",
    "F",
    "FwcimParams",
    "FwcimSolution",
    "FwcimSolutionAsync",
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
    "ThreatMetrixCollector",
    "ThreatMetrixParams",
    "TransportCause",
    "WreqTarget",
]
