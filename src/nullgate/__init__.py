"""Prepare target requests with Nullgate. Your HTTP client sends them."""

from .client import Nullgate
from .errors import NullgateError
from .target import TargetRequest, TargetResponse

__all__ = ["Nullgate", "NullgateError", "TargetRequest", "TargetResponse"]
__version__ = "2.0.0"
