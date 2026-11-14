"""Prepare target requests with Nullgate. Use ``acic`` for local ACIC discovery."""

from . import acic
from .akamai import PreparedInput, abck_counters, is_enough, prepare_inputs
from .client import Nullgate
from .errors import NullgateError
from .target import TargetRequest, TargetResponse

__all__ = [
    "Nullgate",
    "NullgateError",
    "PreparedInput",
    "TargetRequest",
    "TargetResponse",
    "acic",
    "abck_counters",
    "is_enough",
    "prepare_inputs",
]
__version__ = "2.0.0"
