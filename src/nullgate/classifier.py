"""Image classification request validation and response shapes."""

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .errors import NullgateError

Image = bytes | bytearray | memoryview
_MAX_IMAGES = 32


@dataclass(frozen=True, slots=True)
class Classification:
    """Top label and one score per requested label, in request label order."""

    label: str
    scores: list[float]


@dataclass(frozen=True, slots=True)
class Classified:
    """One result per image, in request image order."""

    model: str
    results: list[Classification]


def _request(
    images: Image | Sequence[Image], labels: Sequence[str]
) -> tuple[list[bytes], list[str]]:
    batch = [images] if isinstance(images, Image) else images
    if isinstance(batch, str) or not isinstance(batch, Sequence):
        raise NullgateError(
            "images must be bytes or a sequence of bytes", code="invalid_request"
        )
    if not 1 <= len(batch) <= _MAX_IMAGES:
        raise NullgateError(
            f"images must contain 1 to {_MAX_IMAGES} items", code="invalid_request"
        )
    if not all(isinstance(image, Image) and len(image) for image in batch):
        raise NullgateError("Each image must be nonempty bytes", code="invalid_request")
    if isinstance(labels, str) or len(labels) < 2:
        raise NullgateError(
            "labels must contain at least 2 items", code="invalid_request"
        )
    return [bytes(image) for image in batch], list(labels)


def _classified(data: dict[str, Any], *, images: int, labels: list[str]) -> Classified:
    try:
        model, results = data["model"], data["results"]
        if not isinstance(model, str) or not isinstance(results, list):
            raise ValueError
        if len(results) != images:
            raise ValueError
        parsed = []
        for result in results:
            label, scores = result["label"], result["scores"]
            if label not in labels or not isinstance(scores, list):
                raise ValueError
            if len(scores) != len(labels) or not all(
                type(score) in (int, float) and math.isfinite(score) for score in scores
            ):
                raise ValueError
            parsed.append(Classification(label, [float(score) for score in scores]))
    except (KeyError, TypeError, ValueError):
        raise NullgateError(
            "Invalid classification response", code="invalid_response"
        ) from None
    return Classified(model, parsed)
