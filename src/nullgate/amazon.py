"""Public Amazon observations only; no JavaScript or credential submission."""

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from struct import iter_unpack
from typing import NotRequired, TypedDict, cast
from zlib import crc32

import soupsieve
from bs4 import BeautifulSoup, Tag
from bs4.element import NavigableString

from .akamai.inputs import (
    InputValue,
    _prepare_actions,
    _validate_summary,
    prepare_inputs,
)
from .models import Page


@dataclass(frozen=True, slots=True)
class AcicWaf:
    client_solution: list[int]
    request_id: str

    def verification_body(
        self, problem: Mapping[str, object], *, elapsed_seconds: float, locale: str
    ) -> dict[str, object]:
        """Build the AWS verification body without sending it."""
        return {
            "state": problem["state"],
            "key": problem["key"],
            "hmac_tag": problem["hmac_tag"],
            "client_solution": self.client_solution,
            "metrics": {"solve_time_millis": int(elapsed_seconds * 1000)},
            "locale": locale,
        }


class Geometry(TypedDict):
    width: float
    height: float
    left: NotRequired[float]
    top: NotRequired[float]


class InputObservation(TypedDict):
    attributes: dict[str, str]
    value: InputValue
    checksum: NotRequired[int | None]
    selector: NotRequired[str]
    geometry: NotRequired[Geometry]
    text: NotRequired[str | None]


def _retain_nonempty_value(
    attributes: dict[str, str | list[str]], key: str, value: str
) -> None:
    # Duplicate values remain in the original HTML sent across the boundary.
    if key == "value" and value:
        attributes[key] = value


def _document(page: Page) -> BeautifulSoup:
    document = BeautifulSoup(
        page.html, "html.parser", on_duplicate_attribute=_retain_nonempty_value
    )
    if any(
        _password_control(node)
        and (
            node.get("value")
            or node.name == "textarea"
            and any(
                isinstance(child, NavigableString) and bool(child)
                for child in node.descendants
            )
        )
        for node in cast(list[Tag], document.find_all(["input", "textarea"]))
    ):
        raise ValueError("Page HTML must not contain password values")
    # Native selectors cannot traverse a template's separate content fragment.
    for template in document.find_all("template"):
        template.clear()
    return document


def _password_control(node: Tag) -> bool:
    def normalize(value: object) -> str:
        return str(value).strip().lower()

    return (
        normalize(node.get("type", "")) == "password"
        or bool(
            {"current-password", "new-password"}
            & set(normalize(node.get("autocomplete", "")).split())
        )
        or any(
            normalize(node.get(key, "")) in {"password", "ap_password"}
            for key in ("id", "name")
        )
    )


def _wire_value(value: object) -> object:
    """Detach JSON containers without running caller-defined serialization hooks."""
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if isinstance(value, dict):
        if any(type(key) is not str for key in dict.keys(value)):
            raise ValueError("Observation object keys must be strings")
        return {key: _wire_value(item) for key, item in dict.items(value)}
    if isinstance(value, list):
        return [_wire_value(item) for item in list.__iter__(value)]
    if isinstance(value, tuple):
        return tuple(_wire_value(item) for item in tuple.__iter__(value))
    raise ValueError("Observations must contain finite JSON values")


def _input_node(
    document: BeautifulSoup, attributes: Mapping[str, str], selector: str | None
) -> Tag:
    if not attributes.keys() <= {"id", "name"}:
        raise ValueError("Input attributes support only id/name")
    if not all(isinstance(value, str) for value in attributes.values()):
        raise TypeError("Input identity attributes must be strings")
    if selector is not None:
        if not isinstance(selector, str) or not selector.strip():
            raise ValueError("Input selector must be nonempty")
        try:
            candidates: list[Tag] = document.select(selector)
        except soupsieve.SelectorSyntaxError:
            raise ValueError("Invalid input selector") from None
        if len(candidates) != 1:
            raise ValueError("Input selector must match exactly one element")
    else:
        if not attributes:
            raise ValueError("Input requires id/name or a selector")
        candidates = cast(
            list[Tag],
            document.find_all(["input", "textarea"], attrs=dict(attributes)),
        )
    if (
        len(candidates) != 1
        or candidates[0].name not in {"input", "textarea"}
        or any(candidates[0].get(key) != value for key, value in attributes.items())
    ):
        raise ValueError("Input must match exactly one input or textarea")
    return candidates[0]


def observe_input(
    page: Page,
    value: str,
    *,
    id: str | None = None,
    name: str | None = None,
    selector: str | None = None,
    geometry: Geometry | None = None,
    include_text: bool = False,
) -> InputObservation:
    """Summarize a DOM-confirmed nonpassword value, optionally retaining canvas text."""
    attributes = {
        key: val for key, val in (("id", id), ("name", name)) if val is not None
    }
    node = _input_node(_document(page), attributes, selector)
    if _password_control(node):
        raise ValueError("Raw password observations are not allowed")
    if not isinstance(value, str):
        raise TypeError("Input value must be a string")
    summary = prepare_inputs([{"value": value}])[0]["value"]
    # CESU-8 encodes UTF-16 units independently, including surrogate pairs.
    encoded = b"".join(
        chr(unit).encode("utf-8", errors="surrogatepass")
        for (unit,) in iter_unpack(
            "<H", value.encode("utf-16-le", errors="surrogatepass")
        )
    )
    observation: InputObservation = {
        "attributes": attributes,
        "value": summary,
        "checksum": crc32(encoded),
    }
    if selector is not None:
        observation["selector"] = selector
    if geometry is not None:
        observation["geometry"] = geometry.copy()
    if include_text:
        observation["text"] = value
    return observation


@dataclass(frozen=True, slots=True)
class _Params:
    page: Page
    performance_timing: Mapping[str, int] = field(repr=False)
    cookies: Mapping[str, str] | None = field(default=None, repr=False)
    form_selector: str | None = None
    inputs: Sequence[InputObservation] | None = field(default=None, repr=False)
    actions: Sequence[Mapping[str, object]] | None = field(default=None, repr=False)
    submitted: bool = True
    referrer: str = ""
    history_length: int | None = None


def _payload(params: _Params, timezone: str | None) -> dict[str, object]:
    if not isinstance(params, _Params):
        raise TypeError("Invalid form observations")
    document = _document(params.page)
    if type(params.submitted) is not bool or not isinstance(params.referrer, str):
        raise ValueError("submitted must be a boolean and referrer must be a string")
    if params.history_length is not None and (
        type(params.history_length) is not int or params.history_length < 1
    ):
        raise ValueError("history_length must be a positive integer")
    timing = dict(params.performance_timing)
    if any(
        not isinstance(key, str) or type(value) is not int or value < 0
        for key, value in timing.items()
    ):
        raise ValueError("performance_timing needs nonnegative integer timestamps")
    if (
        params.page.started_at_ms <= 0
        or timing.get("navigationStart") != params.page.started_at_ms
    ):
        raise ValueError(
            "performance_timing.navigationStart must match positive Page start"
        )
    if any(
        value != 0 and value < params.page.started_at_ms for value in timing.values()
    ):
        raise ValueError(
            "Nonzero performance timestamps must not precede navigationStart"
        )
    form: Tag | None = None
    if params.form_selector is not None:
        if (
            not isinstance(params.form_selector, str)
            or not params.form_selector.strip()
        ):
            raise ValueError("Form selector must be nonempty")
        try:
            forms = document.select(params.form_selector)
        except soupsieve.SelectorSyntaxError:
            raise ValueError("Invalid form selector") from None
        if len(forms) != 1 or forms[0].name != "form":
            raise ValueError("Form selector must match exactly one form")
        form = forms[0]
    website: dict[str, object] = {
        "url": params.page.url,
        "html": params.page.html,
        "document_id": params.page.document_id,
        "started_at_ms": params.page.started_at_ms,
        "referrer": params.referrer,
    }
    if params.history_length is not None:
        website["history_length"] = params.history_length
    values: dict[str, object] = {
        "website": website,
        "cookies": dict(params.cookies or {}),
        "submitted": params.submitted,
        "performance_timing": timing,
    }
    if timezone is not None:
        values["timezone"] = timezone
    if params.form_selector is not None:
        values["form_selector"] = params.form_selector
    if params.inputs is not None:
        inputs: list[dict[str, object]] = []
        for observation in cast(list[InputObservation], _wire_value(params.inputs)):
            if (
                not isinstance(observation, dict)
                or not {"attributes", "value"} <= observation.keys()
                or not isinstance(observation["attributes"], dict)
            ):
                raise ValueError("Input observation requires attributes and value")
            node = _input_node(
                document, observation["attributes"], observation.get("selector")
            )
            if form is not None and not any(parent is form for parent in node.parents):
                raise ValueError("Observed input must be inside the selected form")
            if _password_control(node) and (
                "text" in observation or "checksum" in observation
            ):
                raise ValueError("Password text and checksums are not allowed")
            _validate_summary(observation["value"])
            if not observation.keys() <= {
                "attributes",
                "value",
                "selector",
                "checksum",
                "geometry",
                "text",
            }:
                raise ValueError("Input observation contains unsupported fields")
            checksum = observation.get("checksum")
            if checksum is not None and (
                type(checksum) is not int or not 0 <= checksum <= 0xFFFFFFFF
            ):
                raise ValueError("Input checksum must be a uint32 or null")
            if observation.get("text") is not None and not isinstance(
                observation["text"], str
            ):
                raise ValueError("Input text must be a string or null")
            geometry = observation.get("geometry")
            if geometry is not None and (
                not isinstance(geometry, dict)
                or not {"width", "height"} <= geometry.keys()
                or not geometry.keys() <= {"left", "top", "width", "height"}
                or any(
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(value)
                    for value in geometry.values()
                )
                or geometry["width"] < 0
                or geometry["height"] < 0
            ):
                raise ValueError("Input geometry needs finite nonnegative dimensions")
            inputs.append(dict(observation))
        values["inputs"] = inputs
    if params.actions is not None:
        actions = _prepare_actions(
            cast(list[Mapping[str, object]], _wire_value(params.actions))
        )
        allowed = {
            "type",
            "time",
            "target",
            "target_path",
            "trusted",
            "x",
            "y",
            "button",
            "which",
            "pointer_type",
            "pointer_id",
            "key_code",
            "char_code",
            "shift",
            "ctrl",
            "alt",
            "meta",
            "touches",
            "alpha",
            "beta",
            "gamma",
            "absolute",
            "acceleration",
            "acceleration_with_gravity",
            "rotation_rate",
            "interval",
            "input_summary",
        }
        for action in actions:
            if not action.keys() <= allowed:
                raise ValueError("Actions contain unsupported fields")
            _validate_action(action)
        values["actions"] = actions
    return cast(dict[str, object], _wire_value(values))


def _number_or_none(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _validate_action(action: Mapping[str, object]) -> None:
    for key in ("type", "target_path", "pointer_type"):
        if key in action and not isinstance(action[key], str):
            raise ValueError("Action string fields must be strings")
    if action.get("target") is not None and type(action["target"]) is not int:
        raise ValueError("Action target must be an integer or null")
    for key in ("trusted", "shift", "ctrl", "alt", "meta", "absolute"):
        if action.get(key) is not None and type(action[key]) is not bool:
            raise ValueError("Action flags must be booleans or null")
    for key in (
        "time",
        "x",
        "y",
        "button",
        "which",
        "pointer_id",
        "key_code",
        "char_code",
        "alpha",
        "beta",
        "gamma",
        "interval",
    ):
        if not _number_or_none(action.get(key)):
            raise ValueError("Action numeric fields must be finite numbers or null")
    if "touches" in action:
        touches = action["touches"]
        if not isinstance(touches, (list, tuple)) or any(
            not isinstance(point, Mapping)
            or not {"x", "y"} <= point.keys() <= {"x", "y", "identifier"}
            or any(
                point[key] is None or not _number_or_none(point[key])
                for key in ("x", "y")
            )
            or ("identifier" in point and type(point["identifier"]) is not int)
            for point in touches
        ):
            raise ValueError("Action touches must contain only numeric touch facts")
    for key in ("acceleration", "acceleration_with_gravity", "rotation_rate"):
        vector = action.get(key)
        if vector is not None and (
            not isinstance(vector, (list, tuple))
            or len(vector) != 3
            or any(not _number_or_none(value) for value in vector)
        ):
            raise ValueError(
                "Action vectors must contain three nullable finite numbers"
            )
    if "input_summary" in action:
        summary = action["input_summary"]
        if (
            not isinstance(summary, (list, tuple))
            or len(summary) != 2
            or type(summary[0]) is not int
            or summary[0] < 0
            or (
                summary[1] is not None
                and (
                    not isinstance(summary[1], (list, tuple))
                    or len(summary[1]) != 4
                    or any(type(count) is not int or count < 0 for count in summary[1])
                )
            )
        ):
            raise ValueError(
                "Action input_summary must be a redacted length/counts pair"
            )
