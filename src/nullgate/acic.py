"""Discover ACIC challenges and prepare requests for the caller's HTTP client.

Only literal protocol options are supported. Callback and div mount expressions
are never executed.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlsplit

from bs4 import BeautifulSoup

from .target import TargetRequest


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _origin(url: str) -> str:
    try:
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
        ):
            raise ValueError
        port = parts.port
    except (TypeError, ValueError):
        raise ValueError(
            "Expected an HTTPS URL without credentials or fragment"
        ) from None
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port and port != 443 else "")


def _object_end(text: str, start: int) -> int:
    stack: list[str] = []
    string = ""
    escaped = False
    pairs = {"}": "{", ")": "(", "]": "["}
    for index in range(start, len(text)):
        char = text[index]
        if string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == string:
                string = ""
        elif char in "\"'`":
            string = char
        elif char in "{([":
            stack.append(char)
        elif char in "})]":
            if not stack or stack.pop() != pairs[char]:
                break
            if not stack:
                return index + 1
    raise ValueError("Malformed ACIC bootstrap")


def _literal(raw: str) -> Any:
    if raw.startswith("'"):
        if not re.fullmatch(
            r"""'(?:[^'\\\r\n]|\\(?:['"\\/bfnrt]|u[0-9a-fA-F]{4}))*'""", raw
        ):
            raise ValueError("Unsupported ACIC string literal")

        def escape(match: re.Match[str]) -> str:
            token = match.group()
            if token == "\\'":
                return "'"
            if token == '"':
                return '\\"'
            return token

        raw = '"' + re.sub(r'\\.|"', escape, raw[1:-1]) + '"'
    return json.loads(raw)


def _properties(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    index = 1
    while index < len(text) - 1:
        match = re.match(r"\s*(?:,\s*)?([\"'])([^\"']+)\1\s*:\s*", text[index:])
        if not match:
            if not text[index:-1].strip().strip(",").strip():
                break
            raise ValueError("Unsupported ACIC bootstrap property")
        key = match.group(2)
        if key in result:
            raise ValueError("Duplicate ACIC bootstrap property")
        index += match.end()
        start = index
        # Values can contain nested callback functions. Only protocol properties
        # are decoded below; callbacks are skipped without executing them.
        stack: list[str] = []
        string = ""
        escaped = False
        while index < len(text) - 1:
            char = text[index]
            if string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == string:
                    string = ""
            elif char in "\"'`":
                string = char
            elif char in "{([":
                stack.append(char)
            elif char in "})]":
                if not stack:
                    raise ValueError("Malformed ACIC bootstrap property")
                stack.pop()
            elif char == "," and not stack:
                break
            index += 1
        raw = text[start:index].strip()
        if key == "data-div":
            if not raw or raw in {"null", "false", "undefined"}:
                raise ValueError("Invalid ACIC mount")
            result[key] = raw
            continue
        if key == "data-callback":
            result[key] = None
            continue
        try:
            value = _literal(raw)
        except (ValueError, SyntaxError):
            raise ValueError("Unsupported ACIC bootstrap property value") from None
        result[key] = value
    return result


_HOSTS = {
    "NA": "com",
    "US": "com",
    "EU": "de",
    "DE": "de",
    "FE": "co.jp",
    "JP": "co.jp",
    "CA": "ca",
    "MX": "com.mx",
    "AT": "at",
    "SG": "sg",
    "AU": "com.au",
    "PL": "pl",
    "TR": "com.tr",
    "IT": "it",
    "AE": "ae",
    "GB": "co.uk",
    "UK": "co.uk",
    "SA": "sa",
    "IN": "in",
    "FR": "fr",
    "ES": "es",
    "NL": "nl",
    "SE": "se",
    "BR": "com.br",
    "EG": "eg",
}


@dataclass(frozen=True, slots=True)
class Result:
    action_type: str
    client_side_context: Any = field(repr=False)
    session_token: str = field(repr=False)

    def voucher_response(self, voucher: str) -> str:
        if not isinstance(voucher, str):
            raise TypeError("Voucher must be a string")
        return _json({"challengeType": self.action_type, "data": _json(voucher)})


def parse_result(headers: Mapping[str, str]) -> Result | None:
    values = [
        value for key, value in headers.items() if key.lower() == "amz-aamation-resp"
    ]
    if not values:
        return None
    if len(values) != 1:
        raise ValueError("Ambiguous ACIC result header")
    try:
        value = json.loads(values[0])
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("actionType"), str)
            or not value["actionType"]
            or "clientSideContext" not in value
            or not isinstance(value.get("sessionToken"), str)
            or not value["sessionToken"]
        ):
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("Malformed ACIC result header") from None
    return Result(
        value["actionType"], value["clientSideContext"], value["sessionToken"]
    )


@dataclass(frozen=True, slots=True)
class Setup:
    service_url: str
    locale: str
    origin: str
    _options: str = field(repr=False)
    _form_action: str | None = field(repr=False)
    _form_method: str | None = field(repr=False)
    _form_fields: tuple[tuple[str, str], ...] = field(repr=False)
    _page_url: str = field(repr=False)

    def _request(self, context: Any, response: str, token: str | None) -> TargetRequest:
        body = {
            "context": context,
            "options": self._options,
            "response": response,
            "fwcimBlob": None,
        }
        url = self.service_url
        query: dict[str, str] = {"options": self._options}
        if token is not None:
            url += "/" + quote(token, safe="")
            query = {
                "context": context if isinstance(context, str) else _json(context),
                "options": self._options,
                "response": response,
            }
        return TargetRequest(
            "acic",
            url + "?" + urlencode(query),
            "POST",
            {
                "Content-Type": "application/json",
                "Origin": self.origin,
                "Referer": self._page_url,
            },
            _json(body).encode(),
            "include",
        )

    def start(self) -> TargetRequest:
        return self._request(None, "null", None)

    def answer(self, result: Result, response: str) -> TargetRequest:
        if not isinstance(result, Result) or not isinstance(response, str):
            raise TypeError("Expected an ACIC result and serialized response")
        return self._request(result.client_side_context, response, result.session_token)

    def continuation(self, result: Result) -> TargetRequest:
        if not isinstance(result, Result) or result.action_type != "PASS":
            raise ValueError("ACIC continuation requires a PASS result")
        if self._form_action is None:
            raise ValueError("ACIC continuation form is missing")
        if self._form_method != "post" or _origin(self._form_action) != self.origin:
            raise ValueError("ACIC continuation form must POST to the page origin")
        if not any(
            name == "cvf_aamation_response_token" for name, _ in self._form_fields
        ):
            raise ValueError("ACIC continuation form lacks its response token field")
        fields = [
            (
                name,
                result.session_token
                if name == "cvf_aamation_response_token"
                else value,
            )
            for name, value in self._form_fields
        ]
        return TargetRequest(
            "acic-continuation",
            self._form_action,
            "POST",
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.origin,
                "Referer": self._page_url,
            },
            urlencode(fields).encode(),
            "include",
        )


def discover(url: str, html: str) -> Setup | None:
    document = BeautifulSoup(html, "html.parser")
    scripts = [
        script.string or script.get_text() for script in document.find_all("script")
    ]
    calls = [
        (script, match)
        for script in scripts
        for match in re.finditer(r"\bacic\s*\.\s*setupACIC\s*\(", script)
    ]
    if not calls:
        return None
    if len(calls) != 1:
        raise ValueError("Ambiguous ACIC setup")
    origin = _origin(url)
    script, match = calls[0]
    start = match.end()
    while start < len(script) and script[start].isspace():
        start += 1
    if start >= len(script) or script[start] != "{":
        raise ValueError("Unsupported ACIC setup argument")
    end = _object_end(script, start)
    if not re.match(r"\s*\)", script[end:]):
        raise ValueError("Malformed ACIC setup call")
    props = _properties(script[start:end])
    required = (
        "data-ref-id",
        "data-challenge-type",
        "data-context",
        "data-locale",
        "data-external-id",
        "data-host-config",
    )
    if any(not isinstance(props.get(key), str) or not props[key] for key in required):
        raise ValueError("Missing or invalid ACIC bootstrap property")
    mounts = [key for key in ("data-div", "data-iframe-id") if key in props]
    if (
        len(mounts) != 1
        or not isinstance(props[mounts[0]], str)
        or not props[mounts[0]]
    ):
        raise ValueError("Invalid ACIC mount")
    host = urlsplit(url).hostname
    known_hosts = {"www.amazon." + suffix for suffix in _HOSTS.values()}
    config = re.fullmatch(r"prod\.([A-Z]+)Amazon", props["data-host-config"])
    if host in known_hosts:
        service_host = host
    elif config and config.group(1) in _HOSTS:
        service_host = "www.amazon." + _HOSTS[config.group(1)]
    else:
        raise ValueError("Unsupported ACIC host config")
    options: dict[str, Any] = {
        "clientData": props["data-context"],
        "challengeType": props["data-challenge-type"],
        "locale": props["data-locale"],
        "externalId": props["data-external-id"],
        "enableHeaderFooter": False,
        "enableBypassMechanism": False,
        "enableModalView": False,
        "eventTrigger": None,
        "aaExternalToken": None,
        "forceJsFlush": mounts[0] == "data-iframe-id",
        "aamationToken": None,
        "pageId": None,
    }
    mappings = {
        "data-header-footer": "enableHeaderFooter",
        "data-enable-bypass-mechanism": "enableBypassMechanism",
        "data-enable-modal-view": "enableModalView",
        "data-event-trigger": "eventTrigger",
        "data-aa-external-token": "aaExternalToken",
        "data-force-js-flush": "forceJsFlush",
        "data-aamation-token": "aamationToken",
        "data-page-id": "pageId",
    }
    for key, name in mappings.items():
        if key in props:
            value = props[key]
            if name in {
                "enableHeaderFooter",
                "enableBypassMechanism",
                "enableModalView",
                "forceJsFlush",
            }:
                if not isinstance(value, bool):
                    raise ValueError("Invalid ACIC boolean property")
            elif value is not None and not isinstance(value, str):
                raise ValueError("Invalid ACIC option property")
            options[name] = value
    forms = document.find_all("form", id="cvf-aamation-challenge-form")
    if len(forms) > 1:
        raise ValueError("Ambiguous ACIC continuation form")
    action = None
    method = None
    fields: list[tuple[str, str]] = []
    if forms:
        form = forms[0]
        action = urljoin(url, str(form.get("action", "")))
        method = str(form.get("method", "get")).lower()
        for item in form.find_all("input", disabled=False):
            if str(item.get("type", "text")).lower() == "hidden" and item.has_attr(
                "name"
            ):
                fields.append((str(item["name"]), str(item.get("value", ""))))
    service = (
        f"https://{service_host}/aaut/verify/{quote(props['data-ref-id'], safe='')}"
    )
    return Setup(
        service,
        props["data-locale"],
        origin,
        _json(options),
        action,
        method,
        tuple(fields),
        url,
    )


@dataclass(frozen=True, slots=True)
class Waf:
    problem_url: str = field(repr=False)
    locale: str
    rounds_required: int
    headers: Mapping[str, str]
    _provider: str = field(repr=False)

    def verification_url(self, problem: Mapping[str, Any]) -> str:
        region = problem.get("region")
        if region is not None and not isinstance(region, str):
            raise ValueError("Invalid WAF problem region")
        return (
            self._provider
            + "/verify"
            + ("?" + urlencode({"region": region}) if region else "")
        )


def discover_waf(url: str, html: str) -> Waf | None:
    document = BeautifulSoup(html, "html.parser")
    sources = [
        str(tag.get("src"))
        for tag in document.find_all("script", src=True)
        if urlsplit(str(tag.get("src"))).path.endswith("/captcha.js")
    ]
    scripts = [tag.string or tag.get_text() for tag in document.find_all("script")]
    assignments = [
        (script, match)
        for script in scripts
        for match in re.finditer(
            r"\bwafInputProperties\s*=\s*Object\s*\.\s*assign\s*\(", script
        )
    ]
    if not sources and not assignments:
        return None
    if len(sources) != 1 or len(assignments) != 1:
        raise ValueError("Malformed or ambiguous WAF view")
    origin = _origin(url)
    source = urljoin(url, sources[0])
    _origin(source)
    parsed = urlsplit(source)
    if (
        not parsed.hostname
        or not (
            parsed.hostname == "captcha.awswaf.com"
            or parsed.hostname.endswith(".captcha.awswaf.com")
        )
        or parsed.query
    ):
        raise ValueError("Invalid WAF provider URL")
    script, match = assignments[0]
    start = match.end()
    while start < len(script) and script[start].isspace():
        start += 1
    if start >= len(script) or script[start] != "{":
        raise ValueError("Unsupported WAF properties")
    end = _object_end(script, start)
    if not re.match(r"\s*,\s*wafOnLoadProperty\s*\)", script[end:]):
        raise ValueError("Unsupported WAF properties")
    try:

        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        props = json.loads(script[start:end], object_pairs_hook=unique)
        if (
            not isinstance(props, dict)
            or any(
                not isinstance(props.get(key), str) or not props[key]
                for key in ("problem", "defaultLocale", "id")
            )
            or type(props.get("visualSolutionsRequired")) is not int
            or props["visualSolutionsRequired"] < 1
        ):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("Malformed WAF properties") from None
    provider = source[: -len("/captcha.js")]
    locale = props["defaultLocale"].lower()
    query = urlencode(
        {
            "kind": "visual",
            "domain": urlsplit(url).hostname,
            "locale": locale,
            "problem": props["problem"],
            "num_solutions_required": props["visualSolutionsRequired"],
            "id": props["id"],
        }
    )
    return Waf(
        provider + "/problem?" + query,
        locale,
        props["visualSolutionsRequired"],
        {
            "Origin": origin,
            "Referer": origin + "/",
            "Content-Type": "text/plain;charset=UTF-8",
        },
        provider,
    )
