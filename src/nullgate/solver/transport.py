"""Browser-profile HTTP transport; httpx owns cookie scope and export metadata."""

import re
from collections.abc import Mapping
from datetime import timedelta
from http.cookiejar import DefaultCookiePolicy
from typing import Any

import httpx
import wreq
from wreq import emulation, http2, tls

from ..target import TargetRequest, TargetResponse, _proxy_url
from .models import SolveError, http_url

_BODY_LIMIT = 8 * 1024 * 1024


def _browser_headers(user_agent: str) -> dict[str, str]:
    headers = {"user-agent": user_agent, "accept-language": "en-US,en;q=0.9"}
    chrome = re.search(r"Chrome/(\d+)", user_agent)
    if chrome:
        major = chrome[1]
        brand = "Microsoft Edge" if "Edg/" in user_agent else "Google Chrome"
        platform = (
            "Android"
            if "Android" in user_agent
            else "Windows"
            if "Windows" in user_agent
            else "macOS"
            if "Macintosh" in user_agent
            else "Linux"
        )
        # Low-entropy Chrome header model; high-entropy hints stay caller-owned.
        headers.update(
            {
                "sec-ch-ua": (
                    f'"Chromium";v="{major}", "{brand}";v="{major}", '
                    '"Not A(Brand";v="99"'
                ),
                "sec-ch-ua-mobile": "?1" if "Mobile" in user_agent else "?0",
                "sec-ch-ua-platform": f'"{platform}"',
            }
        )
    return headers


def _profile(user_agent: str, name: object) -> wreq.Emulation:
    platform = (
        emulation.Platform.Android
        if "Android" in user_agent
        else emulation.Platform.IOS
        if any(s in user_agent for s in ("iPhone", "iPad"))
        else emulation.Platform.Windows
        if "Windows" in user_agent
        else emulation.Platform.MacOS
        if "Macintosh" in user_agent
        else emulation.Platform.Linux
    )
    if name is None:
        family, version = "Chrome", 154
        for token, prefix in (
            ("Edg/", "Edge"),
            ("Firefox/", "Firefox"),
            ("Chrome/", "Chrome"),
            ("Version/", "Safari"),
        ):
            match = re.search(re.escape(token) + r"(\d+)", user_agent)
            if match:
                family, version = prefix, int(match[1])
                break
        if platform == emulation.Platform.IOS:
            family = "SafariIPad" if "iPad" in user_agent else "SafariIos"
            if os_version := re.search(r"OS (\d+)", user_agent):
                version = int(os_version[1])
        candidates = [
            (int(m[1]), key)
            for key in dir(emulation.Profile)
            if (m := re.fullmatch(family + r"(\d+)(?:_\d+)*", key, re.IGNORECASE))
        ]
        if not candidates:
            raise SolveError(
                "invalid_request",
                "No matching browser profile; set transport.emulation explicitly",
                stage="validate",
            )
        name = min(candidates, key=lambda x: (abs(x[0] - version), -x[0]))[1]
    selected = getattr(emulation.Profile, name, None) if isinstance(name, str) else None
    if not isinstance(selected, emulation.Profile):
        raise SolveError(
            "invalid_request", "Unknown wreq emulation profile", stage="validate"
        )
    return wreq.Emulation(profile=selected, platform=platform)


def _settings(options: dict[str, Any] | None, user_agent: str) -> dict[str, Any]:
    options = options or {}
    if set(options) - {"emulation", "tls_options", "http2_options"}:
        raise SolveError(
            "invalid_request",
            "Unknown transport setting; use emulation, tls_options or http2_options",
            stage="validate",
        )
    result: dict[str, Any] = {
        "emulation": _profile(user_agent, options.get("emulation"))
    }
    for name, module, constructor in (
        ("tls_options", tls, wreq.TlsOptions),
        ("http2_options", http2, wreq.Http2Options),
    ):
        if name not in options:
            continue
        values = options[name]
        if (
            not isinstance(values, dict)
            or set(values) - module.Params.__annotations__.keys()
        ):
            raise SolveError(
                "invalid_request", f"Unknown {name} option", stage="validate"
            )
        values = dict(values)
        enums: dict[str, Any] = (
            {
                "alpn_protocols": tls.AlpnProtocol,
                "alps_protocols": tls.AlpsProtocol,
                "key_shares": tls.KeyShare,
                "certificate_compression_algorithms": (
                    tls.CertificateCompressionAlgorithm
                ),
                "extension_permutation": tls.ExtensionType,
            }
            if name == "tls_options"
            else {}
        )
        try:
            for key, enum in enums.items():
                if key in values:
                    values[key] = [getattr(enum, item) for item in values[key]]
            for key in ("min_tls_version", "max_tls_version"):
                if key in values:
                    values[key] = getattr(tls.TlsVersion, values[key])
            if "headers_pseudo_order" in values:
                values["headers_pseudo_order"] = http2.PseudoOrder(
                    *(
                        getattr(http2.PseudoId, item)
                        for item in values["headers_pseudo_order"]
                    )
                )
            if "settings_order" in values:
                values["settings_order"] = http2.SettingsOrder(
                    *(
                        getattr(http2.SettingId, item)
                        for item in values["settings_order"]
                    )
                )
            for key in ("keep_alive_interval", "keep_alive_timeout"):
                if key in values:
                    values[key] = timedelta(seconds=values[key])
            for key in ("headers_stream_dependency", "priorities"):
                if key in values:
                    raise ValueError("unsupported structured HTTP2 option")
            result[name] = constructor(**values)
        except (AttributeError, TypeError, ValueError, KeyError, OverflowError):
            raise SolveError(
                "invalid_request",
                f"Invalid {name}; use wreq enum names and JSON scalar options",
                stage="validate",
            ) from None
    return result


class Transport:
    def __init__(
        self,
        user_agent: str,
        proxy: str | None,
        options: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        try:
            self.proxy = _proxy_url(proxy)
        except ValueError:
            raise SolveError(
                "invalid_request",
                "proxy must be an HTTP/SOCKS URL with an explicit port",
                stage="validate",
            ) from None
        self.user_agent = user_agent
        self.cookies = httpx.Cookies()
        self.cookies.jar.set_policy(
            DefaultCookiePolicy(
                strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain,
                strict_domain=True,
            )
        )
        self._headers = dict(headers or {})
        self._origin: tuple[str, str, int | None] | None = None
        self._document: httpx.URL | None = None
        self._client = wreq.Client(
            **_settings(options, user_agent),
            user_agent=user_agent,
            no_proxy=self.proxy is None,
            proxies=[wreq.Proxy.all(self.proxy)] if self.proxy else [],
            redirect=wreq.Policy.none(),
            timeout=timedelta(seconds=30),
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        credentials: bool = True,
        navigation: bool = False,
    ) -> httpx.Response:
        http_url(url)
        initial = httpx.URL(url)
        if self._origin is None:
            self._origin = (initial.scheme, initial.host, initial.port)
        for redirect_count in range(11):
            current = httpx.URL(url)
            same_origin = (current.scheme, current.host, current.port) == self._origin
            outgoing = httpx.Headers(_browser_headers(self.user_agent))
            if same_origin:
                outgoing.update(self._headers)
            if navigation:
                self._document = current
            elif self._document is not None:
                document = self._document
                if document.scheme != "https" or current.scheme == "https":
                    identical_origin = (
                        document.scheme,
                        document.host,
                        document.port,
                    ) == (current.scheme, current.host, current.port)
                    outgoing["referer"] = str(
                        document
                        if identical_origin
                        else document.copy_with(path="/", query=None, fragment=None)
                    )
            if navigation:
                outgoing.update(
                    {
                        "accept": (
                            "text/html,application/xhtml+xml,"
                            "application/xml;q=0.9,*/*;q=0.8"
                        ),
                        "sec-fetch-dest": "document",
                        "sec-fetch-mode": "navigate",
                        "sec-fetch-site": "none",
                        "sec-fetch-user": "?1",
                    }
                )
            elif method == "GET":
                outgoing.update(
                    {
                        "accept": "*/*",
                        "sec-fetch-dest": "script",
                        "sec-fetch-mode": "no-cors",
                        "sec-fetch-site": "same-origin"
                        if same_origin
                        else "cross-site",
                    }
                )
            outgoing.update(headers or {})
            if not same_origin or not credentials:
                for key in ("authorization", "proxy-authorization"):
                    outgoing.pop(key, None)
            outgoing["user-agent"] = self.user_agent
            outgoing.pop("cookie", None)
            probe = httpx.Request(method, url, headers=outgoing, content=body)
            if credentials:
                self.cookies.set_cookie_header(probe)
            try:
                response = await self._client.request(
                    getattr(wreq.Method, method.upper()),
                    url,
                    headers=dict(probe.headers),
                    body=body,
                    # Context headers must not inherit navigation-only profile fields.
                    default_headers=False,
                )
                async with response:
                    pairs = [
                        (bytes(key), bytes(value))
                        for key in response.headers.keys()
                        for value in response.headers.get_all(
                            bytes(key).decode("ascii")
                        )
                    ]
                    chunks = bytearray()
                    async with response.stream() as stream:
                        async for chunk in stream:
                            if isinstance(chunk, wreq.HeaderMap):
                                continue
                            if len(chunks) + len(chunk) > _BODY_LIMIT:
                                raise SolveError(
                                    "target_error",
                                    "Target response exceeds 8 MiB",
                                    stage="target",
                                )
                            chunks.extend(chunk)
                    result = httpx.Response(
                        response.status.as_int(),
                        content=bytes(chunks),
                        request=probe,
                    )
                    # wreq has already decoded Content-Encoding during streaming.
                    result.headers = httpx.Headers(pairs)
            except SolveError:
                raise
            except Exception as error:
                raise SolveError(
                    "transport_error",
                    "Target HTTP transport failed",
                    stage="target",
                    cause=type(error).__name__,
                ) from None
            if credentials:
                self.cookies.extract_cookies(result)
            if (
                method == "GET"
                and result.status_code in (301, 302, 303, 307, 308)
                and "location" in result.headers
            ):
                if redirect_count == 10:
                    raise SolveError(
                        "target_error", "Too many target redirects", stage="page"
                    )
                url = str(current.join(result.headers["location"]))
                http_url(url)
                if (
                    httpx.URL(url).scheme,
                    httpx.URL(url).host,
                    httpx.URL(url).port,
                ) != (current.scheme, current.host, current.port):
                    headers = {
                        k: v
                        for k, v in (headers or {}).items()
                        if k.lower()
                        not in {"authorization", "proxy-authorization", "cookie"}
                    }
                continue
            return result
        raise AssertionError("unreachable redirect loop")

    async def send(self, request: TargetRequest) -> TargetResponse:
        response = await self.request(
            request.method,
            request.url,
            headers=request.headers,
            body=request.body,
            credentials=request.credentials == "include",
        )
        return TargetResponse(
            response.status_code, dict(response.headers), response.content
        )

    async def aclose(self) -> None:
        self._client.close()
