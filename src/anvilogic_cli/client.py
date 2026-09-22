from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from anvilogic_cli import __version__
from anvilogic_cli.errors import ConfigError, TransportError

SAFE_RETRY_METHODS = {"GET", "HEAD", "OPTIONS"}
RETRY_STATUSES = {429, 500, 502, 503, 504}
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
SENSITIVE_NAME_PARTS = (
    "api-key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "jwt",
    "password",
    "private-key",
    "refresh-token",
    "secret",
    "token",
)


@dataclass(frozen=True)
class RequestPlan:
    method: str
    url: str
    query: tuple[tuple[str, str], ...]
    headers: dict[str, str]
    json_body: Any = None


def auth_headers(api_key: str | None, scheme: str) -> dict[str, str]:
    if scheme == "none":
        return {}
    if not api_key:
        raise ConfigError("An API key is required unless auth scheme 'none' is selected.")
    if scheme == "bearer":
        return {"Authorization": f"Bearer {api_key}"}
    if scheme == "token":
        return {"Authorization": f"Token {api_key}"}
    if scheme == "x-api-key":
        return {"X-API-Key": api_key}
    raise ConfigError(f"Unsupported authentication scheme: {scheme}")


def build_url(base_url: str, path: str) -> str:
    candidate = path.strip()
    if not candidate:
        raise ValueError("Request path cannot be empty.")
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        raise ValueError("Request path must be relative; configure the host with --base-url.")
    if parsed.query or parsed.fragment:
        raise ValueError("Put query values in --query; path queries and fragments are not allowed.")
    if any(segment == ".." for segment in parsed.path.split("/")):
        raise ValueError("Request path must not contain '..' segments.")
    return f"{base_url.rstrip('/')}/{parsed.path.lstrip('/')}"


def validate_headers(headers: Mapping[str, str]) -> dict[str, str]:
    validated: dict[str, str] = {}
    seen: set[str] = set()
    for raw_name, raw_value in headers.items():
        name = raw_name.strip()
        value = raw_value.strip()
        if not name or not HEADER_NAME_RE.fullmatch(name):
            raise ValueError(f"Invalid HTTP header name: {raw_name!r}")
        if "\r" in raw_value or "\n" in raw_value:
            raise ValueError(f"HTTP header '{name}' contains a newline.")
        folded = name.casefold()
        if folded in seen:
            raise ValueError(f"Duplicate HTTP header: {name}")
        seen.add(folded)
        validated[name] = value
    return validated


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        key: "***" if is_sensitive_name(key) else value
        for key, value in headers.items()
    }


def redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "***" if is_sensitive_name(str(key)) else redact_json(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    return value


def is_sensitive_name(name: str) -> bool:
    normalized = re.sub(r"[_\s]+", "-", name.casefold())
    return any(part in normalized for part in SENSITIVE_NAME_PARTS)


class AnvilogicClient:
    def __init__(
        self,
        *,
        verify_tls: bool = True,
        timeout: float = 30.0,
        retries: int = 2,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if timeout <= 0:
            raise ValueError("Timeout must be positive.")
        if retries < 0 or retries > 5:
            raise ValueError("Retries must be between 0 and 5.")
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.retries = retries
        self._client = client
        self._owns_client = client is None
        self._sleep = sleep

    def __enter__(self) -> AnvilogicClient:
        self._get_client()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._client is not None and self._owns_client:
            self._client.close()

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                verify=self.verify_tls,
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=False,
            )
        return self._client

    def send(self, plan: RequestPlan) -> httpx.Response:
        attempts = self.retries + 1 if plan.method in SAFE_RETRY_METHODS else 1
        for attempt in range(attempts):
            try:
                response = self._get_client().request(
                    plan.method,
                    plan.url,
                    params=list(plan.query) or None,
                    headers=plan.headers,
                    json=plan.json_body,
                )
            except httpx.RequestError as exc:
                if attempt + 1 < attempts:
                    self._sleep(0.25 * (2**attempt))
                    continue
                raise TransportError(
                    f"Request failed before receiving a response ({exc.__class__.__name__})."
                ) from exc
            if response.status_code in RETRY_STATUSES and attempt + 1 < attempts:
                self._sleep(_retry_delay(response, attempt))
                continue
            return response
        raise AssertionError("request retry loop ended unexpectedly")  # pragma: no cover


def prepare_request(
    *,
    method: str,
    base_url: str,
    path: str,
    query: list[tuple[str, str]] | None,
    custom_headers: Mapping[str, str] | None,
    api_key: str | None,
    auth_scheme: str,
    json_body: Any = None,
) -> RequestPlan:
    normalized_method = method.strip().upper()
    if normalized_method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("Method must be GET, HEAD, OPTIONS, POST, PUT, PATCH, or DELETE.")
    headers = {
        "Accept": "application/json",
        "User-Agent": f"anvilogic-cli/{__version__}",
        **auth_headers(api_key, auth_scheme),
    }
    supplied = validate_headers(custom_headers or {})
    reserved = {name.casefold() for name in headers}
    collisions = [name for name in supplied if name.casefold() in reserved]
    if collisions:
        raise ValueError(
            "Custom headers conflict with managed headers: " + ", ".join(sorted(collisions))
        )
    headers.update(supplied)
    return RequestPlan(
        method=normalized_method,
        url=build_url(base_url, path),
        query=tuple(query or ()),
        headers=headers,
        json_body=json_body,
    )


def redacted_plan(plan: RequestPlan) -> dict[str, Any]:
    return {
        "method": plan.method,
        "url": plan.url,
        "query": [
            {"name": key, "value": "***" if is_sensitive_name(key) else value}
            for key, value in plan.query
        ],
        "headers": redact_headers(plan.headers),
        "body": redact_json(plan.json_body),
        "sent": False,
    }


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            value = float(retry_after)
        except ValueError:
            pass
        else:
            return max(0.0, min(value, 8.0))
    return float(0.25 * (2**attempt))
