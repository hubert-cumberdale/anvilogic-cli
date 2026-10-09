from __future__ import annotations

import httpx
import pytest

from anvilogic_cli.client import (
    AnvilogicClient,
    RequestPlan,
    auth_headers,
    build_url,
    prepare_request,
    redact_headers,
    redact_json,
)
from anvilogic_cli.errors import ConfigError, TransportError


def test_auth_header_schemes() -> None:
    assert auth_headers("secret", "bearer") == {"Authorization": "Bearer secret"}
    assert auth_headers("secret", "x-api-key") == {"X-API-Key": "secret"}
    assert auth_headers("secret", "token") == {"Authorization": "Token secret"}
    assert auth_headers(None, "none") == {}
    with pytest.raises(ConfigError):
        auth_headers(None, "bearer")


def test_url_building_preserves_base_path_and_rejects_absolute_urls() -> None:
    assert build_url("https://example.com/api", "/v1/items") == "https://example.com/api/v1/items"
    with pytest.raises(ValueError, match="relative"):
        build_url("https://example.com", "https://evil.example/path")
    with pytest.raises(ValueError, match="query"):
        build_url("https://example.com", "/items?token=secret")


def test_prepare_request_rejects_managed_header_collision() -> None:
    with pytest.raises(ValueError, match="managed"):
        prepare_request(
            method="GET",
            base_url="https://example.com",
            path="/v1/items",
            query=[],
            custom_headers={"authorization": "something"},
            api_key="secret",
            auth_scheme="bearer",
        )


def test_redaction_is_recursive_and_case_insensitive() -> None:
    assert redact_headers({"Authorization": "Bearer secret", "Accept": "json"}) == {
        "Authorization": "***",
        "Accept": "json",
    }
    assert redact_json({"credentials": {"apiKey": "secret"}, "name": "visible"}) == {
        "credentials": "***",
        "name": "visible",
    }


def test_safe_request_retries_retryable_status() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        status = 503 if calls == 1 else 200
        return httpx.Response(status, json={"ok": True}, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = AnvilogicClient(client=http_client, retries=2, sleep=lambda _delay: None)
    plan = RequestPlan("GET", "https://example.com/items", (), {})

    assert client.send(plan).status_code == 200
    assert calls == 2


def test_mutating_request_is_never_retried() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = AnvilogicClient(client=http_client, retries=2, sleep=lambda _delay: None)

    assert client.send(RequestPlan("POST", "https://example.com/items", (), {})).status_code == 503
    assert calls == 1


def test_transport_error_does_not_echo_exception_details() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret host details", request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = AnvilogicClient(client=http_client, retries=0)

    with pytest.raises(TransportError, match="ConnectError") as caught:
        client.send(RequestPlan("GET", "https://example.com/items", (), {}))
    assert "secret host details" not in str(caught.value)
