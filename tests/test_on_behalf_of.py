"""
Tests for On-Behalf-Of (OBO) token exchange and the act-claim helpers exposed
through the FastAPI plugin.

The exchange itself is performed by the underlying auth0-api-python ApiClient,
reached via auth0.api_client. These tests confirm the wrapper surfaces it and
re-exports the act helpers and result type.
"""
import base64
import urllib.parse

import pytest
from pytest_httpx import HTTPXMock

from fastapi_plugin import (
    ApiError,
    Auth0FastAPI,
    GetTokenByExchangeProfileError,
    OnBehalfOfTokenResult,
    get_current_actor,
    get_delegation_chain,
)

DISCOVERY_URL = "https://auth0.local/.well-known/openid-configuration"
TOKEN_ENDPOINT = "https://auth0.local/oauth/token"


def _mock_discovery(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="GET",
        url=DISCOVERY_URL,
        json={"token_endpoint": TOKEN_ENDPOINT},
    )


def _last_form(httpx_mock: HTTPXMock) -> dict[str, list[str]]:
    req = httpx_mock.get_requests()[-1]
    return urllib.parse.parse_qs(req.content.decode())


def _confidential_client() -> Auth0FastAPI:
    return Auth0FastAPI(
        domain="auth0.local",
        audience="my-audience",
        client_id="cid",
        client_secret="csecret",
    )


# =============================================================================
# Exchange - configuration guards
# =============================================================================

@pytest.mark.asyncio
async def test_obo_requires_client_credentials():
    """OBO requires a confidential client configured on the plugin."""
    auth0 = Auth0FastAPI(domain="auth0.local", audience="my-audience")

    with pytest.raises(GetTokenByExchangeProfileError) as err:
        await auth0.api_client.get_token_on_behalf_of(
            access_token="incoming-access-token",
            audience="https://api.backend.com",
        )

    assert "client credentials are required" in str(err.value).lower()


@pytest.mark.asyncio
async def test_obo_requires_client_secret():
    """OBO requires client_secret when only client_id is configured."""
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="my-audience",
        client_id="cid",
    )

    with pytest.raises(GetTokenByExchangeProfileError) as err:
        await auth0.api_client.get_token_on_behalf_of(
            access_token="incoming-access-token",
            audience="https://api.backend.com",
        )

    assert "client credentials are required" in str(err.value).lower()


@pytest.mark.asyncio
async def test_obo_requires_audience():
    """OBO requires an explicit downstream audience."""
    from auth0_api_python.errors import MissingRequiredArgumentError

    auth0 = _confidential_client()

    with pytest.raises(MissingRequiredArgumentError):
        await auth0.api_client.get_token_on_behalf_of(
            access_token="incoming-access-token",
            audience="",
        )


# =============================================================================
# Exchange - success path and request well-formedness
# =============================================================================

@pytest.mark.asyncio
async def test_obo_success_sends_fixed_token_types(httpx_mock: HTTPXMock):
    """Successful OBO exchange sends the fixed RFC 8693 access-token types."""
    _mock_discovery(httpx_mock)
    httpx_mock.add_response(
        method="POST",
        url=TOKEN_ENDPOINT,
        json={
            "access_token": "obo-access-token",
            "expires_in": 3600,
            "scope": "read:data write:data",
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        },
    )

    auth0 = _confidential_client()
    result = await auth0.api_client.get_token_on_behalf_of(
        access_token="incoming-access-token",
        audience="https://api.backend.com",
        scope="read:data write:data",
    )

    assert result["access_token"] == "obo-access-token"
    assert result["expires_in"] == 3600
    assert isinstance(result["expires_at"], int)
    assert result["scope"] == "read:data write:data"
    assert result["token_type"] == "Bearer"
    assert result["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"

    form = _last_form(httpx_mock)
    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
    assert form["subject_token"] == ["incoming-access-token"]
    assert form["subject_token_type"] == ["urn:ietf:params:oauth:token-type:access_token"]
    assert form["requested_token_type"] == ["urn:ietf:params:oauth:token-type:access_token"]
    assert form["audience"] == ["https://api.backend.com"]
    assert form["scope"] == ["read:data write:data"]
    # Client credentials go via HTTP Basic auth, not the form body.
    assert "client_id" not in form
    assert "client_secret" not in form

    auth_header = httpx_mock.get_requests()[-1].headers.get("authorization")
    assert auth_header is not None and auth_header.startswith("Basic ")
    decoded = base64.b64decode(auth_header.split(" ")[1]).decode()
    assert decoded == "cid:csecret"


@pytest.mark.asyncio
async def test_obo_omits_scope_when_not_provided(httpx_mock: HTTPXMock):
    """OBO omits the scope field when no scope is requested."""
    _mock_discovery(httpx_mock)
    httpx_mock.add_response(
        method="POST",
        url=TOKEN_ENDPOINT,
        json={
            "access_token": "obo-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        },
    )

    auth0 = _confidential_client()
    result = await auth0.api_client.get_token_on_behalf_of(
        access_token="incoming-access-token",
        audience="https://api.backend.com",
    )

    assert result["access_token"] == "obo-access-token"
    assert "scope" not in _last_form(httpx_mock)


@pytest.mark.asyncio
async def test_obo_does_not_expose_id_or_refresh_token(httpx_mock: HTTPXMock):
    """OBO result only exposes access-token-oriented fields."""
    _mock_discovery(httpx_mock)
    httpx_mock.add_response(
        method="POST",
        url=TOKEN_ENDPOINT,
        json={
            "access_token": "obo-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "id_token": "id-token",
            "refresh_token": "refresh-token",
        },
    )

    auth0 = _confidential_client()
    result = await auth0.api_client.get_token_on_behalf_of(
        access_token="incoming-access-token",
        audience="https://api.backend.com",
    )

    assert result["access_token"] == "obo-access-token"
    assert "id_token" not in result
    assert "refresh_token" not in result


@pytest.mark.asyncio
async def test_obo_propagates_exchange_error(httpx_mock: HTTPXMock):
    """OBO surfaces the underlying exchange error when Auth0 rejects it."""
    _mock_discovery(httpx_mock)
    httpx_mock.add_response(
        method="POST",
        url=TOKEN_ENDPOINT,
        status_code=400,
        json={
            "error": "invalid_target",
            "error_description": "The target API is not allowed",
        },
    )

    auth0 = _confidential_client()
    with pytest.raises(ApiError) as err:
        await auth0.api_client.get_token_on_behalf_of(
            access_token="incoming-access-token",
            audience="https://api.backend.com",
        )

    assert err.value.get_status_code() == 400


# =============================================================================
# Re-exports
# =============================================================================

def test_act_helpers_and_types_reexported():
    """The act helpers, OBO result type, and error types are re-exported from fastapi_plugin."""
    import auth0_api_python as dep

    assert get_current_actor is dep.get_current_actor
    assert get_delegation_chain is dep.get_delegation_chain
    assert OnBehalfOfTokenResult is dep.OnBehalfOfTokenResult
    assert GetTokenByExchangeProfileError is dep.GetTokenByExchangeProfileError
    assert ApiError is dep.ApiError


# =============================================================================
# act-claim helpers
# =============================================================================

def test_get_current_actor_and_chain_none_when_act_missing():
    """No act claim means no current actor and an empty delegation chain."""
    claims = {"sub": "auth0|user123"}

    assert get_current_actor(claims) is None
    assert get_delegation_chain(claims) == []


def test_get_current_actor_and_chain_from_nested_act():
    """Current actor is the outermost act.sub; chain runs newest to oldest."""
    claims = {
        "sub": "auth0|user123",
        "act": {
            "sub": "mcp_server_2_client_id",
            "act": {
                "sub": "mcp_server_1_client_id",
                "act": {"sub": "spa_client_id"},
            },
        },
    }

    assert get_current_actor(claims) == "mcp_server_2_client_id"
    assert get_delegation_chain(claims) == [
        "mcp_server_2_client_id",
        "mcp_server_1_client_id",
        "spa_client_id",
    ]


def test_act_helpers_reject_malformed_act_claim():
    """A present but malformed act claim raises VerifyAccessTokenError."""
    from auth0_api_python.errors import VerifyAccessTokenError

    with pytest.raises(VerifyAccessTokenError):
        get_current_actor({"sub": "auth0|user123", "act": "not-an-object"})

    with pytest.raises(VerifyAccessTokenError):
        get_delegation_chain(
            {"act": {"sub": "mcp_server_client_id", "act": "spa_client_id"}}
        )
