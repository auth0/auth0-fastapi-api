"""
Tests for the On-Behalf-Of (OBO) surface this plugin owns: the require_auth() ->
pull the verified token -> exchange flow through a real FastAPI route, and the
re-exports the plugin adds on top of auth0-api-python.

The exchange, the form well-formedness, the Basic auth encoding, and the act-claim
parsing are exercised in auth0-api-python's own suite (test_api_client.py, test_act.py),
so they are not repeated here.
"""
import base64
import urllib.parse

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from pytest_httpx import HTTPXMock

from fastapi_plugin import (
    ApiError,
    Auth0FastAPI,
    BaseAuthError,
    GetTokenByExchangeProfileError,
    MissingRequiredArgumentError,
    OnBehalfOfTokenResult,
    VerifyAccessTokenError,
    get_current_actor,
    get_delegation_chain,
)

from .test_utils import generate_token

TOKEN_ENDPOINT = "https://auth0.local/oauth/token"


def _setup_obo_mocks(httpx_mock: HTTPXMock):
    """OIDC discovery (with a token_endpoint), JWKS, and the token-exchange response."""
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "issuer": "https://auth0.local/",
            "jwks_uri": "https://auth0.local/.well-known/jwks.json",
            "token_endpoint": TOKEN_ENDPOINT,
        },
    )
    from .conftest import PUBLIC_DPOP_JWK, RSA_PUBLIC_KEY
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={"keys": [RSA_PUBLIC_KEY, PUBLIC_DPOP_JWK]},
    )
    httpx_mock.add_response(
        method="POST",
        url=TOKEN_ENDPOINT,
        json={
            "access_token": "obo-access-token",
            "expires_in": 3600,
            "scope": "calendar:read",
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        },
    )


# =============================================================================
# The owned flow: require_auth() -> pull verified token -> exchange, via a route
# =============================================================================

@pytest.mark.asyncio
async def test_documented_route_verifies_then_exchanges(httpx_mock: HTTPXMock):
    """A protected route pulls the verified token and exchanges it on behalf of the user."""
    _setup_obo_mocks(httpx_mock)

    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="my-audience",
        issuer="https://auth0.local/",
        iat=True,
        exp=True,
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="my-audience",
        client_id="cid",
        client_secret="csecret",
    )

    @app.post("/schedule-meeting")
    async def schedule_meeting(request: Request, claims=Depends(auth0.require_auth())):
        incoming = request.headers["authorization"].split(" ", 1)[1]
        obo = await auth0.api_client.get_token_on_behalf_of(
            access_token=incoming,
            audience="https://calendar-api.example.com",
            scope="calendar:read",
        )
        return {"user": claims["sub"], "downstream_token": obo["access_token"]}

    client = TestClient(app)
    response = client.post(
        "/schedule-meeting",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    assert response.json() == {"user": "user_123", "downstream_token": "obo-access-token"}

    exchange_req = httpx_mock.get_requests(method="POST", url=TOKEN_ENDPOINT)[-1]
    form = urllib.parse.parse_qs(exchange_req.content.decode())
    assert form["subject_token"] == [access_token]
    assert form["audience"] == ["https://calendar-api.example.com"]
    assert "client_secret" not in form
    auth_header = exchange_req.headers.get("authorization")
    assert auth_header.startswith("Basic ")
    assert base64.b64decode(auth_header.split(" ")[1]).decode() == "cid:csecret"


# =============================================================================
# Re-exports the plugin adds on top of auth0-api-python
# =============================================================================

def test_obo_surface_reexported():
    """The OBO method's helpers, result type, and error types are re-exported from the plugin."""
    import auth0_api_python as dep
    import auth0_api_python.errors as errors

    assert get_current_actor is dep.get_current_actor
    assert get_delegation_chain is dep.get_delegation_chain
    assert OnBehalfOfTokenResult is dep.OnBehalfOfTokenResult
    assert GetTokenByExchangeProfileError is dep.GetTokenByExchangeProfileError
    assert ApiError is dep.ApiError
    # These three are only under auth0_api_python.errors upstream, not at its top level.
    assert MissingRequiredArgumentError is errors.MissingRequiredArgumentError
    assert VerifyAccessTokenError is errors.VerifyAccessTokenError
    assert BaseAuthError is errors.BaseAuthError
    for err in (GetTokenByExchangeProfileError, ApiError, MissingRequiredArgumentError, VerifyAccessTokenError):
        assert issubclass(err, BaseAuthError)
