"""
Tests for Bearer token authentication and JWT validation.
Tests core JWT validation logic including issuer, expiration, and scope checks.
"""
import pytest
from fastapi import FastAPI, Depends
from pytest_httpx import HTTPXMock
from fastapi.testclient import TestClient

from fastapi_plugin.fast_api_client import Auth0FastAPI
from test_utils import generate_token
from conftest import setup_mocks


# =============================================================================
# Missing Token Tests
# =============================================================================

@pytest.mark.asyncio
async def test_missing_authorization_header():
    """Test that requests without Authorization header return 400."""
    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get("/test")
    
    assert response.status_code == 400
    json_body = response.json()
    assert json_body["detail"]["error"] == "invalid_request"


# =============================================================================
# Valid Token Tests
# =============================================================================

@pytest.mark.asyncio
async def test_valid_bearer_token_authentication(httpx_mock: HTTPXMock):
    """Test successful authentication with a valid Bearer token."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/",
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200


# =============================================================================
# Issuer Validation Tests
# =============================================================================

@pytest.mark.asyncio
async def test_missing_issuer_claim(httpx_mock: HTTPXMock):
    """Test that tokens without 'iss' claim are rejected with 401."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer=False,  # Omit issuer claim
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_invalid_issuer_claim(httpx_mock: HTTPXMock):
    """Test that tokens with mismatched issuer are rejected with 401."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://invalid-issuer.local",  # Wrong issuer
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    
    assert response.status_code == 401


# =============================================================================
# Expiration Validation Tests
# =============================================================================

@pytest.mark.asyncio
async def test_missing_expiration_claim(httpx_mock: HTTPXMock):
    """Test that tokens without 'exp' claim are rejected with 401."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/",
        iat=True,
        exp=False  # Omit expiration claim
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    
    assert response.status_code == 401


# =============================================================================
# Scope Validation Tests
# =============================================================================

@pytest.mark.asyncio
async def test_insufficient_scope(httpx_mock: HTTPXMock):
    """Test that tokens with insufficient scopes are rejected with 403."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/",
        iat=True,
        exp=True,
        claims={"scope": "invalid"}  # Wrong scope
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth(scopes="valid"))):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    
    assert response.status_code == 403
    json_body = response.json()
    assert json_body["detail"]["error"] == "insufficient_scope"
