"""
Tests for DPoP operational modes (enabled/required/disabled).
Tests the runtime behavior of different DPoP configuration modes.
"""
import pytest
from fastapi import FastAPI, Depends
from pytest_httpx import HTTPXMock
from fastapi.testclient import TestClient

from fastapi_plugin.fast_api_client import Auth0FastAPI
from .test_utils import (
    generate_token,
    generate_dpop_proof,
    generate_dpop_bound_token,
)
from .conftest import setup_mocks


# =============================================================================
# DPoP Required Mode Tests
# =============================================================================

@pytest.mark.asyncio
async def test_dpop_required_mode_rejects_bearer():
    """Test that Bearer tokens are rejected when dpop_required=True."""
    # No need to mock JWKS - request should fail before token validation
    bearer_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    app = FastAPI()
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="<audience>",
        dpop_required=True  # DPoP required mode
    )
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"
    
    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {bearer_token}"}
    )
    
    assert response.status_code == 400
    json_body = response.json()
    assert json_body["detail"]["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_dpop_required_mode_accepts_dpop(httpx_mock: HTTPXMock):
    """Test that DPoP tokens are accepted when dpop_required=True."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="http://testserver/test",
        access_token=access_token
    )
    
    app = FastAPI()
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="<audience>",
        dpop_required=True
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return {"user": claims["sub"]}
    
    client = TestClient(app)
    response = client.get(
        "/test",
        headers={
            "Authorization": f"DPoP {access_token}",
            "DPoP": dpop_proof
        }
    )
    
    assert response.status_code == 200
    assert response.json()["user"] == "user_123"


# =============================================================================
# DPoP Disabled Mode Tests
# =============================================================================

@pytest.mark.asyncio
async def test_dpop_disabled_mode_rejects_dpop():
    """Test that DPoP tokens are rejected when dpop_enabled=False."""
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="http://testserver/test",
        access_token=access_token
    )
    
    app = FastAPI()
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="<audience>",
        dpop_enabled=False  # DPoP disabled
    )
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"
    
    client = TestClient(app)
    response = client.get(
        "/test",
        headers={
            "Authorization": f"DPoP {access_token}",
            "DPoP": dpop_proof
        }
    )
    
    assert response.status_code == 400
    json_body = response.json()
    assert json_body["detail"]["error"] == "invalid_request"


# =============================================================================
# Bearer-Only Mode Tests (DPoP disabled)
# =============================================================================

@pytest.mark.asyncio
async def test_bearer_only_mode_accepts_bearer(httpx_mock: HTTPXMock):
    """Test that Bearer tokens work when DPoP is disabled."""
    setup_mocks(httpx_mock)
    
    bearer_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    app = FastAPI()
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="<audience>",
        dpop_enabled=False  # Bearer only mode
    )
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return {"user": claims["sub"]}
    
    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {bearer_token}"}
    )
    
    assert response.status_code == 200
    assert response.json()["user"] == "user_123"


# =============================================================================
# Token/Scheme Mismatch Tests
# =============================================================================

@pytest.mark.asyncio
async def test_dpop_bound_token_with_bearer_scheme_fails(httpx_mock: HTTPXMock):
    """Test that DPoP-bound tokens fail when using Bearer scheme."""
    setup_mocks(httpx_mock)
    
    # Generate a DPoP-bound token (has cnf claim)
    dpop_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    app = FastAPI()
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="<audience>",
        dpop_enabled=True
    )
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"
    
    client = TestClient(app)
    # Try to use DPoP-bound token with Bearer scheme (should fail)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {dpop_token}"}
    )
    
    assert response.status_code == 401
    json_body = response.json()
    assert json_body["detail"]["error"] == "invalid_token"
    assert "dpop" in json_body["detail"]["error_description"].lower()
