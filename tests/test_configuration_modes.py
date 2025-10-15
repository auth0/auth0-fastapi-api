"""
Tests for DPoP configuration modes (enabled/required/disabled).
Tests the different operational modes of the Auth0FastAPI middleware.
"""
import pytest
from fastapi import FastAPI, Depends
from pytest_httpx import HTTPXMock
from fastapi.testclient import TestClient

from fastapi_plugin.fast_api_client import Auth0FastAPI
from fastapi_plugin.test_utils import (
    generate_token,
    generate_dpop_proof,
    generate_dpop_bound_token,
    PUBLIC_DPOP_JWK
)


def setup_mocks(httpx_mock: HTTPXMock):
    """Setup common OIDC and JWKS mocks."""
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "issuer": "https://auth0.local/",
            "jwks_uri": "https://auth0.local/.well-known/jwks.json"
        }
    )
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "TEST_KEY",
                    "n": "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw",
                    "e": "AQAB",
                    "alg": "RS256",
                    "use": "sig"
                },
                PUBLIC_DPOP_JWK
            ]
        }
    )


def test_dpop_configuration_defaults():
    """Test that DPoP configuration has correct defaults."""
    auth0 = Auth0FastAPI(domain="auth0.local", audience="test")
    assert auth0.api_client.options.dpop_enabled == True
    assert auth0.api_client.options.dpop_required == False
    assert auth0.api_client.options.dpop_iat_leeway == 30
    assert auth0.api_client.options.dpop_iat_offset == 300


def test_dpop_disabled_configuration():
    """Test DPoP can be explicitly disabled."""
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="test",
        dpop_enabled=False
    )
    assert auth0.api_client.options.dpop_enabled == False


def test_dpop_custom_timing_configuration():
    """Test custom DPoP timing parameters."""
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="test",
        dpop_iat_leeway=60,
        dpop_iat_offset=600
    )
    assert auth0.api_client.options.dpop_iat_leeway == 60
    assert auth0.api_client.options.dpop_iat_offset == 600


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


@pytest.mark.asyncio
async def test_mixed_mode_accepts_bearer(httpx_mock: HTTPXMock):
    """Test that Bearer tokens are accepted in mixed mode (default)."""
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
        dpop_enabled=True,
        dpop_required=False  # Mixed mode
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


@pytest.mark.asyncio
async def test_mixed_mode_accepts_dpop(httpx_mock: HTTPXMock):
    """Test that DPoP tokens are accepted in mixed mode (default)."""
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
        dpop_enabled=True,
        dpop_required=False  # Mixed mode
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
    assert "dpop" in json_body["detail"]["error_description"].lower()
