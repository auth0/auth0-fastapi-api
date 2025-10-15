"""
Tests for DPoP authentication functionality in FastAPI middleware.
Focuses on DPoP-specific authentication flows and error cases.
"""
import pytest
from fastapi import FastAPI, Depends
from pytest_httpx import HTTPXMock
from fastapi.testclient import TestClient

from fastapi_plugin.fast_api_client import Auth0FastAPI
from fastapi_plugin.test_utils import (
    generate_dpop_proof,
    generate_dpop_bound_token
)
from conftest import setup_mocks


@pytest.mark.asyncio
async def test_dpop_authentication_success(httpx_mock: HTTPXMock):
    """Test successful DPoP authentication with valid token and proof."""
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
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
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
async def test_dpop_authentication_missing_dpop_header(httpx_mock: HTTPXMock):
    """Test DPoP request fails when DPoP header is missing."""
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"
    
    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"DPoP {access_token}"}  # Missing DPoP header
    )
    
    assert response.status_code == 400
    json_body = response.json()
    assert "invalid_request" in json_body["detail"]["error"]


@pytest.mark.asyncio
async def test_dpop_authentication_invalid_dpop_proof(httpx_mock: HTTPXMock):
    """Test DPoP request fails with malformed DPoP proof."""
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"
    
    client = TestClient(app)
    response = client.get(
        "/test",
        headers={
            "Authorization": f"DPoP {access_token}",
            "DPoP": "invalid.jwt.proof"
        }
    )
    
    assert response.status_code == 400
    json_body = response.json()
    assert "invalid_dpop_proof" in json_body["detail"]["error"]


@pytest.mark.asyncio
async def test_dpop_authentication_url_mismatch(httpx_mock: HTTPXMock):
    """Test DPoP proof fails when htu doesn't match request URL."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    # Generate proof for WRONG URL
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="http://testserver/wrong-url",  # Wrong URL
        access_token=access_token
    )
    
    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
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
    assert "invalid_dpop_proof" in json_body["detail"]["error"]


@pytest.mark.asyncio
async def test_dpop_authentication_method_mismatch(httpx_mock: HTTPXMock):
    """Test DPoP proof fails when htm doesn't match request method."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    # Generate proof for POST but send GET
    dpop_proof = await generate_dpop_proof(
        http_method="POST",  # Wrong method
        http_url="http://testserver/test",
        access_token=access_token
    )
    
    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
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
    assert "invalid_dpop_proof" in json_body["detail"]["error"]


@pytest.mark.asyncio
async def test_dpop_with_scope_validation(httpx_mock: HTTPXMock):
    """Test that scope validation works with DPoP tokens."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/",
        claims={"scope": "read:data write:data"}
    )
    
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="http://testserver/test",
        access_token=access_token
    )
    
    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth(scopes=["read:data"]))):
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
async def test_dpop_with_invalid_scope(httpx_mock: HTTPXMock):
    """Test that scope validation fails with insufficient scopes."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/",
        claims={"scope": "read:data"}
    )
    
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="http://testserver/test",
        access_token=access_token
    )
    
    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth(scopes=["write:data"]))):
        return "OK"
    
    client = TestClient(app)
    response = client.get(
        "/test",
        headers={
            "Authorization": f"DPoP {access_token}",
            "DPoP": dpop_proof
        }
    )
    
    assert response.status_code == 403
    json_body = response.json()
    assert json_body["detail"]["error"] == "insufficient_scope"
