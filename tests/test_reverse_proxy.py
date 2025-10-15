"""
Tests for reverse proxy support in FastAPI middleware.
Tests the get_canonical_url functionality and X-Forwarded-* header handling.
"""
import pytest
from fastapi import FastAPI, Depends, Request
from pytest_httpx import HTTPXMock
from fastapi.testclient import TestClient

from fastapi_plugin.fast_api_client import Auth0FastAPI
from fastapi_plugin.utils import get_canonical_url
from fastapi_plugin.test_utils import (
    generate_dpop_proof,
    generate_dpop_bound_token
)
from conftest import setup_mocks


@pytest.mark.asyncio
async def test_reverse_proxy_with_trust_enabled(httpx_mock: HTTPXMock):
    """Test that X-Forwarded headers are used when trust_proxy=True."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    # Generate DPoP proof for the PUBLIC URL
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="https://api.example.com/test",  # Public URL
        access_token=access_token
    )
    
    app = FastAPI()
    app.state.trust_proxy = True  # Enable proxy trust
    
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return {"user": claims["sub"]}
    
    client = TestClient(app)
    
    # Request comes to internal URL but with X-Forwarded headers
    response = client.get(
        "/test",
        headers={
            "Authorization": f"DPoP {access_token}",
            "DPoP": dpop_proof,
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "api.example.com"
        }
    )
    
    assert response.status_code == 200
    assert response.json()["user"] == "user_123"


@pytest.mark.asyncio
async def test_reverse_proxy_without_trust_fails(httpx_mock: HTTPXMock):
    """Test that X-Forwarded headers are IGNORED when trust_proxy=False."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    # Generate DPoP proof for the PUBLIC URL
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="https://api.example.com/test",
        access_token=access_token
    )
    
    app = FastAPI()
    # trust_proxy defaults to False
    
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"
    
    client = TestClient(app)
    
    # Headers are present but should be ignored
    response = client.get(
        "/test",
        headers={
            "Authorization": f"DPoP {access_token}",
            "DPoP": dpop_proof,
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "api.example.com"
        }
    )
    
    # Should fail because proof expects https://api.example.com
    # but app sees http://testserver (headers ignored)
    assert response.status_code == 400
    json_body = response.json()
    assert "invalid_dpop_proof" in json_body["detail"]["error"]


@pytest.mark.asyncio
async def test_reverse_proxy_with_path_prefix(httpx_mock: HTTPXMock):
    """Test X-Forwarded-Prefix handling."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    # Generate DPoP proof with prefix
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="https://api.example.com/api/v1/test",
        access_token=access_token
    )
    
    app = FastAPI()
    app.state.trust_proxy = True
    
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return {"user": claims["sub"]}
    
    client = TestClient(app)
    
    response = client.get(
        "/test",
        headers={
            "Authorization": f"DPoP {access_token}",
            "DPoP": dpop_proof,
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "api.example.com",
            "X-Forwarded-Prefix": "/api/v1"
        }
    )
    
    assert response.status_code == 200
    assert response.json()["user"] == "user_123"


@pytest.mark.asyncio
async def test_reverse_proxy_with_trailing_slash_prefix(httpx_mock: HTTPXMock):
    """Test X-Forwarded-Prefix with trailing slash is handled correctly."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    # Generate DPoP proof WITHOUT trailing slash
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="https://api.example.com/api/v1/test",
        access_token=access_token
    )
    
    app = FastAPI()
    app.state.trust_proxy = True
    
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return {"user": claims["sub"]}
    
    client = TestClient(app)
    
    response = client.get(
        "/test",
        headers={
            "Authorization": f"DPoP {access_token}",
            "DPoP": dpop_proof,
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "api.example.com",
            "X-Forwarded-Prefix": "/api/v1/"  # With trailing slash
        }
    )
    
    # Should still work - trailing slash should be stripped
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_reverse_proxy_multiple_hosts(httpx_mock: HTTPXMock):
    """Test that first host is used from comma-separated X-Forwarded-Host."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="https://client.example.com/test",
        access_token=access_token
    )
    
    app = FastAPI()
    app.state.trust_proxy = True
    
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return {"user": claims["sub"]}
    
    client = TestClient(app)
    
    response = client.get(
        "/test",
        headers={
            "Authorization": f"DPoP {access_token}",
            "DPoP": dpop_proof,
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "client.example.com, proxy1.internal, proxy2.internal"
        }
    )
    
    assert response.status_code == 200
    assert response.json()["user"] == "user_123"


@pytest.mark.asyncio
async def test_reverse_proxy_with_query_params(httpx_mock: HTTPXMock):
    """Test that query parameters are preserved in canonical URL."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="https://api.example.com/test?page=1&limit=10",
        access_token=access_token
    )
    
    app = FastAPI()
    app.state.trust_proxy = True
    
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return {"user": claims["sub"]}
    
    client = TestClient(app)
    
    response = client.get(
        "/test?page=1&limit=10",
        headers={
            "Authorization": f"DPoP {access_token}",
            "DPoP": dpop_proof,
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "api.example.com"
        }
    )
    
    assert response.status_code == 200
    assert response.json()["user"] == "user_123"


@pytest.mark.asyncio
async def test_reverse_proxy_partial_headers(httpx_mock: HTTPXMock):
    """Test with only X-Forwarded-Proto (partial headers)."""
    setup_mocks(httpx_mock)
    
    access_token = await generate_dpop_bound_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer="https://auth0.local/"
    )
    
    # Proof expects https but with testserver host
    dpop_proof = await generate_dpop_proof(
        http_method="GET",
        http_url="https://testserver/test",
        access_token=access_token
    )
    
    app = FastAPI()
    app.state.trust_proxy = True
    
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>", dpop_enabled=True)
    
    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return {"user": claims["sub"]}
    
    client = TestClient(app)
    
    response = client.get(
        "/test",
        headers={
            "Authorization": f"DPoP {access_token}",
            "DPoP": dpop_proof,
            "X-Forwarded-Proto": "https"  # Only proto, no host
        }
    )
    
    assert response.status_code == 200


def test_get_canonical_url_without_proxy():
    """Test get_canonical_url returns direct URL when trust_proxy=False."""
    app = FastAPI()
    # trust_proxy defaults to False
    
    @app.get("/test")
    async def test_route(request: Request):
        canonical_url = get_canonical_url(request)
        return {"url": canonical_url}
    
    client = TestClient(app)
    response = client.get(
        "/test",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "evil.com"  # Should be ignored
        }
    )
    
    assert response.status_code == 200
    url = response.json()["url"]
    # Should use testserver, not evil.com
    assert "testserver" in url
    assert "evil.com" not in url


def test_get_canonical_url_with_proxy():
    """Test get_canonical_url uses X-Forwarded headers when trust_proxy=True."""
    app = FastAPI()
    app.state.trust_proxy = True
    
    @app.get("/test")
    async def test_route(request: Request):
        canonical_url = get_canonical_url(request)
        return {"url": canonical_url}
    
    client = TestClient(app)
    response = client.get(
        "/test",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "api.example.com"
        }
    )
    
    assert response.status_code == 200
    url = response.json()["url"]
    assert "https://api.example.com/test" == url


def test_get_canonical_url_security_without_trust():
    """Test that malicious X-Forwarded headers are ignored without trust."""
    app = FastAPI()
    # trust_proxy = False (default)
    
    @app.get("/test")
    async def test_route(request: Request):
        canonical_url = get_canonical_url(request)
        return {"url": canonical_url}
    
    client = TestClient(app)
    response = client.get(
        "/test",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "attacker.com"
        }
    )
    
    assert response.status_code == 200
    url = response.json()["url"]
    # Malicious headers should be ignored
    assert "attacker.com" not in url
    assert "testserver" in url
