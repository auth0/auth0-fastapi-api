"""
Tests for Bearer token authentication and JWT validation.
Tests core JWT validation logic including issuer, expiration, and scope checks.
"""
import pytest
from fastapi import FastAPI, Depends
from pytest_httpx import HTTPXMock
from fastapi.testclient import TestClient

from fastapi_plugin.fast_api_client import Auth0FastAPI
from .test_utils import generate_token
from .conftest import setup_mocks, setup_mcd_mocks


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
@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
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
@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
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


# =============================================================================
# MCD Token Verification Tests
# =============================================================================

@pytest.mark.asyncio
async def test_mcd_valid_token_from_allowed_domain(httpx_mock: HTTPXMock):
    """Test that a valid token from a domain in the static list is accepted."""
    setup_mcd_mocks(httpx_mock, ["tenant1.auth0.com"])

    access_token = await generate_token(
        domain="tenant1.auth0.com",
        user_id="user_123",
        audience="<audience>",
        issuer="https://tenant1.auth0.com/",
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domains=["tenant1.auth0.com", "tenant2.auth0.com"],
        audience="<audience>"
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return {"user": claims["sub"]}

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200
    assert response.json()["user"] == "user_123"


@pytest.mark.asyncio
async def test_mcd_token_from_disallowed_domain_rejected():
    """Test that a token from a domain NOT in the allowed list is rejected with 401."""
    access_token = await generate_token(
        domain="attacker.auth0.com",
        user_id="user_123",
        audience="<audience>",
        issuer="https://attacker.auth0.com/",
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domains=["tenant1.auth0.com", "tenant2.auth0.com"],
        audience="<audience>"
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 401
    json_body = response.json()
    assert json_body["detail"]["error"] == "invalid_token"


@pytest.mark.asyncio
async def test_mcd_with_callable_resolver_success(httpx_mock: HTTPXMock):
    """Test MCD with a callable resolver that accepts the issuer."""
    setup_mcd_mocks(httpx_mock, ["dynamic.auth0.com"])

    def domain_resolver(context):
        return ["dynamic.auth0.com"]

    access_token = await generate_token(
        domain="dynamic.auth0.com",
        user_id="user_123",
        audience="<audience>",
        issuer="https://dynamic.auth0.com/",
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domains=domain_resolver,
        audience="<audience>"
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return {"user": claims["sub"]}

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200
    assert response.json()["user"] == "user_123"


@pytest.mark.asyncio
async def test_mcd_resolver_rejects_issuer():
    """Test that a resolver returning domains not matching the issuer results in 401."""
    def restrictive_resolver(context):
        return ["allowed.auth0.com"]

    access_token = await generate_token(
        domain="unknown.auth0.com",
        user_id="user_123",
        audience="<audience>",
        issuer="https://unknown.auth0.com/",
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domains=restrictive_resolver,
        audience="<audience>"
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 401
    json_body = response.json()
    assert json_body["detail"]["error"] == "invalid_token"


@pytest.mark.asyncio
async def test_mcd_resolver_throws_exception():
    """Test that a resolver that throws an exception results in 500."""
    def broken_resolver(context):
        raise ValueError("Database unavailable")

    access_token = await generate_token(
        domain="some.auth0.com",
        user_id="user_123",
        audience="<audience>",
        issuer="https://some.auth0.com/",
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domains=broken_resolver,
        audience="<audience>"
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 500
    json_body = response.json()
    assert json_body["detail"]["error"] == "domains_resolver_error"


@pytest.mark.asyncio
async def test_mcd_token_with_valid_scopes(httpx_mock: HTTPXMock):
    """Test MCD token verification passes with valid scopes."""
    setup_mcd_mocks(httpx_mock, ["tenant1.auth0.com"])

    access_token = await generate_token(
        domain="tenant1.auth0.com",
        user_id="user_123",
        audience="<audience>",
        issuer="https://tenant1.auth0.com/",
        iat=True,
        exp=True,
        claims={"scope": "read:data write:data"}
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domains=["tenant1.auth0.com"],
        audience="<audience>"
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth(scopes=["read:data"]))):
        return {"user": claims["sub"]}

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200
    assert response.json()["user"] == "user_123"


@pytest.mark.asyncio
async def test_mcd_token_with_insufficient_scopes(httpx_mock: HTTPXMock):
    """Test MCD token verification fails with insufficient scopes."""
    setup_mcd_mocks(httpx_mock, ["tenant1.auth0.com"])

    access_token = await generate_token(
        domain="tenant1.auth0.com",
        user_id="user_123",
        audience="<audience>",
        issuer="https://tenant1.auth0.com/",
        iat=True,
        exp=True,
        claims={"scope": "read:data"}
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domains=["tenant1.auth0.com"],
        audience="<audience>"
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth(scopes=["write:data"]))):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 403
    json_body = response.json()
    assert json_body["detail"]["error"] == "insufficient_scope"

@pytest.mark.asyncio
async def test_mcd_resolver_receives_request_context(httpx_mock: HTTPXMock):
    """Test that the domains resolver receives request_url and request_headers from the incoming request."""
    setup_mcd_mocks(httpx_mock, ["secondary.auth0.com"])

    resolved_context = {}

    def capturing_resolver(context):
        resolved_context.update(context)
        return ["secondary.auth0.com"]

    access_token = await generate_token(
        domain="secondary.auth0.com",
        user_id="user_123",
        audience="<audience>",
        issuer="https://secondary.auth0.com/",
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domains=capturing_resolver,
        audience="<audience>"
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-Custom-Header": "test-value"
        }
    )

    assert response.status_code == 200
    assert "unverified_iss" in resolved_context
    assert resolved_context["unverified_iss"] == "https://secondary.auth0.com/"
    assert "request_headers" in resolved_context
    assert resolved_context["request_headers"]["x-custom-header"] == "test-value"


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
async def test_mcd_token_missing_iss_with_domains_enabled():
    """Test that a token without 'iss' claim is rejected with 401 when using domains configuration."""
    access_token = await generate_token(
        domain="tenant1.auth0.com",
        user_id="user_123",
        audience="<audience>",
        issuer=False,  # Omit issuer claim
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domains=["tenant1.auth0.com"],
        audience="<audience>"
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 401
    json_body = response.json()
    assert json_body["detail"]["error"] == "invalid_token"


@pytest.mark.asyncio
async def test_mcd_resolver_returns_empty_list_at_runtime():
    """Test that a resolver returning an empty list at runtime results in an error."""
    def empty_resolver(context):
        return []

    access_token = await generate_token(
        domain="some.auth0.com",
        user_id="user_123",
        audience="<audience>",
        issuer="https://some.auth0.com/",
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domains=empty_resolver,
        audience="<audience>"
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    # Empty resolver list is treated as an error - token is not accepted
    assert response.status_code in (401, 500)


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
async def test_mcd_issuer_not_in_resolved_domains_list(httpx_mock: HTTPXMock):
    """Test that a token whose issuer is not in the resolver's returned list is rejected with 401."""
    setup_mcd_mocks(httpx_mock, ["other.example.com"])

    def resolver(context):
        return ["other.example.com"]

    access_token = await generate_token(
        domain="secondary.auth0.com",
        user_id="user_123",
        audience="<audience>",
        issuer="https://secondary.auth0.com/",
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(
        domains=resolver,
        audience="<audience>"
    )

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 401
    json_body = response.json()
    assert json_body["detail"]["error"] == "invalid_token"
