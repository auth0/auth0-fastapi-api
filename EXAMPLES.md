# Auth0 FastAPI-API Examples

This document provides examples for using the `auth0-fastapi-api` package to secure your FastAPI applications with Auth0.

## Bearer Authentication

```python
from fastapi import FastAPI, Depends
from fastapi_plugin.fast_api_client import Auth0FastAPI

app = FastAPI()
auth0 = Auth0FastAPI(
    domain="your-domain.auth0.com",
    audience="your-api-identifier"
)

@app.get("/api/protected")
async def protected_route(claims=Depends(auth0.require_auth())):
    return {"user_id": claims["sub"]}
```

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:8000/api/protected
```

## DPoP Authentication

> [!NOTE]
> DPoP is in Early Access. Contact Auth0 support to enable it.

**Mixed Mode (default)** - Accept both Bearer and DPoP:

```python
auth0 = Auth0FastAPI(
    domain="your-domain.auth0.com",
    audience="your-api-identifier",
    dpop_enabled=True,      # Default
    dpop_required=False     # Default
)
```

```bash
# DPoP request
curl -H "Authorization: DPoP YOUR_ACCESS_TOKEN" \
     -H "DPoP: YOUR_DPOP_PROOF_JWT" \
     http://localhost:8000/api/protected
```

**DPoP Required Mode** - Reject Bearer tokens:

```python
auth0 = Auth0FastAPI(
    domain="your-domain.auth0.com",
    audience="your-api-identifier",
    dpop_required=True
)
```

**Bearer-Only Mode** - Disable DPoP:

```python
auth0 = Auth0FastAPI(
    domain="your-domain.auth0.com",
    audience="your-api-identifier",
    dpop_enabled=False
)
```

## Scope Validation

```python
@app.get("/api/admin")
async def admin_route(claims=Depends(auth0.require_auth(scopes=["admin:access"]))):
    return {"message": "Admin access granted"}

@app.delete("/api/resource")
async def delete_route(
    claims=Depends(auth0.require_auth(scopes=["delete:data", "admin:access"]))
):
    """Requires BOTH scopes."""
    return {"message": "Resource deleted"}
```

## Reverse Proxy Support

Enable X-Forwarded-* header trust for DPoP behind proxies:

```python
app = FastAPI()
app.state.trust_proxy = True  # Required for load balancers/CDN

auth0 = Auth0FastAPI(
    domain="your-domain.auth0.com",
    audience="your-api-identifier"
)
```
