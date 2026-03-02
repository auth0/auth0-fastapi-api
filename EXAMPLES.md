# Examples

This document provides examples for using the `auth0-fastapi-api` package to secure your FastAPI applications with Auth0.


- [Bearer Authentication](#bearer-authentication)
- [Scope Validation](#scope-validation)
- [DPoP Authentication](#dpop-authentication)
  - [Accept both Bearer and DPoP tokens (default)](#accept-both-bearer-and-dpop-tokens-default)
  - [Require only DPoP tokens](#require-only-dpop-tokens)
  - [Require only Bearer tokens](#rquire-only-bearer-tokens)
- [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)
  - [Static domain list](#static-domain-list)
  - [Dynamic resolver function](#dynamic-resolver-function)
  - [Hybrid mode](#hybrid-mode)
  - [With DPoP](#with-dpop)
  - [With custom cache configuration](#with-custom-cache-configuration)
- [Reverse Proxy Support](#reverse-proxy-support)

---

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

---

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

---

## DPoP Authentication

> [!NOTE]
> DPoP is in Early Access. Contact Auth0 support to enable it.

### Accept both Bearer and DPoP tokens (default)

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

### Require only DPoP tokens

```python
auth0 = Auth0FastAPI(
    domain="your-domain.auth0.com",
    audience="your-api-identifier",
    dpop_required=True
)
```

### Require only Bearer tokens

```python
auth0 = Auth0FastAPI(
    domain="your-domain.auth0.com",
    audience="your-api-identifier",
    dpop_enabled=False
)
```
### Reverse Proxy Support

Enable X-Forwarded-* header trust for DPoP behind proxies:

```python
app = FastAPI()
app.state.trust_proxy = True  # Required for load balancers/CDN

auth0 = Auth0FastAPI(
    domain="your-domain.auth0.com",
    audience="your-api-identifier"
)
```

---

## Multiple Custom Domains (MCD)

### Static domain list

```python
from fastapi import FastAPI, Depends
from fastapi_plugin.fast_api_client import Auth0FastAPI

app = FastAPI()
auth0 = Auth0FastAPI(
    domains=["tenant1.us.auth0.com", "tenant2.eu.auth0.com"],
    audience="your-api-identifier"
)

@app.get("/api/protected")
async def protected_route(claims=Depends(auth0.require_auth())):
    return {"user_id": claims["sub"]}
```

```bash
# Token from either domain is accepted
curl -H "Authorization: Bearer TOKEN_FROM_TENANT1" \
     http://localhost:8000/api/protected
```

### Dynamic resolver function

```python
from fastapi_plugin import Auth0FastAPI, DomainsResolverContext

def resolve_domains(context: DomainsResolverContext) -> list:
    """Resolve allowed domains based on request context."""
    # context['unverified_iss'] - issuer from the token (before verification)
    # context.get('request_url') - the API request URL
    # context.get('request_headers') - the API request headers
    return ["tenant1.us.auth0.com", "auth.example.com"]

auth0 = Auth0FastAPI(
    domains=resolve_domains,
    audience="your-api-identifier"
)
```

### Hybrid mode

Use `domain` and `domains` together for zero-downtime domain migration scenarios:

```python
auth0 = Auth0FastAPI(
    domain="primary.us.auth0.com",
    domains=["primary.us.auth0.com", "new-domain.example.com"],
    audience="your-api-identifier",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET"
)
```

### With DPoP

```python
auth0 = Auth0FastAPI(
    domains=["tenant1.us.auth0.com", "tenant2.eu.auth0.com"],
    audience="your-api-identifier",
    dpop_enabled=True,
    dpop_required=False
)
```

### With custom cache configuration

```python
from fastapi_plugin import Auth0FastAPI

# Option 1: Use default InMemoryCache with custom config (recommended)
auth0 = Auth0FastAPI(
    domains=["tenant1.us.auth0.com", "tenant2.eu.auth0.com"],
    audience="your-api-identifier",
    cache_ttl_seconds=1200,      # Cache TTL
    cache_max_entries=200         # Max cached entries
)

# Option 2: Provide pre-configured cache adapter
from fastapi_plugin import InMemoryCache

auth0 = Auth0FastAPI(
    domains=["tenant1.us.auth0.com", "tenant2.eu.auth0.com"],
    audience="your-api-identifier",
    cache_adapter=InMemoryCache(max_entries=200),  # Configure here
    cache_ttl_seconds=1200
    # Note: cache_max_entries is ignored when cache_adapter is provided
)

# Option 3: Custom cache implementation (Redis, etc.)
from fastapi_plugin import CacheAdapter

class RedisCache(CacheAdapter):
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def get(self, key: str):
        return self.redis.get(key)
    
    def set(self, key: str, value, ttl_seconds=None):
        self.redis.set(key, value, ex=ttl_seconds)
    
    def delete(self, key: str):
        self.redis.delete(key)
    
    def clear(self):
        self.redis.flushdb()

auth0 = Auth0FastAPI(
    domains=["tenant1.us.auth0.com", "tenant2.eu.auth0.com"],
    audience="your-api-identifier",
    cache_adapter=RedisCache(redis_client),
    cache_ttl_seconds=1200
)
```
