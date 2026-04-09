# Examples

- [Configuration](#configuration)
  - [Basic Configuration](#basic-configuration)
  - [Configuring a `custom_fetch` Implementation](#configuring-a-custom_fetch-implementation)
- [Scope Validation](#scope-validation)
- [DPoP Authentication](#dpop-authentication)
  - [Accept both Bearer and DPoP tokens (default)](#accept-both-bearer-and-dpop-tokens-default)
  - [Require only DPoP tokens](#require-only-dpop-tokens)
  - [Require only Bearer tokens](#require-only-bearer-tokens)
- [Reverse Proxy Support](#reverse-proxy-support)
- [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)
  - [Static Allowlist](#static-allowlist)
  - [Dynamic Domain Resolver](#dynamic-domain-resolver)
  - [`domain` vs `domains` Configuration](#domain-vs-domains-configuration)
  - [Security Requirements](#security-requirements)
  - [DPoP with MCD](#dpop-with-mcd)
- [Discovery Cache Configuration](#discovery-cache-configuration)
- [Protecting API Routes](#protecting-api-routes)

## Configuration

### Basic Configuration

Create an instance of the `Auth0FastAPI` class with your Auth0 domain and audience.

```python
from fastapi import FastAPI, Depends
from fastapi_plugin.fast_api_client import Auth0FastAPI

app = FastAPI()
auth0 = Auth0FastAPI(
    domain="<AUTH0_DOMAIN>",
    audience="<AUTH0_AUDIENCE>"
)

@app.get("/api/protected")
async def protected_route(claims=Depends(auth0.require_auth())):
    return {"user_id": claims["sub"]}
```

The `AUTH0_DOMAIN` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application.
The `AUTH0_AUDIENCE` is the identifier of the API that is being called. You can find this in the API section of the Auth0 dashboard.

### Configuring a `custom_fetch` Implementation

The SDK allows overriding the HTTP implementation used for making requests by providing a custom fetch function when creating the client:

```python
import httpx

async def my_custom_fetch(url, **kwargs):
    async with httpx.AsyncClient() as client:
        response = await client.request(method=kwargs.get("method", "GET"), url=url, **kwargs)
        return response

auth0 = Auth0FastAPI(
    domain="<AUTH0_DOMAIN>",
    audience="<AUTH0_AUDIENCE>",
    custom_fetch=my_custom_fetch
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

## DPoP Authentication

### Accept both Bearer and DPoP tokens (default)

```python
auth0 = Auth0FastAPI(
    domain="<AUTH0_DOMAIN>",
    audience="<AUTH0_AUDIENCE>",
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
    domain="<AUTH0_DOMAIN>",
    audience="<AUTH0_AUDIENCE>",
    dpop_required=True
)
```

### Require only Bearer tokens

```python
auth0 = Auth0FastAPI(
    domain="<AUTH0_DOMAIN>",
    audience="<AUTH0_AUDIENCE>",
    dpop_enabled=False
)
```

## Reverse Proxy Support

Enable X-Forwarded-* header trust for DPoP behind proxies:

```python
app = FastAPI()
app.state.trust_proxy = True  # Required for load balancers/CDN

auth0 = Auth0FastAPI(
    domain="<AUTH0_DOMAIN>",
    audience="<AUTH0_AUDIENCE>"
)
```

## Multiple Custom Domains (MCD)
Multiple Custom Domains (MCD) support enables a single API application to accept access tokens issued by multiple domains associated with the same Auth0 tenant, including the `canonical domain` and its `custom domains`.

This is commonly required in scenarios such as:
- Multi-brand applications (B2C) where each brand uses a different custom domain but they all share the same API.
- A single API serves multiple frontend applications that use different custom domains.
- A gradual migration from the canonical domain to a custom domain, where both domains need to be supported during the transition period.

In these cases, your API must trust and validate tokens from multiple issuers instead of a single domain.

The SDK supports two approaches for configuring multiple allowed issuer domains: `Static Allowlist` and `Dynamic Domain Resolver`.

### Static Domain List
Use a static domain list when the set of trusted issuer domains is known in advance and remains the same for all requests.
This approach also works well for domain migration scenarios, where multiple domains (such as the canonical domain and one or more custom domains) need to be accepted during a transition period.
The SDK validates incoming tokens against a predefined list of allowed domains.

```python
from fastapi import FastAPI, Depends
from fastapi_plugin import Auth0FastAPI

app = FastAPI()

auth0 = Auth0FastAPI(
    audience="<AUTH0_AUDIENCE>",
    domains=[
        "brand1.auth.example.com",
        "brand2.auth.example.com",
    ],
)

@app.get("/api/protected")
async def protected_route(claims=Depends(auth0.require_auth())):
    return {"user_id": claims["sub"]}
```

### Dynamic Domain Resolver
Use a dynamic resolver when the set of allowed issuer domains needs to be determined at runtime based on the incoming request.
The SDK provides a `DomainsResolverContext` containing request and token-derived information (`request_url`, `request_headers`, and `unverified_iss`). You can use any combination of these inputs to determine the allowed issuer domains for the request.

In the following example, a single API application is accessed through two domains:

- `https://api.brand1.com/`
- `https://api.brand2.com/`

Each domain should only accept tokens issued by its corresponding Auth0 custom domains.

- `https://api.brand1.com/` should accept tokens issued by:
  - `brand1-en.auth.example.com`
  - `brand1-jp.auth.example.com`

- `https://api.brand2.com/` should accept tokens issued by:
  - `brand2-en.auth.example.com`
  - `brand2-jp.auth.example.com`

To enforce this behavior, you can configure a dynamic domain resolver that determines the allowed issuer domains based on the incoming request.

```python
from urllib.parse import urlparse
from fastapi import FastAPI, Depends
from fastapi_plugin import Auth0FastAPI, DomainsResolverContext

app = FastAPI()

def domains_resolver(context: DomainsResolverContext) -> list:
    request_url = context.get("request_url")
    host = urlparse(request_url).hostname if request_url else None

    if host == "api.brand1.com":
        return ["brand1-en.auth.example.com", "brand1-jp.auth.example.com"]

    if host == "api.brand2.com":
        return ["brand2-en.auth.example.com", "brand2-jp.auth.example.com"]

    # fallback to default custom domains
    return ["default.auth.example.com"]

auth0 = Auth0FastAPI(
    audience="<AUTH0_AUDIENCE>",
    domain="<AUTH0_DOMAIN>",  # optional for verification-only, required for client flows
    domains=domains_resolver,
)
```

The resolver receives a `DomainsResolverContext` dictionary with:
- `request_url`: the request URL, when available
- `request_headers`: the request headers
- `unverified_iss`: the issuer read from the token before signature verification

It is the application's responsibility to decide how to use this information to return the allowed issuer domains. This allows the application to control which issuers the SDK can verify tokens from on a per-request basis. The resolver must return a non-empty list of domain strings.

### `domain` vs `domains` Configuration
This section explains the roles of `domain` and `domains`, and how the SDK determines which configuration is used for access token validation.
- When both `domain` and `domains` are configured, the SDK uses `domains` exclusively for access token verification.
- The `domain` option should be retained only if your application also performs client-side flows (for example, `get_access_token_for_connection()`).
- When `domains` is specified, the SDK uses the provided issuer domains for discovery and token verification instead of `domain`.
- If `domains` is not configured, the SDK falls back to `domain` for discovery and token verification.

These values must be provided exactly as configured in the Auth0 Dashboard.

```python
auth0 = Auth0FastAPI(
    domain="<AUTH0_DOMAIN>",                   # retained for client flows
    domains=["<AUTH0_DOMAIN>", "custom.example.com"],  # used for verification
    audience="<AUTH0_AUDIENCE>",
    client_id="<AUTH0_CLIENT_ID>",
    client_secret="<AUTH0_CLIENT_SECRET>"
)
```

### Security Requirements
When configuring `domains` or a domain resolver for Multiple Custom Domains (MCD), you are responsible for ensuring that only trusted issuer domains are returned.

Mis-configuring the domain resolver is a critical security risk. It can cause the SDK to:
- accept access tokens from unintended issuers
- make discovery or JWKS requests to unintended domains

**Single Tenant Limitation:**
The `domains` configuration is intended only for multiple custom domains that belong to the same Auth0 tenant. It is not a supported mechanism for connecting multiple Auth0 tenants to a single API.

**FastAPI Request and Proxy Warning:**
If your resolver uses request-derived values such as `context["request_url"]`, `context["request_headers"]`, or `context["unverified_iss"]`, do not trust those values directly. Use them only to map known and expected request values to a fixed allowlist of issuer domains that you control.

In particular:
- `context["request_url"]` and host-related request data may depend on your FastAPI and proxy configuration
- if your application is behind a reverse proxy or load balancer, configure FastAPI and your proxy so that host-related request information is trusted only when it comes from trusted infrastructure (see `app.state.trust_proxy = True`)
- do not rely directly on `Host` or `X-Forwarded-*` unless your deployment is configured to sanitize and trust them correctly
- `context["unverified_iss"]` comes from the token before signature verification and must not be trusted by itself

Misconfigured proxy handling or loose resolver logic can cause the SDK to trust unintended issuer domains.

### DPoP with MCD

```python
auth0 = Auth0FastAPI(
    domains=["brand1.auth.example.com", "brand2.auth.example.com"],
    audience="<AUTH0_AUDIENCE>",
    dpop_enabled=True,
    dpop_required=False
)
```

## Discovery Cache Configuration

You can control discovery and signing-key caching behavior with `cache_ttl_seconds`, `cache_max_entries`, or a custom `cache_adapter`. This cache is not specific to MCD. It applies to all token verification flows.

By default, the SDK uses an in-memory LRU cache with:
- `cache_ttl_seconds`: 600
- `cache_max_entries`: 100

The SDK maintains:
- a discovery metadata cache, keyed by normalized domain
- a signing-key fetcher cache, keyed by `jwks_uri`

The same cache settings apply to both caches.

Most applications can keep the defaults, but you may want to adjust them in the following cases:
- Increase `cache_max_entries` if one process may verify tokens for more than 100 distinct domains or JWKS URIs during the TTL window. This is most common in Multiple Custom Domains deployments that work with many custom domains.
- Decrease `cache_max_entries` if memory usage matters more than avoiding repeated discovery and signing-key setup.
- Increase `cache_ttl_seconds` if the same domains are reused often and you want to reduce repeated discovery and signing-key setup after entries expire.
- Decrease `cache_ttl_seconds` if you want the SDK to pick up metadata or signing-key changes sooner.
- Set `cache_ttl_seconds` to `0` if you want to effectively disable cache reuse.

Rule of thumb: set `cache_max_entries` to cover the number of distinct domains or JWKS URIs a single process is expected to use during the TTL window, with some headroom.

```python
from fastapi_plugin import Auth0FastAPI

# Option 1: Use default InMemoryCache with custom config (recommended)
auth0 = Auth0FastAPI(
    domain="<AUTH0_DOMAIN>",
    audience="<AUTH0_AUDIENCE>",
    cache_ttl_seconds=1200,
    cache_max_entries=200
)

# Option 2: Provide pre-configured cache adapter
from fastapi_plugin import InMemoryCache

auth0 = Auth0FastAPI(
    domain="<AUTH0_DOMAIN>",
    audience="<AUTH0_AUDIENCE>",
    cache_adapter=InMemoryCache(max_entries=200),
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
    domain="<AUTH0_DOMAIN>",
    audience="<AUTH0_AUDIENCE>",
    cache_adapter=RedisCache(redis_client),
    cache_ttl_seconds=1200
)
```

## Protecting API Routes

To protect a FastAPI route, use the `require_auth()` dependency. The SDK automatically detects and validates both Bearer and DPoP authentication schemes.

```python
@app.get("/api/protected")
async def protected_route(claims=Depends(auth0.require_auth())):
    return {"user_id": claims["sub"]}
```

> [!IMPORTANT]
> The above is to protect API routes by the means of a bearer token, and not server-side rendering routes using a session.
