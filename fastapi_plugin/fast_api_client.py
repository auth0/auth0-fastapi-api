from typing import Callable, Optional, Union

from auth0_api_python.api_client import ApiClient, ApiClientOptions, BaseAuthError
from auth0_api_python.cache import CacheAdapter
from fastapi import Request

from .utils import get_canonical_url, http_exception, validate_scopes


class Auth0FastAPI:
    """
    A class that configures and exposes a method to protect routes in FastAPI,
    mirroring the concept from TypeScript's Fastify plugin.
    """

    def __init__(
        self,
        domain: Optional[str] = None,
        audience: str = "",
        domains: Optional[Union[list[str], Callable]] = None,
        client_id=None,
        client_secret=None,
        custom_fetch=None,
        dpop_enabled=True,
        dpop_required=False,
        dpop_iat_leeway=30,
        dpop_iat_offset=300,
        cache_adapter: Optional[CacheAdapter] = None,
        cache_ttl_seconds: int = 600,
        cache_max_entries: int = 100):
        """
        domain: Your Auth0 domain (like 'my-tenant.us.auth0.com').
                Use for single-domain mode. Optional if 'domains' is provided.
        audience: API identifier from the Auth0 Dashboard
        domains: List of allowed domain strings or a callable resolver function for
                 multi-custom domain (MCD) mode. Optional if 'domain' is provided.
                 Callable signature: (DomainsResolverContext) -> list[str]
        client_id: Client ID for token exchange flows
        client_secret: Client secret for token exchange flows
        custom_fetch: optional HTTP fetch override for the underlying SDK
        dpop_enabled: Enable DPoP support (default: True)
        dpop_required: Require DPoP authentication, reject Bearer tokens (default: False)
        dpop_iat_leeway: Clock skew tolerance for DPoP proof iat claim in seconds (default: 30)
        dpop_iat_offset: Maximum DPoP proof age in seconds (default: 300)
        cache_adapter: Custom cache backend implementing CacheAdapter (default: InMemoryCache)
                       Note: When providing cache_adapter, configure it directly.
                       The cache_max_entries parameter only applies when cache_adapter is None.
        cache_ttl_seconds: Cache time-to-live in seconds (default: 600)
        cache_max_entries: Maximum cache entries before LRU eviction (default: 100)
                          Ignored when cache_adapter is provided.
        """
        if not audience:
            raise ValueError("audience is required.")

        self.api_client = ApiClient(
            ApiClientOptions(
                domain=domain,
                audience=audience,
                domains=domains,
                client_id=client_id,
                client_secret=client_secret,
                custom_fetch=custom_fetch,
                dpop_enabled=dpop_enabled,
                dpop_required=dpop_required,
                dpop_iat_leeway=dpop_iat_leeway,
                dpop_iat_offset=dpop_iat_offset,
                cache_adapter=cache_adapter,
                cache_ttl_seconds=cache_ttl_seconds,
                cache_max_entries=cache_max_entries
            )
        )

    def require_auth(
        self,
        scopes: Optional[Union[str, list[str]]] = None
    ):
        """
        Returns an async FastAPI dependency that:
         1) Uses the unified verify_request() method to auto-detect Bearer or DPoP authentication
         2) Verifies the request with auth0-api-python including full HTTP context
         3) If 'scopes' is provided, checks for them in the token's 'scope' claim
         4) Raises HTTPException on error
         5) On success, returns the decoded claims
        """
        async def _dependency(request: Request) -> dict:
            try:
                claims = await self.api_client.verify_request(
                    headers=dict(request.headers),
                    http_method=request.method,
                    http_url=get_canonical_url(request)
                )
            except BaseAuthError as e:
                raise http_exception(
                    status_code=e.get_status_code(),
                    error=e.get_error_code(),
                    error_desc=e.get_error_description(),
                    headers=e.get_headers()
                )
            except Exception:
                # Handle any unexpected errors
                raise http_exception(
                    status_code=500,
                    error="internal_server_error",
                    error_desc="An unexpected error occurred during authentication"
                )

            # If scopes needed, validate
            if scopes:
                required_scopes = [scopes] if isinstance(scopes, str) else scopes
                if not validate_scopes(claims, required_scopes):
                    raise http_exception(
                        status_code=403,
                        error="insufficient_scope",
                        error_desc="Insufficient scopes"
                    )

            # Return the claims as the "user" info
            return claims

        return _dependency
