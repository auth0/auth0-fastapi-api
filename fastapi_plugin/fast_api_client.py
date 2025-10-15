from typing import Optional, List, Union, Dict
from fastapi import Request, HTTPException
from starlette.responses import Response

from .utils import validate_scopes, http_exception, get_canonical_url

from auth0_api_python.api_client import ApiClient, ApiClientOptions, BaseAuthError


class Auth0FastAPI:
    """
    A class that configures and exposes a method to protect routes in FastAPI,
    mirroring the concept from TypeScript's Fastify plugin.
    """

    def __init__(
        self, 
        domain: str, 
        audience: str, 
        client_id=None, 
        client_secret=None, 
        custom_fetch=None, 
        dpop_enabled=True, 
        dpop_required=False, 
        dpop_iat_leeway=30, 
        dpop_iat_offset=300):
        """
        domain: Your Auth0 domain (like 'my-tenant.us.auth0.com')
        audience: API identifier from the Auth0 Dashboard
        custom_fetch: optional HTTP fetch override for the underlying SDK
        dpop_enabled: Enable DPoP support (default: True)
        dpop_required: Require DPoP authentication, reject Bearer tokens (default: False)
        dpop_iat_leeway: Clock skew tolerance for DPoP proof iat claim in seconds (default: 30)
        dpop_iat_offset: Maximum DPoP proof age in seconds (default: 300)
        """
        if not domain:
            raise ValueError("domain is required.")
        if not audience:
            raise ValueError("audience is required.")

        self.api_client = ApiClient(
            ApiClientOptions(
                domain=domain, 
                audience=audience, 
                client_id=client_id, 
                client_secret=client_secret, 
                custom_fetch=custom_fetch,
                dpop_enabled=dpop_enabled,
                dpop_required=dpop_required,
                dpop_iat_leeway=dpop_iat_leeway,
                dpop_iat_offset=dpop_iat_offset
            )
        )

    def require_auth(
        self,
        scopes: Optional[Union[str, List[str]]] = None
    ):
        """
        Returns an async FastAPI dependency that:
         1) Uses the unified verify_request() method to auto-detect Bearer or DPoP authentication
         2) Verifies the request with auth0-api-python including full HTTP context
         3) If 'scopes' is provided, checks for them in the token's 'scope' claim
         4) Raises HTTPException on error
         5) On success, returns the decoded claims
        """
        async def _dependency(request: Request) -> Dict:
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
            except Exception as e:
                # Handle any unexpected errors
                raise http_exception(
                    status_code=400,
                    error="invalid_request",
                    error_desc=str(e)
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
