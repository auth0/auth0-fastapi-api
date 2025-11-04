from typing import Optional, List, Union, Dict
from fastapi import Request, HTTPException
from starlette.responses import Response
from urllib.parse import urlparse, urlunparse

def http_exception(
    status_code: int,
    error: str,
    error_desc: str,
    headers: Optional[Dict[str, str]] = None
) -> HTTPException:
    """
    Construct an HTTPException with appropriate headers.
    
    Args:
        status_code: HTTP status code
        error: OAuth2/DPoP error code
        error_desc: Human-readable error description  
        headers: Optional headers dict (e.g., from BaseAuthError.get_headers())
    
    Note: When used with BaseAuthError, pass the headers from get_headers()
    to ensure correct WWW-Authenticate challenges are included.
    """
    return HTTPException(
        status_code=status_code,
        detail={
            "error": error,
            "error_description": error_desc
        },
        headers=headers or {}
    )

def _should_trust_proxy(request: Request) -> bool:
    """
    Determines if X-Forwarded-* headers should be trusted.
    
    Returns:
        bool: True if proxy headers should be trusted
    """
    # Check if the app has explicitly enabled proxy trust
    try:
        return getattr(request.app.state, 'trust_proxy', False)
    except AttributeError:
        # If app.state doesn't exist or trust_proxy isn't set, don't trust
        return False

def _parse_forwarded_host(forwarded_host: Optional[str]) -> Optional[str]:
    """
    Parses X-Forwarded-Host header, handling multiple comma-separated values.
    
    Args:
        forwarded_host: Value of X-Forwarded-Host header
    
    Returns:
        The first host value, or None if empty
    """
    if not forwarded_host:
        return None
    
    # Handle comma-separated values (multiple proxies)
    comma_index = forwarded_host.find(',')
    if comma_index != -1:
        forwarded_host = forwarded_host[:comma_index].rstrip()
    
    return forwarded_host.strip() or None

def get_canonical_url(request: Request) -> str:
    """
    Constructs the canonical URL for DPoP validation, securely handling reverse proxy headers.
    
    Args:
        request: FastAPI/Starlette Request object
    
    Returns:
        Canonical URL string matching what the client used
    
    """
    # Start with the direct connection URL
    parsed = urlparse(str(request.url))
    
    # Default to direct request values
    scheme = parsed.scheme
    netloc = parsed.netloc
    path = parsed.path
    
    # Only process X-Forwarded headers if proxy is trusted
    if _should_trust_proxy(request):
        # X-Forwarded-Proto: Override scheme if present
        forwarded_proto = request.headers.get("x-forwarded-proto")
        if forwarded_proto:
            proto = forwarded_proto.strip().lower()
            if proto in ("http", "https"):
                scheme = proto
        
        # X-Forwarded-Host: Override host, handling multiple proxies
        forwarded_host = request.headers.get("x-forwarded-host")
        parsed_host = _parse_forwarded_host(forwarded_host)
        if parsed_host:
            netloc = parsed_host
        
        # X-Forwarded-Prefix: Prepend path prefix
        forwarded_prefix = request.headers.get("x-forwarded-prefix", "").strip()
        if forwarded_prefix and not any([
            ".." in forwarded_prefix, forwarded_prefix.startswith("//"),
            ":" in forwarded_prefix, "\x00" in forwarded_prefix,
            "%2e%2e" in forwarded_prefix.lower()
        ]):
            if not forwarded_prefix.startswith("/"):
                forwarded_prefix = "/" + forwarded_prefix
            path = forwarded_prefix.rstrip("/") + path
    
    canonical_url = urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        ""  # No fragment in DPoP htu claim
    ))
    
    return canonical_url

def validate_scopes(claims: Dict, required_scopes: List[str]) -> bool:
    """
    Verifies the 'scope' claim (a space-delimited string) includes all required_scopes.
    """
    scope_str = claims.get("scope")
    if not scope_str:
        return False

    token_scopes = scope_str.split()  # space-delimited
    return all(req in token_scopes for req in required_scopes)