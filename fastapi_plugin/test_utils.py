import time
import hashlib
import base64
import secrets
from typing import Optional, Dict, Any, Union
from authlib.jose import JsonWebKey, jwt


# A private RSA JWK for test usage (Bearer tokens).
PRIVATE_JWK = {
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "kid": "TEST_KEY",
    "n": "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw",
    "e": "AQAB",
    "d": "VuVE_KEP6323WjpbBdAIv7HGahGrgGANvbxZsIhm34lsVOPK0XDegZkhAybMZHjRhp-gwVxX5ChC-J3cUpOBH5FNxElgW6HizD2Jcq6t6LoLYgPSrfEHm71iHg8JsgrqfUnGYFzMJmv88C6WdCtpgG_qJV1K00_Ly1G1QKoBffEs-v4fAMJrCbUdCz1qWto-PU-HLMEo-krfEpGgcmtZeRlDADh8cETMQlgQfQX2VWq_aAP4a1SXmo-j0cvRU4W5Fj0RVwNesIpetX2ZFz4p_JmB5sWFEj_fC7h5z2lq-6Bme2T3BHtXkIxoBW0_pYVnASC8P2puO5FnVxDmWuHDYQ",
    "p": "07rgXd_tLUhVRF_g1OaqRZh5uZ8hiLWUSU0vu9coOaQcatSqjQlIwLW8UdKv_38GrmpIfgcEVQjzq6rFBowUm9zWBO9Eq6enpasYJBOeD8EMeDK-nsST57HjPVOCvoVC5ZX-cozPXna3iRNZ1TVYBY3smn0IaxysIK-zxESf4pM",
    "q": "6qrE9TPhCS5iNR7QrKThunLu6t4H_8CkYRPLbvOIt2MgZyPLiZCsvdkTVSOX76QQEXt7Y0nTNua69q3K3Jhf-YOkPSJsWTxgrfOnjoDvRKzbW3OExIMm7D99fVBODuNWinjYgUwGSqGAsb_3TKhtI-Gr5ls3fn6B6oEjVL0dpmk",
    "dp": "mHqjrFdgelT2OyiFRS3dAAPf3cLxJoAGC4gP0UoQyPocEP-Y17sQ7t-ygIanguubBy65iDFLeGXa_g0cmSt2iAzRAHrDzI8P1-pQl2KdWSEg9ssspjBRh_F_AiJLLSPRWn_b3-jySkhawtfxwO8Kte1QsK1My765Y0zFvJnjPws",
    "dq": "KmjaV4YcsVAUp4z-IXVa5htHWmLuByaFjpXJOjABEUN0467wZdgjn9vPRp-8Ia8AyGgMkJES_uUL_PDDrMJM9gb4c6P4-NeUkVtreLGMjFjA-_IQmIMrUZ7XywHsWXx0c2oLlrJqoKo3W-hZhR0bPFTYgDUT_mRWjk7wV6wl46E",
    "qi": "iYltkV_4PmQDfZfGFpzn2UtYEKyhy-9t3Vy8Mw2VHLAADKGwJvVK5ficQAr2atIF1-agXY2bd6KV-w52zR8rmZfTr0gobzYIyqHczOm13t7uXJv2WygY7QEC2OGjdxa2Fr9RnvS99ozMa5nomZBqTqT7z5QV33czjPRCjvg6FcE",
}

# A private EC P-256 JWK for DPoP test usage.
PRIVATE_DPOP_JWK = {
    "kty": "EC",
    "alg": "ES256",
    "use": "sig",
    "kid": "DPOP_TEST_KEY",
    "crv": "P-256",
    "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGHwHitJBcBmXdA_x4ySJOjY_1WykDKVf_",
    "y": "Hkwp7nOHFcFancWLb-AmIYhZaUO_6-DoV0oNNXLgr-M",
    "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvqPqg"
}

# Public counterpart for JWKS
PUBLIC_DPOP_JWK = {
    "kty": "EC",
    "alg": "ES256",
    "use": "sig",
    "kid": "DPOP_TEST_KEY",
    "crv": "P-256",
    "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGHwHitJBcBmXdA_x4ySJOjY_1WykDKVf_",
    "y": "Hkwp7nOHFcFancWLb-AmIYhZaUO_6-DoV0oNNXLgr-M"
}


async def generate_token(
    domain: str,
    user_id: str,
    audience: Optional[str] = None,
    issuer: Union[str, bool, None] = None,
    iat: bool = True,
    exp: bool = True,
    claims: Optional[Dict[str, Any]] = None,
    expiration_time: int = 3600,
    token_type: str = "bearer"
) -> str:
    """
    Generates a real RS256-signed JWT using the private key above.

    Args:
        domain: The Auth0 domain (used if issuer is not False).
        user_id: The 'sub' claim in the token.
        audience: The 'aud' claim in the token. If omitted, 'aud' won't be included.
        issuer:
            - If a string, it's placed in 'iss' claim.
            - If None, default is f"https://{domain}/".
            - If False, skip 'iss' claim entirely.
        iat: Whether to set the 'iat' (issued at) claim. If False, skip it.
        exp: Whether to set the 'exp' claim. If False, skip it.
        claims: Additional custom claims to merge into the token.
        expiration_time: If exp is True, how many seconds from now until expiration.
        token_type: "bearer" for regular tokens, "dpop" for DPoP-bound tokens

    Returns:
        A RS256-signed JWT string.

    """
    token_claims = dict(claims or {})
    token_claims.setdefault("sub", user_id)

    if iat:
        token_claims["iat"] = int(time.time())

    if exp:
        token_claims["exp"] = int(time.time()) + expiration_time

    if issuer is not False:
        token_claims["iss"] = issuer if isinstance(issuer, str) else f"https://{domain}/"

    if audience:
        token_claims["aud"] = audience
    
    # Add DPoP binding for DPoP tokens
    if token_type == "dpop":
        jkt = calculate_jwk_thumbprint(PRIVATE_DPOP_JWK)
        token_claims["cnf"] = {"jkt": jkt}

    key = JsonWebKey.import_key(PRIVATE_JWK)
    header = {"alg": "RS256", "kid": PRIVATE_JWK["kid"]}
    token = jwt.encode(header, token_claims, key)
    return token

def base64url_encode(data: bytes) -> str:
    """Base64URL encode without padding."""
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

def sha256_hash(data: str) -> str:
    """SHA256 hash and base64url encode."""
    return base64url_encode(hashlib.sha256(data.encode('utf-8')).digest())

def generate_jti() -> str:
    """Generate a random JTI (JWT ID) for DPoP proof."""
    return base64url_encode(secrets.token_bytes(16))

def calculate_jwk_thumbprint(jwk_dict: Dict[str, Any]) -> str:
    """Calculate JWK thumbprint for DPoP proof."""
    # For EC P-256 keys, thumbprint is calculated from crv, kty, x, y
    thumbprint_jwk = {
        "crv": jwk_dict["crv"],
        "kty": jwk_dict["kty"],
        "x": jwk_dict["x"],
        "y": jwk_dict["y"]
    }
    # Sort keys and create JSON string
    import json
    canonical_json = json.dumps(thumbprint_jwk, sort_keys=True, separators=(',', ':'))
    return base64url_encode(hashlib.sha256(canonical_json.encode('utf-8')).digest())

async def generate_dpop_proof(
    http_method: str,
    http_url: str,
    access_token: Optional[str] = None,
    nonce: Optional[str] = None,
    iat_offset: int = 0
) -> str:
    """
    Generate a DPoP proof JWT for testing.
    
    Args:
        http_method: HTTP method (GET, POST, etc.)
        http_url: Full HTTP URL
        access_token: Access token to bind (for ath claim)
        nonce: Server nonce for DPoP proof
        iat_offset: Offset for iat claim (for testing expired proofs)
    
    Returns:
        DPoP proof JWT string
    """
    current_time = int(time.time()) + iat_offset
    jti = generate_jti()
    
    # Calculate JWK thumbprint for jkt claim
    jkt = calculate_jwk_thumbprint(PRIVATE_DPOP_JWK)
    
    # DPoP proof claims
    proof_claims = {
        "jti": jti,
        "htm": http_method.upper(),
        "htu": http_url,
        "iat": current_time,
        "jkt": jkt
    }
    
    # Add access token hash if provided
    if access_token:
        proof_claims["ath"] = sha256_hash(access_token)
    
    # Add nonce if provided
    if nonce:
        proof_claims["nonce"] = nonce
    
    # Create header with public key
    header = {
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": {
            "kty": PUBLIC_DPOP_JWK["kty"],
            "crv": PUBLIC_DPOP_JWK["crv"],
            "x": PUBLIC_DPOP_JWK["x"],
            "y": PUBLIC_DPOP_JWK["y"]
        }
    }
    
    # Sign with private key
    key = JsonWebKey.import_key(PRIVATE_DPOP_JWK)
    proof_jwt = jwt.encode(header, proof_claims, key)
    return proof_jwt

async def generate_dpop_bound_token(
    domain: str,
    user_id: str,
    audience: Optional[str] = None,
    issuer: Union[str, bool, None] = None,
    iat: bool = True,
    exp: bool = True,
    claims: Optional[Dict[str, Any]] = None,
    expiration_time: int = 3600,
    cnf_jkt: Optional[str] = None
) -> str:
    """
    Generate a DPoP-bound access token for testing.
    Similar to generate_token but includes cnf claim with jkt.
    
    Args:
        domain: Auth0 domain
        user_id: Subject claim
        audience: Audience claim
        issuer: Issuer claim
        iat: Include iat claim
        exp: Include exp claim
        claims: Additional claims
        expiration_time: Token expiration in seconds
        cnf_jkt: JWK thumbprint for confirmation claim (auto-calculated if None)
    
    Returns:
        DPoP-bound access token JWT string
    """
    token_claims = dict(claims or {})
    token_claims.setdefault("sub", user_id)
    
    if iat:
        token_claims["iat"] = int(time.time())
    
    if exp:
        token_claims["exp"] = int(time.time()) + expiration_time
    
    if issuer is not False:
        token_claims["iss"] = issuer if isinstance(issuer, str) else f"https://{domain}/"
    
    if audience:
        token_claims["aud"] = audience
    
    # Add DPoP binding
    if cnf_jkt is None:
        cnf_jkt = calculate_jwk_thumbprint(PRIVATE_DPOP_JWK)
    
    token_claims["cnf"] = {
        "jkt": cnf_jkt
    }
    
    # Sign with RS256 (access tokens are still RS256, only DPoP proofs are ES256)
    key = JsonWebKey.import_key(PRIVATE_JWK)
    header = {"alg": "RS256", "kid": PRIVATE_JWK["kid"]}
    token = jwt.encode(header, token_claims, key)
    return token
