
from pytest_httpx import HTTPXMock

from .test_utils import PRIVATE_JWK, PUBLIC_DPOP_JWK

# RSA public key used across all test domains (shared key for simplicity)
RSA_PUBLIC_KEY = {
    "kty": "RSA",
    "kid": "TEST_KEY",
    "n": PRIVATE_JWK["n"],
    "e": PRIVATE_JWK["e"],
    "alg": "RS256",
    "use": "sig"
}


def setup_mocks(httpx_mock: HTTPXMock):
    """Setup common OIDC and JWKS mocks for all tests."""
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "issuer": "https://auth0.local/",
            "jwks_uri": "https://auth0.local/.well-known/jwks.json"
        }
    )
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={
            "keys": [
                RSA_PUBLIC_KEY,
                PUBLIC_DPOP_JWK
            ]
        }
    )


def setup_mcd_mocks(httpx_mock: HTTPXMock, domains: list[str]):
    """Setup OIDC and JWKS mocks for multiple domains in MCD tests.

    Each domain gets its own .well-known/openid-configuration and
    .well-known/jwks.json endpoints, all using the same RSA test key.

    Args:
        httpx_mock: pytest-httpx HTTPXMock fixture
        domains: List of domain strings (e.g., ["tenant1.auth0.com", "tenant2.auth0.com"])
    """
    for domain in domains:
        # Strip protocol and trailing slash if present
        clean_domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        base_url = f"https://{clean_domain}"

        httpx_mock.add_response(
            method="GET",
            url=f"{base_url}/.well-known/openid-configuration",
            json={
                "issuer": f"{base_url}/",
                "jwks_uri": f"{base_url}/.well-known/jwks.json"
            }
        )
        httpx_mock.add_response(
            method="GET",
            url=f"{base_url}/.well-known/jwks.json",
            json={
                "keys": [
                    RSA_PUBLIC_KEY,
                    PUBLIC_DPOP_JWK
                ]
            }
        )
