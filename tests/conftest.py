from pytest_httpx import HTTPXMock
from fastapi_plugin.test_utils import PUBLIC_DPOP_JWK


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
                {
                    "kty": "RSA",
                    "kid": "TEST_KEY",
                    "n": "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw",
                    "e": "AQAB",
                    "alg": "RS256",
                    "use": "sig"
                },
                PUBLIC_DPOP_JWK
            ]
        }
    )