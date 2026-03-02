"""
Tests for Auth0FastAPI client initialization and configuration.
Tests constructor parameters, default values, and configuration options.
"""
import pytest
from fastapi_plugin.fast_api_client import Auth0FastAPI
from fastapi_plugin import ConfigurationError, InMemoryCache


# =============================================================================
# Client Credentials Configuration
# =============================================================================

def test_initialization_with_client_credentials():
    """Test that Auth0FastAPI accepts and stores client_id and client_secret."""
    client_id = "test_client_id"
    client_secret = "test_client_secret"
    
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="test_audience",
        client_id=client_id,
        client_secret=client_secret
    )
    
    options = auth0.api_client.options
    assert options.client_id == client_id
    assert options.client_secret == client_secret


# =============================================================================
# DPoP Configuration Tests
# =============================================================================

def test_dpop_default_configuration():
    """Test that DPoP has correct default configuration values."""
    auth0 = Auth0FastAPI(domain="auth0.local", audience="test")
    
    assert auth0.api_client.options.dpop_enabled is True
    assert auth0.api_client.options.dpop_required is False
    assert auth0.api_client.options.dpop_iat_leeway == 30
    assert auth0.api_client.options.dpop_iat_offset == 300


def test_dpop_disabled_configuration():
    """Test that DPoP can be explicitly disabled."""
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="test",
        dpop_enabled=False
    )
    
    assert auth0.api_client.options.dpop_enabled is False


def test_dpop_custom_timing_configuration():
    """Test that custom DPoP timing parameters are accepted."""
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="test",
        dpop_iat_leeway=60,
        dpop_iat_offset=600
    )
    
    assert auth0.api_client.options.dpop_iat_leeway == 60
    assert auth0.api_client.options.dpop_iat_offset == 600


# =============================================================================
# MCD Configuration Tests
# =============================================================================

def test_mcd_initialization_with_static_domains_list():
    """Test MCD initialization with a static list of domains."""
    auth0 = Auth0FastAPI(
        domains=["tenant1.auth0.com", "tenant2.auth0.com"],
        audience="test_audience"
    )

    assert auth0.api_client.options.domains is not None
    assert auth0.api_client.options.domain is None


def test_mcd_initialization_with_callable_resolver():
    """Test MCD initialization with a domain resolver function."""
    def resolver(context):
        return ["tenant1.auth0.com"]

    auth0 = Auth0FastAPI(
        domains=resolver,
        audience="test_audience"
    )

    assert callable(auth0.api_client.options.domains)


def test_mcd_initialization_hybrid_mode():
    """Test that both domain and domains can be provided (hybrid mode)."""
    auth0 = Auth0FastAPI(
        domain="primary.auth0.com",
        domains=["primary.auth0.com", "secondary.auth0.com"],
        audience="test_audience"
    )

    assert auth0.api_client.options.domain == "primary.auth0.com"
    assert auth0.api_client.options.domains is not None


def test_mcd_missing_both_domain_and_domains_raises_error():
    """Test that ConfigurationError is raised when neither domain nor domains is provided."""
    with pytest.raises(ConfigurationError):
        Auth0FastAPI(audience="test_audience")


def test_mcd_empty_domains_list_raises_error():
    """Test that ConfigurationError is raised for an empty domains list."""
    with pytest.raises(ConfigurationError):
        Auth0FastAPI(domains=[], audience="test_audience")


def test_mcd_cache_configuration_passthrough():
    """Test that cache parameters are passed through to ApiClientOptions."""
    custom_cache = InMemoryCache()

    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="test_audience",
        cache_adapter=custom_cache,
        cache_ttl_seconds=1200,
        cache_max_entries=200
    )

    assert auth0.api_client.options.cache_adapter is custom_cache
    assert auth0.api_client.options.cache_ttl_seconds == 1200
    assert auth0.api_client.options.cache_max_entries == 200


def test_mcd_backward_compatibility_single_domain():
    """Test that existing single-domain usage still works unchanged."""
    auth0 = Auth0FastAPI(
        domain="auth0.local",
        audience="test_audience"
    )

    assert auth0.api_client.options.domain == "auth0.local"
    assert auth0.api_client.options.domains is None
