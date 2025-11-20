"""
Tests for Auth0FastAPI client initialization and configuration.
Tests constructor parameters, default values, and configuration options.
"""
from fastapi_plugin.fast_api_client import Auth0FastAPI


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
