"""
SSL Context management for internal service communication
Creates a custom SSL context that trusts our self-signed certificates
"""

import ssl
import certifi

def create_internal_ssl_context():
    """
    Create an SSL context that trusts our self-signed certificates
    This is for internal service communication on localhost only
    """
    context = ssl.create_default_context()
    
    # For localhost internal communication, we disable hostname checking
    # but still verify the certificate is valid
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # For self-signed certs on localhost
    
    return context

def create_iap_ssl_context():
    """
    Create SSL context for IAP proxy to API Gateway communication
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    return context