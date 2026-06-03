"""
Internal authentication middleware for service-to-service communication
"""

from functools import wraps
from flask import request, jsonify
from app.config import INTERNAL_API_TOKEN

def require_internal_token(f):
    """
    Decorator to require internal API token for service-to-service requests.
    This prevents external direct access to internal endpoints.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check for internal token in headers
        token = request.headers.get('X-Internal-Token', '')
        
        if not token:
            return jsonify({'error': 'Internal authentication required'}), 401
        
        if token != INTERNAL_API_TOKEN:
            return jsonify({'error': 'Invalid internal token'}), 401
        
        return f(*args, **kwargs)
    return decorated


def require_local_only(f):
    """
    Decorator to restrict access to localhost only.
    Prevents external access to internal services.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check if request comes from localhost
        client_ip = request.remote_addr
        
        # In development, Flask might show 127.0.0.1
        if client_ip not in ['127.0.0.1', 'localhost', None]:
            return jsonify({'error': 'Access denied. This endpoint is internal only.'}), 403
        
        return f(*args, **kwargs)
    return decorated