import jwt
import os
from functools import wraps
from flask import request, jsonify, current_app
from datetime import datetime, timedelta, timezone

class JWTValidator:
    """JWT token validation for IAP"""
    
    def __init__(self, secret_key=None):
        self.secret_key = secret_key or os.environ.get('JWT_SECRET', 'iap-secret-key-change-in-prod')
        self.algorithm = 'HS256'  # Consistent with FW1 & FW2
    
    def generate_token(self, user_data):
        """Generate JWT token for authenticated user"""
        payload = {
            'user_id': user_data['user_id'],
            'username': user_data['username'],
            'clearance': user_data.get('clearance', 'BASIC'),
            'department': user_data.get('department', 'general'),
            'email': user_data.get('email', ''),
            'exp': datetime.now(timezone.utc) + timedelta(hours=8),
            'iat': datetime.now(timezone.utc)
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token):
        """Verify JWT token and return payload"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return {'valid': True, 'payload': payload}
        except jwt.ExpiredSignatureError:
            return {'valid': False, 'error': 'Token expired'}
        except jwt.InvalidTokenError as e:
            return {'valid': False, 'error': str(e)}
    
    def validate_request(self, token):
        """Validate request and extract user info"""
        if not token:
            return {'authenticated': False, 'error': 'No token provided'}
        
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
        
        result = self.verify_token(token)
        if not result['valid']:
            return {'authenticated': False, 'error': result['error']}
        
        return {
            'authenticated': True,
            'user': result['payload']
        }
    
    def require_auth(self, f):
        """Decorator to protect endpoints"""
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            token = auth_header.replace('Bearer ', '')
            
            if not token:
                # Check for JWT in X-IAP-JWT-Assertion header (IAP standard)
                token = request.headers.get('X-IAP-JWT-Assertion', '')
            
            validation = self.validate_request(token)
            
            if not validation['authenticated']:
                return jsonify({'error': validation.get('error', 'Authentication required')}), 401
            
            request.user = validation['user']
            return f(*args, **kwargs)
        return decorated