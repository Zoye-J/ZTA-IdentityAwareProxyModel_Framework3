from flask import Flask, request, jsonify, Response
import jwt
import requests
import os
from functools import wraps
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

class APIGatewayService:
    """Lightweight API Gateway that routes to document service"""
    
    def __init__(self, port=8502):
        self.app = Flask(__name__)
        self.port = port
        
        # JWT configuration (shared secret with IAP)
        self.jwt_secret = os.environ.get('JWT_SECRET', 'iap-shared-secret')
        
        # Document service URL
        self.document_service_url = "https://localhost:8503"
        
        self._setup_routes()
    
    def _verify_jwt(self):
        """Verify JWT from IAP proxy"""
        token = request.headers.get('X-IAP-JWT-Assertion', '')
        if not token:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return None
        
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'],
                                options={'verify_aud': False})
            return payload
        except Exception as e:
            print(f"API Gateway - JWT verification error: {e}")
            return None
    
    def _require_auth(self, f):
        """Decorator to verify JWT"""
        @wraps(f)
        def decorated(*args, **kwargs):
            user = self._verify_jwt()
            if not user:
                return jsonify({'error': 'Unauthorized - Valid JWT required'}), 401
            request.user = user
            return f(*args, **kwargs)
        return decorated
    
    def _proxy_to_document_service(self, path, method='GET', data=None):
        """Proxy request to document service"""
        url = f"{self.document_service_url}{path}"
        
        # Forward the JWT token
        headers = {
            'X-IAP-JWT-Assertion': request.headers.get('X-IAP-JWT-Assertion', ''),
            'Content-Type': 'application/json'
        }
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, verify=False)
            elif method == 'POST':
                response = requests.post(url, headers=headers, json=data, verify=False)
            else:
                response = requests.get(url, headers=headers, verify=False)
            
            return response.json(), response.status_code
        except requests.exceptions.RequestException as e:
            return {'error': f'Document service error: {str(e)}'}, 502
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.route('/api/v1/user/dashboard', methods=['GET'])
        @self._require_auth
        def dashboard():
            return jsonify({
                'user': {
                    'username': request.user.get('username'),
                    'clearance': request.user.get('clearance'),
                    'department': request.user.get('department')
                },
                'message': f"Welcome {request.user.get('username')} - Access granted via IAP",
                'services': {
                    'document_service': 'https://localhost:8503'
                }
            })
        
        @self.app.route('/api/v1/documents', methods=['GET'])
        @self._require_auth
        def get_documents():
            """Get documents from document service"""
            result, status = self._proxy_to_document_service('/documents')
            return jsonify(result), status
        
        @self.app.route('/api/v1/documents/<int:doc_id>', methods=['GET'])
        @self._require_auth
        def get_document(doc_id):
            """Get specific document from document service"""
            result, status = self._proxy_to_document_service(f'/documents/{doc_id}')
            return jsonify(result), status
        
        @self.app.route('/health', methods=['GET'])
        def health():
            return jsonify({
                'status': 'healthy', 
                'service': 'API Gateway',
                'upstream': 'Document Service'
            })
        
        @self.app.route('/', methods=['GET'])
        def index():
            return jsonify({
                'service': 'API Gateway (IAP Protected)',
                'status': 'running',
                'endpoints': [
                    '/api/v1/user/dashboard',
                    '/api/v1/documents',
                    '/api/v1/documents/<id>'
                ]
            })
    
    def run(self):
        """Start API gateway service"""
        print(f"🔀 API Gateway starting on port {self.port}")
        self.app.run(
            host='127.0.0.1',
            port=self.port,
            ssl_context=('certs/api.crt', 'certs/api.key'),
            debug=False,  # Changed to Falseue,
            use_reloader=False 
        )