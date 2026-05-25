from flask import Flask, request, jsonify, Response
import jwt
import requests
import os
from functools import wraps
import sys

# Use the SAME secret across all services
JWT_SECRET = "iap-shared-secret-framework3-2025"

class APIGatewayService:
    """Lightweight API Gateway that routes to document service"""
    
    def __init__(self, port=8502):
        self.app = Flask(__name__)
        self.port = port
        
        # Use the same secret as other services
        self.jwt_secret = JWT_SECRET
        
        # Document service URL
        self.document_service_url = "https://localhost:8503"
        
        self._setup_routes()
    
    def _verify_jwt(self):
        """Verify JWT from IAP proxy"""
        # Log all headers for debugging
        print(f"🔍 API Gateway Headers received: {dict(request.headers)}")
        
        token = request.headers.get('X-IAP-JWT-Assertion', '')
        if not token:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        print(f"🔍 API Gateway Token: {token[:50] if token else 'NO TOKEN'}...")
        
        if not token:
            return None
        
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'],
                                options={'verify_aud': False})
            print(f"✅ API Gateway: JWT verified for user: {payload.get('username')}")
            return payload
        except jwt.ExpiredSignatureError:
            print("❌ API Gateway: JWT expired")
            return None
        except jwt.InvalidTokenError as e:
            print(f"❌ API Gateway: JWT invalid - {e}")
            return None
        except Exception as e:
            print(f"❌ API Gateway: Unexpected error - {e}")
            return None
    
    def _require_auth(self, f):
        """Decorator to verify JWT"""
        @wraps(f)
        def decorated(*args, **kwargs):
            print(f"🔍 API Gateway: Request to {request.path}")
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
        
        print(f"🔍 API Gateway: Proxying to {url}")
        print(f"🔍 API Gateway: Forwarding token: {headers['X-IAP-JWT-Assertion'][:50] if headers['X-IAP-JWT-Assertion'] else 'NO TOKEN'}...")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, verify=False)
            elif method == 'POST':
                response = requests.post(url, headers=headers, json=data, verify=False)
            else:
                response = requests.get(url, headers=headers, verify=False)
            
            print(f"✅ API Gateway: Response status {response.status_code}")
            return response.json(), response.status_code
        except requests.exceptions.RequestException as e:
            print(f"❌ API Gateway: Proxy error - {e}")
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
            debug=False,
            threaded=True,
            use_reloader=False 
        )