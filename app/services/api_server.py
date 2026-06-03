from flask import Flask, request, jsonify, Response
import jwt
import requests
import os
import ssl
from functools import wraps
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.config import JWT_SECRET, INTERNAL_API_TOKEN
from app.middleware.internal_auth import require_internal_token, require_local_only

class APIGatewayService:
    """Lightweight API Gateway that routes to document service"""
    
    def __init__(self, port=8502):
        self.app = Flask(__name__)
        self.port = port
        
        # Use central JWT secret
        self.jwt_secret = JWT_SECRET
        
        # Document service URL
        self.document_service_url = "https://localhost:8503"
        
        # Create a session with custom SSL context for self-signed certs
        self.session = requests.Session()
        
        # For internal services on localhost, we trust our self-signed certs
        # Create SSL context that doesn't verify for localhost only
        self.session.verify = False  # Internal communication only
        # Suppress the insecure request warning
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self._setup_routes()
    
    def _verify_jwt(self):
        """Verify JWT from IAP proxy only (not from external)"""
        token = request.headers.get('X-IAP-JWT-Assertion', '')
        
        if not token:
            print("❌ API Gateway: No X-IAP-JWT-Assertion header - rejecting")
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
    
    def _require_iap_auth(self, f):
        """Decorator to verify JWT comes ONLY from IAP proxy"""
        @wraps(f)
        def decorated(*args, **kwargs):
            # Verify internal token first (service-to-service auth)
            internal_token = request.headers.get('X-Internal-Token', '')
            if internal_token != INTERNAL_API_TOKEN:
                print(f"❌ API Gateway: Invalid internal token")
                return jsonify({'error': 'Unauthorized - Invalid internal token'}), 401
            
            user = self._verify_jwt()
            if not user:
                return jsonify({'error': 'Unauthorized - Valid IAP JWT required'}), 401
            request.user = user
            return f(*args, **kwargs)
        return decorated
    
    def _proxy_to_document_service(self, path, method='GET', data=None):
        """Proxy request to document service"""
        url = f"{self.document_service_url}{path}"
        
        # Forward JWT token AND internal token
        headers = {
            'X-IAP-JWT-Assertion': request.headers.get('X-IAP-JWT-Assertion', ''),
            'X-Internal-Token': INTERNAL_API_TOKEN,
            'Content-Type': 'application/json'
        }
        
        print(f"🔍 API Gateway: Proxying to {url}")
        
        try:
            if method == 'GET':
                response = self.session.get(url, headers=headers)
            elif method == 'POST':
                response = self.session.post(url, headers=headers, json=data)
            else:
                response = self.session.get(url, headers=headers)
            
            print(f"✅ API Gateway: Response status {response.status_code}")
            return response.json(), response.status_code
        except requests.exceptions.RequestException as e:
            print(f"❌ API Gateway: Proxy error - {e}")
            return {'error': f'Document service error: {str(e)}'}, 502
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.before_request
        def log_request():
            print(f"🔍 API Gateway: Request from {request.remote_addr} to {request.path}")
        
        @self.app.route('/api/v1/user/dashboard', methods=['GET'])
        @require_local_only
        @self._require_iap_auth
        def dashboard():
            return jsonify({
                'user': {
                    'username': request.user.get('username'),
                    'clearance': request.user.get('clearance'),
                    'department': request.user.get('department')
                },
                'message': 'Access granted via IAP'
            })
        
        @self.app.route('/api/v1/documents', methods=['GET'])
        @require_local_only
        @self._require_iap_auth
        def get_documents():
            """Get documents from document service"""
            result, status = self._proxy_to_document_service('/documents')
            return jsonify(result), status
        
        @self.app.route('/api/v1/documents/<int:doc_id>', methods=['GET'])
        @require_local_only
        @self._require_iap_auth
        def get_document(doc_id):
            """Get specific document from document service"""
            result, status = self._proxy_to_document_service(f'/documents/{doc_id}')
            return jsonify(result), status
        
        @self.app.route('/health', methods=['GET'])
        @require_internal_token 
        def health():
            return jsonify({
                'status': 'healthy', 
                'service': 'API Gateway'
            })
        
        @self.app.route('/', methods=['GET'])
        def index():
            return jsonify({
                'service': 'API Gateway',
                'status': 'running',
                'note': 'Internal service only'
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