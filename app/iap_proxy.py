from flask import Flask, request, Response, jsonify, session, redirect, render_template
import requests
import jwt
import os
from datetime import datetime, timedelta, timezone

# Use the SAME secret across all services
JWT_SECRET = "iap-shared-secret-framework3-2025"

class IAPProxy:
    """Identity-Aware Proxy - The main gatekeeper"""
    
    def __init__(self, port=8443):
        self.app = Flask(__name__, template_folder='templates')
        self.app.secret_key = os.environ.get('FLASK_SECRET', 'iap-proxy-secret')
        self.port = port
        
        # Service endpoints (all internal)
        self.auth_service_url = "https://localhost:8501"
        self.api_gateway_url = "https://localhost:8502"
        
        # Use the same secret as other services
        self.jwt_secret = JWT_SECRET
        self.algorithm = 'HS256'
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup IAP proxy routes"""
        
        @self.app.before_request
        def check_auth():
            """IAP intercepts ALL requests before routing"""
            # Skip authentication for login, callback, health, and static files
            if request.path in ['/', '/login', '/callback', '/health', '/favicon.ico']:
                return None
            
            # Check for JWT token
            auth_header = request.headers.get('Authorization', '')
            jwt_token = request.headers.get('X-IAP-JWT-Assertion', '')
            
            if not jwt_token and auth_header:
                jwt_token = auth_header.replace('Bearer ', '')
            
            if not jwt_token and session.get('jwt'):
                jwt_token = session.get('jwt')
                print(f"🔍 IAP Proxy: Using token from session")
            
            if not jwt_token:
                # Redirect to login
                print(f"🔍 IAP Proxy: No token, redirecting to login")
                return redirect(f'/login?redirect_url={request.url}')
            
            # Validate JWT
            validation = self._validate_jwt(jwt_token)
            if not validation['valid']:
                print(f"🔍 IAP Proxy: Invalid token")
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            # Inject user info into request context
            request.user = validation['payload']
            request.jwt_token = jwt_token
            print(f"🔍 IAP Proxy: User {request.user.get('username')} authenticated")
            
            return None
        
        @self.app.route('/')
        def index():
            return jsonify({
                'service': 'Identity-Aware Proxy (IAP)',
                'status': 'running',
                'version': '3.0',
                'message': 'This is the IAP gatekeeper - all requests must pass through me',
                'architecture': 'IAP + Separate Document Service'
            })
        
        @self.app.route('/login')
        def login():
            """Login page - serve HTML template"""
            redirect_url = request.args.get('redirect_url', '/dashboard')
            return render_template('login.html', redirect_url=redirect_url)
        
        @self.app.route('/callback')
        def callback():
            """OAuth callback"""
            token = request.args.get('token')
            if token:
                session['jwt'] = token
                print(f"🔍 IAP Proxy: Token stored in session")
                redirect_url = request.args.get('redirect_url', '/dashboard')
                return redirect(redirect_url)
            
            return jsonify({'error': 'No token provided'}), 400
        
        @self.app.route('/dashboard')
        def dashboard():
            """Dashboard - serve HTML template with user data"""
            if not hasattr(request, 'user'):
                print(f"🔍 IAP Proxy: No user in request, redirecting to login")
                return redirect('/login')
            
            print(f"🔍 IAP Proxy: Rendering dashboard for {request.user.get('username')}")
            return render_template('dashboard.html', user_data=request.user)
        
        @self.app.route('/api/v1/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def proxy_api(path):
            """Proxy API requests to API Gateway"""
            if not hasattr(request, 'user'):
                print(f"🔍 IAP Proxy: No user in request for API call")
                return jsonify({'error': 'Unauthorized'}), 401
            
            url = f"{self.api_gateway_url}/api/v1/{path}"
            
            # IMPORTANT: Forward the JWT token in the header
            headers = {
                'X-IAP-JWT-Assertion': request.jwt_token,
                'X-User-Clearance': request.user.get('clearance', ''),
                'X-User-Department': request.user.get('department', ''),
                'Content-Type': 'application/json'
            }
            
            print(f"🔍 IAP Proxy: Proxying to {url}")
            print(f"🔍 IAP Proxy: Forwarding token: {request.jwt_token[:50]}...")
            
            try:
                response = requests.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    data=request.get_data(),
                    cookies=request.cookies,
                    verify=False
                )
                
                print(f"✅ IAP Proxy: Response status {response.status_code}")
                return Response(
                    response.content,
                    status=response.status_code,
                    headers=dict(response.headers)
                )
            except requests.exceptions.RequestException as e:
                print(f"❌ IAP Proxy: Proxy error - {e}")
                return jsonify({'error': f'Proxy error: {str(e)}'}), 502
        
        @self.app.route('/health')
        def health():
            return jsonify({'status': 'healthy', 'service': 'IAP Proxy'})
    
    def _validate_jwt(self, token):
        """Validate JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.algorithm])
            print(f"✅ IAP Proxy: JWT validated for user: {payload.get('username')}")
            return {'valid': True, 'payload': payload}
        except jwt.ExpiredSignatureError:
            print("❌ IAP Proxy: JWT expired")
            return {'valid': False, 'error': 'Token expired'}
        except jwt.InvalidTokenError as e:
            print(f"❌ IAP Proxy: JWT invalid - {e}")
            return {'valid': False, 'error': str(e)}
    
    def run(self):
        """Start the IAP proxy server"""
        print(f"🔐 IAP Proxy starting on port {self.port}")
        self.app.run(
            host='127.0.0.1',
            port=self.port,
            ssl_context=('certs/iap.crt', 'certs/iap.key'),
            debug=False,
            threaded=True,
            use_reloader=False
        )