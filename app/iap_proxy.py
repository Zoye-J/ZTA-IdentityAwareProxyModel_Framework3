from flask import Flask, request, Response, jsonify, session, redirect, render_template
from app.config import JWT_SECRET, INTERNAL_API_TOKEN, FLASK_SECRET
import requests
import jwt
import os
from datetime import datetime, timedelta, timezone


# Use the SAME secret across all services


class IAPProxy:
    """Identity-Aware Proxy - The main gatekeeper"""
    
    def __init__(self, port=8443):
        self.app = Flask(__name__, template_folder='templates')
        self.app.secret_key = FLASK_SECRET 
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
            # Skip authentication for root (login page), callback, health, and static files
            # Also skip if user is already trying to login
            if request.path in ['/', '/callback', '/health', '/favicon.ico']:
                return None
            
            # Check for JWT token
            auth_header = request.headers.get('Authorization', '')
            jwt_token = request.headers.get('X-IAP-JWT-Assertion', '')
            
            if not jwt_token and auth_header:
                jwt_token = auth_header.replace('Bearer ', '')
            
            if not jwt_token and session.get('jwt'):
                jwt_token = session.get('jwt')
            
            if not jwt_token:
                # Redirect to root (login page)
                return redirect(f'/?redirect_url={request.url}')
            
            # Validate JWT
            validation = self._validate_jwt(jwt_token)
            if not validation['valid']:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            # Inject user info into request context
            request.user = validation['payload']
            request.jwt_token = jwt_token
            
            return None
        
        @self.app.route('/')
        def index():
            """Root path - serves login page or redirects to dashboard if already authenticated"""
            # Check if user is already authenticated via session
            if session.get('jwt'):
                jwt_token = session.get('jwt')
                validation = self._validate_jwt(jwt_token)
                if validation['valid']:
                    # User is already logged in, redirect to dashboard
                    return redirect('/dashboard')
            
            # Otherwise show login page
            redirect_url = request.args.get('redirect_url', '/dashboard')
            return render_template('login.html', redirect_url=redirect_url)
        
        @self.app.route('/login')
        def login_redirect():
            """Redirect old /login path to root"""
            redirect_url = request.args.get('redirect_url', '/dashboard')
            return redirect(f'/?redirect_url={redirect_url}')
        
        @self.app.route('/callback')
        def callback():
            """OAuth callback"""
            token = request.args.get('token')
            if token:
                session['jwt'] = token
                redirect_url = request.args.get('redirect_url', '/dashboard')
                return redirect(redirect_url)
            
            return jsonify({'error': 'No token provided'}), 400
        
        @self.app.route('/dashboard')
        def dashboard():
            """Dashboard - serve HTML template with user data"""
            if not hasattr(request, 'user'):
                # Check session for token
                if session.get('jwt'):
                    jwt_token = session.get('jwt')
                    validation = self._validate_jwt(jwt_token)
                    if validation['valid']:
                        request.user = validation['payload']
                        request.jwt_token = jwt_token
                    else:
                        session.pop('jwt', None)
                        return redirect('/')
                else:
                    return redirect('/')
            
            return render_template('dashboard.html', user_data=request.user)
        
        @self.app.route('/api/v1/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def proxy_api(path):
            """Proxy API requests to API Gateway"""
            if not hasattr(request, 'user'):
                if session.get('jwt'):
                    jwt_token = session.get('jwt')
                    validation = self._validate_jwt(jwt_token)
                    if validation['valid']:
                        request.user = validation['payload']
                        request.jwt_token = jwt_token
                    else:
                        session.pop('jwt', None)
                        return jsonify({'error': 'Unauthorized'}), 401
                else:
                    return jsonify({'error': 'Unauthorized'}), 401
            
            url = f"{self.api_gateway_url}/api/v1/{path}"
            
            # Add internal token for service-to-service auth
            headers = {
                'X-IAP-JWT-Assertion': request.jwt_token,
                'X-Internal-Token': INTERNAL_API_TOKEN,
                'X-User-Clearance': request.user.get('clearance', ''),
                'X-User-Department': request.user.get('department', ''),
                'Content-Type': 'application/json'
            }
            
            print(f"🔍 IAP Proxy: Proxying to {url}")
            
            # Use a session with SSL verification disabled for internal communication
            try:
                # Create a session that ignores SSL verification for localhost
                session = requests.Session()
                session.verify = False
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
                response = session.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    data=request.get_data(),
                    cookies=request.cookies
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
        
        @self.app.route('/logout')
        def logout():
            """Logout endpoint"""
            session.pop('jwt', None)
            return redirect('/')
    
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
