from flask import Flask, request, Response, jsonify, session, redirect, url_for
import requests
import jwt
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

class IAPProxy:
    """Identity-Aware Proxy - The main gatekeeper"""
    
    def __init__(self, port=8443):
        self.app = Flask(__name__)
        self.app.secret_key = os.environ.get('FLASK_SECRET', 'iap-proxy-secret')
        self.port = port
        
        # Service endpoints (all internal)
        self.auth_service_url = "https://localhost:8501"  # Auth Server
        self.api_service_url = "https://localhost:8502"   # API Server
        self.policy_service_url = "http://localhost:8503" # Policy Server (OPA)
        
        # JWT configuration
        self.jwt_secret = os.environ.get('JWT_SECRET', 'iap-shared-secret')
        self.algorithm = 'HS256'
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup IAP proxy routes"""
        
        @self.app.before_request
        def check_auth():
            """IAP intercepts ALL requests before routing"""
            # Skip authentication for login page and static assets
            if request.path in ['/', '/login', '/callback', '/health']:
                return None
            
            # Check for existing session or JWT
            auth_header = request.headers.get('Authorization', '')
            jwt_token = request.headers.get('X-IAP-JWT-Assertion', '')
            
            if not jwt_token and auth_header:
                jwt_token = auth_header.replace('Bearer ', '')
            
            if not jwt_token and session.get('user'):
                # Generate new JWT from session
                jwt_token = self._generate_jwt_from_session(session['user'])
            
            if not jwt_token:
                # Redirect to login
                return redirect(url_for('login', redirect_url=request.url))
            
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
            return jsonify({
                'service': 'Identity-Aware Proxy (IAP)',
                'status': 'running',
                'version': '3.0',
                'message': 'This is the IAP gatekeeper - all requests must pass through me'
            })
        
        @self.app.route('/login')
        def login():
            """Login page - redirects to auth service"""
            redirect_url = request.args.get('redirect_url', '/dashboard')
            return self._render_login_page(redirect_url)
        
        @self.app.route('/callback')
        def callback():
            """OAuth callback from auth service"""
            code = request.args.get('code')
            if not code:
                return jsonify({'error': 'No authorization code'}), 400
            
            # Exchange code for user info from auth service
            response = requests.post(
                f"{self.auth_service_url}/token",
                json={'code': code},
                verify=False  # Disable SSL verification for dev
            )
            
            if response.status_code != 200:
                return jsonify({'error': 'Authentication failed'}), 401
            
            user_data = response.json()
            
            # Generate JWT token
            jwt_token = self._generate_jwt(user_data)
            
            # Store in session
            session['user'] = user_data
            session['jwt'] = jwt_token
            
            redirect_url = request.args.get('redirect_url', '/dashboard')
            return redirect(f"{redirect_url}?token={jwt_token}")
        
        @self.app.route('/dashboard')
        def dashboard():
            """Protected dashboard - proxied to API server"""
            if not hasattr(request, 'user'):
                return redirect(url_for('login', redirect_url='/dashboard'))
            
            # Forward request to API server
            return self._proxy_request('/api/v1/user/dashboard')
        
        @self.app.route('/api/v1/documents')
        def get_documents():
            """Proxy document list request to API server"""
            if not hasattr(request, 'user'):
                return jsonify({'error': 'Unauthorized'}), 401
            
            return self._proxy_request('/api/v1/documents')
        
        @self.app.route('/api/v1/documents/<int:doc_id>')
        def get_document(doc_id):
            """Proxy single document request"""
            if not hasattr(request, 'user'):
                return jsonify({'error': 'Unauthorized'}), 401
            
            return self._proxy_request(f'/api/v1/documents/{doc_id}')
        
        @self.app.route('/health')
        def health():
            return jsonify({'status': 'healthy', 'service': 'IAP'})
        
        # Catch-all route for all other requests
        @self.app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
        @self.app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def catch_all(path):
            """Proxy all other requests to the appropriate backend"""
            if not hasattr(request, 'user') and path not in ['login', 'callback', 'health']:
                return redirect(url_for('login', redirect_url=request.url))
            
            # Determine target service based on path
            if path.startswith('api/'):
                return self._proxy_request(f'/{path}', self.api_service_url)
            else:
                return self._proxy_request(f'/{path}', self.api_service_url)
    
    def _generate_jwt(self, user_data):
        """Generate JWT token for authenticated user"""
        payload = {
            'user_id': user_data.get('user_id'),
            'username': user_data.get('username'),
            'clearance': user_data.get('clearance', 'BASIC'),
            'department': user_data.get('department', 'general'),
            'email': user_data.get('email', ''),
            'exp': datetime.now(timezone.utc) + timedelta(hours=8),
            'iat': datetime.now(timezone.utc),
            'iss': 'iap-proxy',
            'aud': 'protected-services'
        }
        return jwt.encode(payload, self.jwt_secret, algorithm=self.algorithm)
    
    def _generate_jwt_from_session(self, user_data):
        """Generate JWT from session data"""
        return self._generate_jwt(user_data)
    
    def _validate_jwt(self, token):
        """Validate JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.algorithm], 
                                audience='protected-services')
            return {'valid': True, 'payload': payload}
        except jwt.ExpiredSignatureError:
            return {'valid': False, 'error': 'Token expired'}
        except jwt.InvalidTokenError as e:
            return {'valid': False, 'error': str(e)}
    
    def _render_login_page(self, redirect_url):
        """Render HTML login page"""
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>IAP Login - Identity-Aware Proxy</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    margin: 0;
                }}
                .login-container {{
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    text-align: center;
                    width: 350px;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 10px;
                }}
                .subtitle {{
                    color: #666;
                    margin-bottom: 30px;
                    font-size: 14px;
                }}
                .btn-login {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    padding: 12px 30px;
                    border-radius: 5px;
                    font-size: 16px;
                    cursor: pointer;
                    width: 100%;
                    margin-bottom: 10px;
                }}
                .btn-login:hover {{
                    opacity: 0.9;
                }}
                .user-card {{
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 15px 0;
                    cursor: pointer;
                    transition: all 0.3s;
                }}
                .user-card:hover {{
                    background: #f5f5f5;
                    border-color: #667eea;
                }}
                .user-name {{
                    font-weight: bold;
                    color: #333;
                }}
                .user-clearance {{
                    font-size: 12px;
                    color: #666;
                    margin-top: 5px;
                }}
                .badge {{
                    display: inline-block;
                    padding: 2px 8px;
                    border-radius: 4px;
                    font-size: 10px;
                    font-weight: bold;
                    margin-left: 8px;
                }}
                .badge-basic {{ background: #4CAF50; color: white; }}
                .badge-confidential {{ background: #FF9800; color: white; }}
                .badge-secret {{ background: #f44336; color: white; }}
                .badge-top_secret {{ background: #9C27B0; color: white; }}
            </style>
        </head>
        <body>
            <div class="login-container">
                <h1>🔐 IAP Login</h1>
                <div class="subtitle">Identity-Aware Proxy - Zero Trust Access</div>
                
                <div id="users">
                    <div class="user-card" onclick="loginAs('intelligence_officer', 'TOP_SECRET', 'intelligence')">
                        <div class="user-name">Sarah Chen <span class="badge badge-top_secret">TOP_SECRET</span></div>
                        <div class="user-clearance">Intelligence Department</div>
                    </div>
                    <div class="user-card" onclick="loginAs('defense_staff', 'SECRET', 'defense')">
                        <div class="user-name">James Bond <span class="badge badge-secret">SECRET</span></div>
                        <div class="user-clearance">Defense Department</div>
                    </div>
                    <div class="user-card" onclick="loginAs('general_user', 'BASIC', 'general')">
                        <div class="user-name">John Doe <span class="badge badge-basic">BASIC</span></div>
                        <div class="user-clearance">General Department</div>
                    </div>
                </div>
                
                <button class="btn-login" onclick="manualLogin()">Login with Credentials</button>
            </div>
            
            <script>
                const REDIRECT_URL = '{redirect_url}';
                
                async function loginAs(username, clearance, department) {{
                    const response = await fetch('{self.auth_service_url}/auth/manual', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ username, clearance, department }})
                    }});
                    
                    const data = await response.json();
                    if (data.token) {{
                        window.location.href = REDIRECT_URL + '?token=' + data.token;
                    }}
                }}
                
                function manualLogin() {{
                    const username = prompt('Enter username:');
                    const password = prompt('Enter password:');
                    if (username && password) {{
                        fetch('{self.auth_service_url}/auth/login', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ username, password }})
                        }})
                        .then(res => res.json())
                        .then(data => {{
                            if (data.token) {{
                                window.location.href = REDIRECT_URL + '?token=' + data.token;
                            }}
                        }});
                    }}
                }}
            </script>
        </body>
        </html>
        '''
    
    def _proxy_request(self, target_path, target_url=None):
        """Forward request to target service with JWT injection"""
        if target_url is None:
            target_url = self.api_service_url
        
        url = f"{target_url}{target_path}"
        
        # Prepare headers - INJECT JWT token (IAP standard)
        headers = dict(request.headers)
        headers['X-IAP-JWT-Assertion'] = request.jwt_token if hasattr(request, 'jwt_token') else ''
        headers['X-Original-User'] = request.user.get('username', '') if hasattr(request, 'user') else ''
        headers['X-User-Clearance'] = request.user.get('clearance', '') if hasattr(request, 'user') else ''
        headers['X-User-Department'] = request.user.get('department', '') if hasattr(request, 'user') else ''
        
        # Forward the request
        try:
            response = requests.request(
                method=request.method,
                url=url,
                headers=headers,
                data=request.get_data(),
                cookies=request.cookies,
                verify=False  # Disable SSL verification for dev
            )
            
            # Return the response back to client
            return Response(
                response.content,
                status=response.status_code,
                headers=dict(response.headers)
            )
        except requests.exceptions.RequestException as e:
            return jsonify({'error': f'Proxy error: {str(e)}'}), 502
    
    def run(self):
        """Start the IAP proxy server"""
        self.app.run(
            host='127.0.0.1',
            port=self.port,
            ssl_context=('certs/iap.crt', 'certs/iap.key'),
            debug=True,
            threaded=True
        )