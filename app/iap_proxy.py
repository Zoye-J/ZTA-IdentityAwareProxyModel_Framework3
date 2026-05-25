from flask import Flask, request, Response, jsonify, session, redirect
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
        self.auth_service_url = "https://localhost:8501"
        self.api_gateway_url = "https://localhost:8502"
        
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
            
            # Check for JWT token
            auth_header = request.headers.get('Authorization', '')
            jwt_token = request.headers.get('X-IAP-JWT-Assertion', '')
            
            if not jwt_token and auth_header:
                jwt_token = auth_header.replace('Bearer ', '')
            
            if not jwt_token and session.get('jwt'):
                jwt_token = session.get('jwt')
            
            if not jwt_token:
                # Redirect to login
                return redirect(f'/login?redirect_url={request.url}')
            
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
                'message': 'This is the IAP gatekeeper - all requests must pass through me',
                'architecture': 'IAP + Separate Document Service'
            })
        
        @self.app.route('/login')
        def login():
            """Login page"""
            redirect_url = request.args.get('redirect_url', '/dashboard')
            return self._render_login_page(redirect_url)
        
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
            """Dashboard"""
            return self._render_dashboard_page()
        
        @self.app.route('/api/v1/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def proxy_api(path):
            """Proxy API requests to API Gateway"""
            if not hasattr(request, 'user'):
                return jsonify({'error': 'Unauthorized'}), 401
            
            url = f"{self.api_gateway_url}/api/v1/{path}"
            
            headers = dict(request.headers)
            headers['X-IAP-JWT-Assertion'] = request.jwt_token
            headers['X-User-Clearance'] = request.user.get('clearance', '')
            headers['X-User-Department'] = request.user.get('department', '')
            
            try:
                response = requests.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    data=request.get_data(),
                    cookies=request.cookies,
                    verify=False
                )
                
                return Response(
                    response.content,
                    status=response.status_code,
                    headers=dict(response.headers)
                )
            except requests.exceptions.RequestException as e:
                return jsonify({'error': f'Proxy error: {str(e)}'}), 502
        
        @self.app.route('/health')
        def health():
            return jsonify({'status': 'healthy', 'service': 'IAP Proxy'})
    
    def _generate_jwt(self, user_data):
        """Generate JWT token"""
        payload = {
            'user_id': user_data.get('user_id'),
            'username': user_data.get('username'),
            'clearance': user_data.get('clearance', 'BASIC'),
            'department': user_data.get('department', 'general'),
            'email': user_data.get('email', ''),
            'exp': datetime.now(timezone.utc) + timedelta(hours=8),
            'iat': datetime.now(timezone.utc),
            'iss': 'iap-proxy'
        }
        return jwt.encode(payload, self.jwt_secret, algorithm=self.algorithm)
    
    def _validate_jwt(self, token):
        """Validate JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.algorithm])
            return {'valid': True, 'payload': payload}
        except jwt.ExpiredSignatureError:
            return {'valid': False, 'error': 'Token expired'}
        except jwt.InvalidTokenError as e:
            return {'valid': False, 'error': str(e)}
    
    def _render_login_page(self, redirect_url):
        """Render login page"""
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>IAP Login - Identity-Aware Proxy</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
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
                    width: 400px;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 10px;
                    text-align: center;
                }}
                .subtitle {{
                    color: #666;
                    margin-bottom: 30px;
                    text-align: center;
                    font-size: 14px;
                }}
                .user-card {{
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 10px 0;
                    cursor: pointer;
                    transition: all 0.3s;
                }}
                .user-card:hover {{
                    background: #f5f5f5;
                    border-color: #667eea;
                    transform: translateX(5px);
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
                .btn-login {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    padding: 12px;
                    border-radius: 5px;
                    font-size: 16px;
                    cursor: pointer;
                    width: 100%;
                    margin-top: 10px;
                }}
                .btn-login:hover {{
                    opacity: 0.9;
                }}
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
                const AUTH_URL = 'https://localhost:8501';
                
                async function loginAs(username, clearance, department) {{
                    try {{
                        const response = await fetch(`${{AUTH_URL}}/auth/manual`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ username, clearance, department }})
                        }});
                        
                        const data = await response.json();
                        if (data.token) {{
                            window.location.href = `/callback?token=${{data.token}}&redirect_url=${{REDIRECT_URL}}`;
                        }}
                    }} catch (error) {{
                        console.error('Login error:', error);
                        alert('Login failed. Make sure auth server is running.');
                    }}
                }}
                
                async function manualLogin() {{
                    const username = prompt('Enter username:');
                    const password = prompt('Enter password:');
                    if (username && password) {{
                        try {{
                            const response = await fetch(`${{AUTH_URL}}/auth/login`, {{
                                method: 'POST',
                                headers: {{ 'Content-Type': 'application/json' }},
                                body: JSON.stringify({{ username, password }})
                            }});
                            
                            const data = await response.json();
                            if (data.token) {{
                                window.location.href = `/callback?token=${{data.token}}&redirect_url=${{REDIRECT_URL}}`;
                            }} else {{
                                alert('Login failed: ' + (data.error || 'Unknown error'));
                            }}
                        }} catch (error) {{
                            console.error('Login error:', error);
                            alert('Login failed. Make sure auth server is running.');
                        }}
                    }}
                }}
            </script>
        </body>
        </html>
        '''
    
    def _render_dashboard_page(self):
        """Render dashboard"""
        user = getattr(request, 'user', {})
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>IAP Dashboard</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #f5f5f5;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                }}
                .user-info {{
                    background: white;
                    padding: 20px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .documents {{
                    background: white;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .doc-card {{
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 10px 0;
                    cursor: pointer;
                    transition: all 0.3s;
                }}
                .doc-card:hover {{
                    background: #f9f9f9;
                    border-color: #667eea;
                }}
                .doc-title {{
                    font-weight: bold;
                    color: #333;
                }}
                .doc-class {{
                    font-size: 12px;
                    display: inline-block;
                    padding: 2px 8px;
                    border-radius: 4px;
                    margin-left: 10px;
                }}
                .modal {{
                    display: none;
                    position: fixed;
                    z-index: 1000;
                    left: 0;
                    top: 0;
                    width: 100%;
                    height: 100%;
                    background-color: rgba(0,0,0,0.5);
                }}
                .modal-content {{
                    background-color: white;
                    margin: 10% auto;
                    padding: 20px;
                    border-radius: 10px;
                    width: 60%;
                    max-width: 600px;
                }}
                .close {{
                    color: #aaa;
                    float: right;
                    font-size: 28px;
                    font-weight: bold;
                    cursor: pointer;
                }}
                .close:hover {{
                    color: black;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Identity-Aware Proxy Dashboard</h1>
                    <p>Framework 3 - IAP Model with Separate Document Service</p>
                </div>
                
                <div class="user-info">
                    <h3>👤 User Information</h3>
                    <p><strong>Username:</strong> {user.get('username', 'Unknown')}</p>
                    <p><strong>Clearance:</strong> <span class="doc-class" style="background: #9C27B0; color: white;">{user.get('clearance', 'BASIC')}</span></p>
                    <p><strong>Department:</strong> {user.get('department', 'general')}</p>
                </div>
                
                <div class="documents">
                    <h3>📄 Available Documents</h3>
                    <div id="doc-list">Loading documents...</div>
                </div>
            </div>
            
            <div id="doc-modal" class="modal">
                <div class="modal-content">
                    <span class="close">&times;</span>
                    <h3 id="modal-title"></h3>
                    <p id="modal-classification"></p>
                    <hr>
                    <p id="modal-content"></p>
                </div>
            </div>
            
            <script>
                const API_URL = '/api/v1';
                
                async function loadDocuments() {{
                    try {{
                        const response = await fetch(`${{API_URL}}/documents`);
                        const data = await response.json();
                        
                        if (data.documents && data.documents.length > 0) {{
                            const docList = document.getElementById('doc-list');
                            docList.innerHTML = '';
                            
                            data.documents.forEach(doc => {{
                                const docCard = document.createElement('div');
                                docCard.className = 'doc-card';
                                docCard.onclick = () => viewDocument(doc.id);
                                
                                let classColor = '#4CAF50';
                                if (doc.classification === 'CONFIDENTIAL') classColor = '#FF9800';
                                if (doc.classification === 'SECRET') classColor = '#f44336';
                                if (doc.classification === 'TOP_SECRET') classColor = '#9C27B0';
                                
                                docCard.innerHTML = `
                                    <div class="doc-title">
                                        ${{doc.title}}
                                        <span class="doc-class" style="background: ${{classColor}}; color: white;">
                                            ${{doc.classification}}
                                        </span>
                                    </div>
                                    <div class="user-clearance">Department: ${{doc.department}}</div>
                                `;
                                docList.appendChild(docCard);
                            }});
                        }} else {{
                            document.getElementById('doc-list').innerHTML = '<p>No documents available with your clearance level.</p>';
                        }}
                    }} catch (error) {{
                        console.error('Error loading documents:', error);
                        document.getElementById('doc-list').innerHTML = '<p>Error loading documents. Make sure services are running.</p>';
                    }}
                }}
                
                async function viewDocument(docId) {{
                    try {{
                        const response = await fetch(`${{API_URL}}/documents/${{docId}}`);
                        const doc = await response.json();
                        
                        document.getElementById('modal-title').textContent = doc.title;
                        document.getElementById('modal-classification').innerHTML = 
                            `<strong>Classification:</strong> ${{doc.classification}} | <strong>Department:</strong> ${{doc.department}}`;
                        document.getElementById('modal-content').textContent = doc.content;
                        
                        document.getElementById('doc-modal').style.display = 'block';
                    }} catch (error) {{
                        console.error('Error loading document:', error);
                        alert('Error loading document: ' + error.message);
                    }}
                }}
                
                // Modal close functionality
                const modal = document.getElementById('doc-modal');
                const closeBtn = document.getElementsByClassName('close')[0];
                
                closeBtn.onclick = function() {{
                    modal.style.display = 'none';
                }}
                
                window.onclick = function(event) {{
                    if (event.target == modal) {{
                        modal.style.display = 'none';
                    }}
                }}
                
                // Load documents on page load
                loadDocuments();
            </script>
        </body>
        </html>
        '''
    
    def run(self):
        """Start the IAP proxy server"""
        print(f"🔐 IAP Proxy starting on port {self.port}")
        self.app.run(
            host='127.0.0.1',
            port=self.port,
            ssl_context=('certs/iap.crt', 'certs/iap.key'),
            debug=False,  # Changed to False
            threaded=True,
            use_reloader=False  # Add this
        )