from flask import Flask, request, jsonify
import jwt
import sqlite3
import os
import secrets
from datetime import datetime, timedelta, timezone

class AuthServer:
    """Authentication Service - OIDC/OAuth2 compatible"""
    
    def __init__(self, port=8501):
        self.app = Flask(__name__)
        self.port = port
        
        self.jwt_secret = os.environ.get('JWT_SECRET', 'iap-shared-secret')
        
        self._init_database()
        self._setup_routes()
    
    def _init_database(self):
        """Initialize user database"""
        os.makedirs('app/database', exist_ok=True)
        
        conn = sqlite3.connect('app/database/users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                clearance TEXT NOT NULL,
                department TEXT NOT NULL,
                email TEXT
            )
        ''')
        
        # Insert sample users
        sample_users = [
            ('intelligence_officer', 'pass123', 'TOP_SECRET', 'intelligence', 'sarah.chen@intelligence.gov.bd'),
            ('defense_staff', 'pass123', 'SECRET', 'defense', 'james.bond@defense.gov.bd'),
            ('general_user', 'pass123', 'BASIC', 'general', 'john.doe@gov.bd')
        ]
        
        for user in sample_users:
            cursor.execute('''
                INSERT OR IGNORE INTO users (username, password, clearance, department, email)
                VALUES (?, ?, ?, ?, ?)
            ''', user)
        
        conn.commit()
        conn.close()
    
    def _setup_routes(self):
        
        @self.app.route('/auth/login', methods=['POST'])
        def login():
            """Password-based login"""
            data = request.json
            username = data.get('username')
            password = data.get('password')
            
            conn = sqlite3.connect('app/database/users.db')
            cursor = conn.cursor()
            
            cursor.execute('SELECT id, username, clearance, department, email FROM users WHERE username = ? AND password = ?',
                          (username, password))
            user = cursor.fetchone()
            conn.close()
            
            if not user:
                return jsonify({'error': 'Invalid credentials'}), 401
            
            user_data = {
                'user_id': user[0],
                'username': user[1],
                'clearance': user[2],
                'department': user[3],
                'email': user[4]
            }
            
            # Generate JWT token for IAP
            token = self._generate_auth_token(user_data)
            
            return jsonify({
                'token': token,
                'user': user_data
            })
        
        @self.app.route('/auth/manual', methods=['POST'])
        def manual_auth():
            """Manual authentication for demo"""
            data = request.json
            user_data = {
                'user_id': 999,
                'username': data.get('username'),
                'clearance': data.get('clearance', 'BASIC'),
                'department': data.get('department', 'general'),
                'email': f"{data.get('username')}@gov.bd"
            }
            
            token = self._generate_auth_token(user_data)
            return jsonify({'token': token, 'user': user_data})
        
        @self.app.route('/token', methods=['POST'])
        def exchange_token():
            """OAuth token exchange endpoint"""
            code = request.json.get('code')
            # In production, validate code against stored state
            return jsonify({
                'user_id': 1,
                'username': 'authenticated_user',
                'clearance': 'BASIC',
                'department': 'general'
            })
        
        @self.app.route('/health')
        def health():
            return jsonify({'status': 'healthy', 'service': 'Auth Server'})
    
    def _generate_auth_token(self, user_data):
        """Generate authentication token"""
        payload = {
            'sub': user_data['username'],
            'user_id': user_data['user_id'],
            'clearance': user_data['clearance'],
            'department': user_data['department'],
            'email': user_data['email'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=8),
            'iat': datetime.now(timezone.utc),
            'iss': 'auth-service'
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def run(self):
        self.app.run(
            host='127.0.0.1',
            port=self.port,
            ssl_context=('certs/iap.crt', 'certs/iap.key'),
            debug=False, 
            threaded=True,
            use_reloader=False  
        )