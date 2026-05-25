from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import sqlite3
import os
from datetime import datetime, timedelta, timezone

# Use the SAME secret across all services
JWT_SECRET = "iap-shared-secret-framework3-2025"

class AuthServer:
    """Authentication Service - OIDC/OAuth2 compatible"""
    
    def __init__(self, port=8501):
        self.app = Flask(__name__)
        CORS(self.app, origins=['https://localhost:8443', 'https://localhost:8501', 'https://localhost:8502', 'https://localhost:8503'])
        self.port = port
        
        # Use the same secret as other services
        self.jwt_secret = JWT_SECRET
        
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
            (1, 'intelligence_officer', 'pass123', 'TOP_SECRET', 'intelligence', 'sarah.chen@intelligence.gov.bd'),
            (2, 'defense_staff', 'pass123', 'SECRET', 'defense', 'james.bond@defense.gov.bd'),
            (3, 'general_user', 'pass123', 'BASIC', 'general', 'john.doe@gov.bd')
        ]
        
        for user in sample_users:
            cursor.execute('''
                INSERT OR IGNORE INTO users (id, username, password, clearance, department, email)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', user)
        
        conn.commit()
        conn.close()
        print("✅ Auth Server: Database initialized")
    
    def _setup_routes(self):
        
        @self.app.route('/auth/login', methods=['POST', 'OPTIONS'])
        def login():
            """Password-based login"""
            if request.method == 'OPTIONS':
                response = jsonify({})
                response.headers['Access-Control-Allow-Origin'] = 'https://localhost:8443'
                response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                return response, 200
            
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
            
            # Generate JWT token
            token = self._generate_auth_token(user_data)
            
            response = jsonify({
                'token': token,
                'user': user_data
            })
            response.headers['Access-Control-Allow-Origin'] = 'https://localhost:8443'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        @self.app.route('/auth/manual', methods=['POST', 'OPTIONS'])
        def manual_auth():
            """Manual authentication for demo"""
            if request.method == 'OPTIONS':
                response = jsonify({})
                response.headers['Access-Control-Allow-Origin'] = 'https://localhost:8443'
                response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                return response, 200
            
            data = request.json
            user_data = {
                'user_id': 999,
                'username': data.get('username'),
                'clearance': data.get('clearance', 'BASIC'),
                'department': data.get('department', 'general'),
                'email': f"{data.get('username')}@gov.bd"
            }
            
            token = self._generate_auth_token(user_data)
            
            response = jsonify({'token': token, 'user': user_data})
            response.headers['Access-Control-Allow-Origin'] = 'https://localhost:8443'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        @self.app.route('/health', methods=['GET', 'OPTIONS'])
        def health():
            if request.method == 'OPTIONS':
                response = jsonify({})
                response.headers['Access-Control-Allow-Origin'] = 'https://localhost:8443'
                return response, 200
            return jsonify({'status': 'healthy', 'service': 'Auth Server'})
    
    def _generate_auth_token(self, user_data):
        """Generate authentication token with consistent secret"""
        payload = {
            'user_id': user_data['user_id'],
            'username': user_data['username'],
            'clearance': user_data['clearance'],
            'department': user_data['department'],
            'email': user_data['email'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=8),
            'iat': datetime.now(timezone.utc),
            'iss': 'auth-service'
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def run(self):
        print(f"🔐 Auth Server starting on port {self.port}")
        self.app.run(
            host='127.0.0.1',
            port=self.port,
            ssl_context=('certs/iap.crt', 'certs/iap.key'),
            debug=False,
            threaded=True,
            use_reloader=False
        )


# For direct testing
if __name__ == "__main__":
    server = AuthServer(port=8501)
    server.run()