from flask import Flask, request, jsonify
import jwt
import sqlite3
import os
import json
from datetime import datetime, timezone
from functools import wraps
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.rsa_aes import RSA_AES_Encryptor

class APIResourceServer:
    """Protected API server with encrypted resources"""
    
    def __init__(self, port=8502):
        self.app = Flask(__name__)
        self.port = port
        
        # JWT configuration (shared secret with IAP)
        self.jwt_secret = os.environ.get('JWT_SECRET', 'iap-shared-secret')
        
        # RSA+AES encryptor for resources
        self.encryptor = RSA_AES_Encryptor(
            private_key_path='keys/private_key.pem',
            public_key_path='keys/public_key.pem'
        )
        
        # Initialize database
        self._init_database()
        
        self._setup_routes()
    
    def _init_database(self):
        """Initialize SQLite database with encrypted documents"""
        os.makedirs('app/database', exist_ok=True)
        
        conn = sqlite3.connect('app/database/documents.db')
        cursor = conn.cursor()
        
        # Documents table with encrypted content
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                classification TEXT NOT NULL,
                department TEXT NOT NULL,
                encrypted_content TEXT NOT NULL,
                encryption_metadata TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert sample encrypted documents if empty
        cursor.execute('SELECT COUNT(*) FROM documents')
        if cursor.fetchone()[0] == 0:
            sample_docs = [
                ("Strategic Defense Plan 2025", "TOP_SECRET", "defense", 
                 "This document contains Bangladesh's strategic defense positioning for 2025. Key assets: naval fleet expansion, cyber defense command establishment."),
                ("Intelligence Report: Regional Analysis", "TOP_SECRET", "intelligence",
                 "Analysis of regional military movements. Sources indicate increased naval activity in Bay of Bengal. Counter-intelligence operations ongoing."),
                ("Annual Defense Budget", "SECRET", "defense",
                 "Defense budget allocation: $5.2B for procurement, $1.8B for personnel, $900M for R&D."),
                ("Intelligence Operations Manual", "SECRET", "intelligence",
                 "Standard operating procedures for field intelligence officers. Covers surveillance, counter-intelligence, and reporting protocols."),
                ("Public Relations Strategy", "CONFIDENTIAL", "general",
                 "Government communication strategy for upcoming fiscal year. Key messaging and media engagement plans."),
                ("Administrative Guidelines", "BASIC", "general",
                 "General administrative guidelines for government employees. Leave policies, expense reporting, etc."),
                ("Cybersecurity Protocol", "CONFIDENTIAL", "defense",
                 "Internal cybersecurity protocols and incident response procedures."),
                ("Foreign Intelligence Assessment", "TOP_SECRET", "intelligence",
                 "Assessment of foreign intelligence capabilities targeting Bangladesh government networks.")
            ]
            
            for doc in sample_docs:
                title, classification, department, content = doc
                encrypted = self.encryptor.encrypt_resource(content)
                cursor.execute('''
                    INSERT INTO documents (title, classification, department, encrypted_content, encryption_metadata)
                    VALUES (?, ?, ?, ?, ?)
                ''', (title, classification, department, 
                      encrypted['encrypted_data'], 
                      json.dumps({
                          'encrypted_key': encrypted['encrypted_key'],
                          'iv': encrypted['iv'],
                          'tag': encrypted['tag']
                      })))
        
        conn.commit()
        conn.close()
    
    def _verify_jwt(self):
        """Verify JWT from IAP proxy"""
        token = request.headers.get('X-IAP-JWT-Assertion', '')
        if not token:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return None
        
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'],
                                audience='protected-services')
            return payload
        except Exception:
            return None
    
    def _require_auth(self, f):
        """Decorator to verify JWT from IAP"""
        @wraps(f)
        def decorated(*args, **kwargs):
            user = self._verify_jwt()
            if not user:
                return jsonify({'error': 'Unauthorized - Valid JWT required'}), 401
            request.user = user
            return f(*args, **kwargs)
        return decorated
    
    def _check_access(self, user, document):
        """Check if user can access document based on clearance and department"""
        clearance_levels = {'BASIC': 0, 'CONFIDENTIAL': 1, 'SECRET': 2, 'TOP_SECRET': 3}
        
        user_clearance = user.get('clearance', 'BASIC')
        doc_classification = document['classification']
        
        if clearance_levels.get(user_clearance, 0) < clearance_levels.get(doc_classification, 0):
            return False, "Insufficient clearance"
        
        # TOP_SECRET documents require same department
        if doc_classification == 'TOP_SECRET':
            if user.get('department') != document['department']:
                return False, "TOP_SECRET documents require same department access"
            
            # Time restriction for TOP_SECRET (8 AM - 4 PM Bangladesh time)
            current_hour = datetime.now(timezone.utc).hour + 6  # Approximate BDT
            if current_hour < 8 or current_hour > 16:
                return False, "TOP_SECRET documents only accessible between 8 AM - 4 PM"
        
        return True, "Access granted"
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.route('/api/v1/user/dashboard')
        @self._require_auth
        def dashboard():
            return jsonify({
                'user': {
                    'username': request.user.get('username'),
                    'clearance': request.user.get('clearance'),
                    'department': request.user.get('department')
                },
                'message': f"Welcome {request.user.get('username')} - Access granted via IAP"
            })
        
        @self.app.route('/api/v1/documents')
        @self._require_auth
        def get_documents():
            """List all documents user can access"""
            conn = sqlite3.connect('app/database/documents.db')
            cursor = conn.cursor()
            
            cursor.execute('SELECT id, title, classification, department FROM documents')
            all_docs = cursor.fetchall()
            conn.close()
            
            accessible_docs = []
            for doc in all_docs:
                doc_dict = {
                    'id': doc[0],
                    'title': doc[1],
                    'classification': doc[2],
                    'department': doc[3]
                }
                
                access_granted, _ = self._check_access(request.user, doc_dict)
                if access_granted:
                    accessible_docs.append(doc_dict)
            
            return jsonify({
                'documents': accessible_docs,
                'total': len(accessible_docs),
                'user': {
                    'clearance': request.user.get('clearance'),
                    'department': request.user.get('department')
                }
            })
        
        @self.app.route('/api/v1/documents/<int:doc_id>')
        @self._require_auth
        def get_document(doc_id):
            """Get specific document (decrypted)"""
            conn = sqlite3.connect('app/database/documents.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, title, classification, department, encrypted_content, encryption_metadata 
                FROM documents WHERE id = ?
            ''', (doc_id,))
            
            doc = cursor.fetchone()
            conn.close()
            
            if not doc:
                return jsonify({'error': 'Document not found'}), 404
            
            doc_dict = {
                'id': doc[0],
                'title': doc[1],
                'classification': doc[2],
                'department': doc[3],
                'encrypted_content': doc[4],
                'encryption_metadata': json.loads(doc[5])
            }
            
            # Check access
            access_granted, message = self._check_access(request.user, doc_dict)
            if not access_granted:
                return jsonify({'error': message}), 403
            
            # Decrypt content
            decrypted_content = self.encryptor.decrypt_resource({
                'encrypted_key': doc_dict['encryption_metadata']['encrypted_key'],
                'encrypted_data': doc_dict['encrypted_content'],
                'iv': doc_dict['encryption_metadata']['iv'],
                'tag': doc_dict['encryption_metadata']['tag']
            })
            
            return jsonify({
                'id': doc_dict['id'],
                'title': doc_dict['title'],
                'classification': doc_dict['classification'],
                'department': doc_dict['department'],
                'content': decrypted_content,
                'access_message': message
            })
        
        @self.app.route('/health')
        def health():
            return jsonify({'status': 'healthy', 'service': 'API Server'})
        
        @self.app.route('/')
        def index():
            return jsonify({'service': 'Protected API Server', 'status': 'running via IAP'})
    
    def run(self):
        """Start API server"""
        self.app.run(
            host='127.0.0.1',
            port=self.port,
            ssl_context=('certs/api.crt', 'certs/api.key'),
            debug=True,
            threaded=True
        )