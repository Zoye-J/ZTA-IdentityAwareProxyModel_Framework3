from flask import Flask, request, jsonify
import jwt
import sqlite3
import os
import json
from datetime import datetime, timezone
from functools import wraps
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from app.crypto.rsa_aes import RSA_AES_Encryptor

class DocumentService:
    """Standalone Document Service with RSA+AES encryption"""
    
    def __init__(self, port=8503):
        self.app = Flask(__name__)
        self.port = port
        
        # JWT configuration (shared secret with IAP)
        self.jwt_secret = os.environ.get('JWT_SECRET', 'iap-shared-secret-change-this-in-production')
        
        # Check if RSA keys exist, generate if not
        if not os.path.exists('keys/private_key.pem') or not os.path.exists('keys/public_key.pem'):
            print("⚠️ RSA keys not found, generating...")
            os.makedirs('keys', exist_ok=True)
            encryptor_temp = RSA_AES_Encryptor()
            encryptor_temp.generate_keys()
        
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
                 "This document contains Bangladesh's strategic defense positioning for 2025."),
                ("Intelligence Report: Regional Analysis", "TOP_SECRET", "intelligence",
                 "Analysis of regional military movements in the Bay of Bengal."),
                ("Annual Defense Budget", "SECRET", "defense",
                 "Defense budget allocation for the fiscal year."),
                ("Intelligence Operations Manual", "SECRET", "intelligence",
                 "Standard operating procedures for field intelligence officers."),
                ("Public Relations Strategy", "CONFIDENTIAL", "general",
                 "Government communication strategy for upcoming fiscal year."),
                ("Administrative Guidelines", "BASIC", "general",
                 "General administrative guidelines for government employees."),
                ("Cybersecurity Protocol", "CONFIDENTIAL", "defense",
                 "Internal cybersecurity protocols and incident response procedures."),
                ("Foreign Intelligence Assessment", "TOP_SECRET", "intelligence",
                 "Assessment of foreign intelligence capabilities.")
            ]
            
            for doc in sample_docs:
                title, classification, department, content = doc
                try:
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
                except Exception as e:
                    print(f"Error encrypting document {title}: {e}")
            
            conn.commit()
            print(f"✅ Document Service: Database initialized with {len(sample_docs)} encrypted documents")
        
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
                                options={'verify_aud': False})
            return payload
        except Exception as e:
            print(f"Document Service - JWT verification error: {e}")
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
        
        return True, "Access granted"
    
    def _setup_routes(self):
        """Setup document service routes"""
        
        @self.app.route('/documents', methods=['GET'])
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
                    'username': request.user.get('username'),
                    'clearance': request.user.get('clearance'),
                    'department': request.user.get('department')
                }
            })
        
        @self.app.route('/documents/<int:doc_id>', methods=['GET'])
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
            try:
                decrypted_content = self.encryptor.decrypt_resource({
                    'encrypted_key': doc_dict['encryption_metadata']['encrypted_key'],
                    'encrypted_data': doc_dict['encrypted_content'],
                    'iv': doc_dict['encryption_metadata']['iv'],
                    'tag': doc_dict['encryption_metadata']['tag']
                })
            except Exception as e:
                return jsonify({'error': f'Decryption failed: {str(e)}'}), 500
            
            return jsonify({
                'id': doc_dict['id'],
                'title': doc_dict['title'],
                'classification': doc_dict['classification'],
                'department': doc_dict['department'],
                'content': decrypted_content,
                'access_message': message
            })
        
        @self.app.route('/health', methods=['GET'])
        def health():
            return jsonify({
                'status': 'healthy', 
                'service': 'Document Service',
                'encryption': 'RSA+AES Hybrid'
            })
        
        @self.app.route('/', methods=['GET'])
        def index():
            return jsonify({
                'service': 'Document Service',
                'status': 'running',
                'endpoints': ['/documents', '/documents/<id>', '/health']
            })
    
    def run(self):
        """Start document service"""
        print(f"📄 Document Service starting on port {self.port}")
        try:
            self.app.run(
                host='127.0.0.1',
                port=self.port,
                ssl_context=('certs/api.crt', 'certs/api.key'),
                debug=False,  
                threaded=True,
                use_reloader=False  
            )
        except Exception as e:
            print(f"❌ Failed to start Document Service: {e}")
            raise