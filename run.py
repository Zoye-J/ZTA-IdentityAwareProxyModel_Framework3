#!/usr/bin/env python
"""
Framework 3: Identity-Aware Proxy (IAP) Model
Zero Trust Architecture with IAP + RSA+AES Encryption + Separate Document Service
"""

import os
import sys
import time
import threading
import webbrowser

from app.config import ENVIRONMENT, DEBUG, FLASK_SECRET

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def generate_certificates():
    """Generate self-signed certificates for HTTPS"""
    os.makedirs('certs', exist_ok=True)
    
    if os.path.exists('certs/iap.crt') and os.path.exists('certs/iap.key'):
        # Check if files are not empty
        if os.path.getsize('certs/iap.crt') > 0 and os.path.getsize('certs/iap.key') > 0:
            print("✅ Certificates already exist")
            return
    
    print("🔐 Generating SSL certificates...")
    
    from OpenSSL import crypto
    
    def generate_cert(cert_path, key_path, common_name="localhost"):
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        cert = crypto.X509()
        cert.get_subject().C = "BD"
        cert.get_subject().ST = "Dhaka"
        cert.get_subject().L = "Dhaka"
        cert.get_subject().O = "ZTA Research"
        cert.get_subject().OU = "Framework 3"
        cert.get_subject().CN = common_name
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        with open(cert_path, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_path, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        
        print(f"   Generated: {cert_path}")
    
    generate_cert('certs/iap.crt', 'certs/iap.key', 'localhost')
    generate_cert('certs/api.crt', 'certs/api.key', 'localhost')
    print("✅ Certificates generated successfully")

def generate_rsa_keys():
    """Generate RSA keys for AES encryption"""
    os.makedirs('keys', exist_ok=True)
    
    if os.path.exists('keys/private_key.pem') and os.path.exists('keys/public_key.pem'):
        if os.path.getsize('keys/private_key.pem') > 0 and os.path.getsize('keys/public_key.pem') > 0:
            print("✅ RSA keys already exist")
            return
    
    print("🔑 Generating RSA keys for AES encryption...")
    
    from app.crypto.rsa_aes import RSA_AES_Encryptor
    encryptor = RSA_AES_Encryptor()
    encryptor.generate_keys()
    
    print("✅ RSA keys generated")

def run_service(service_class, port, name, **kwargs):
    """Run a service in a separate thread without debug mode"""
    def target():
        try:
            service = service_class(port=port, **kwargs)
            print(f"🚀 {name} started on port {port}")
            # Disable debug mode to avoid signal issues
            service.app.debug = False
            service.app.use_reloader = False
            service.run()
        except Exception as e:
            print(f"❌ Failed to start {name}: {e}")
    
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread

def main():
    print("=" * 60)
    print("🔐 FRAMEWORK 3: IDENTITY-AWARE PROXY (IAP) MODEL")
    print("Zero Trust Architecture with RSA+AES Encryption")
    print("Separate Document Service Architecture")
    print("=" * 60)
    
    # Generate certificates and keys
    generate_certificates()
    generate_rsa_keys()
    
    # Import services
    from app.auth_server import AuthServer
    from app.services.api_server import APIGatewayService
    from app.services.document_service import DocumentService
    from app.iap_proxy import IAPProxy
    
    threads = []
    
    print("\n📡 Starting services...")
    
    # Start services in order
    
    # 1. Document Service (Port 8503)
    doc_service = DocumentService(port=8503)
    doc_service.app.debug = False
    doc_service.app.use_reloader = False
    doc_thread = threading.Thread(target=doc_service.run, daemon=True)
    doc_thread.start()
    threads.append(doc_thread)
    print("🚀 Document Service started on port 8503")
    time.sleep(2)
    
    # 2. API Gateway (Port 8502)
    api_service = APIGatewayService(port=8502)
    api_service.app.debug = False
    api_service.app.use_reloader = False
    api_thread = threading.Thread(target=api_service.run, daemon=True)
    api_thread.start()
    threads.append(api_thread)
    print("🚀 API Gateway started on port 8502")
    time.sleep(1)
    
    # 3. Auth Server (Port 8501)
    auth_service = AuthServer(port=8501)
    auth_service.app.debug = False
    auth_service.app.use_reloader = False
    auth_thread = threading.Thread(target=auth_service.run, daemon=True)
    auth_thread.start()
    threads.append(auth_thread)
    print("🚀 Auth Server started on port 8501")
    time.sleep(1)
    
    # 4. IAP Proxy (Port 8443)
    iap_service = IAPProxy(port=8443)
    iap_service.app.debug = False
    iap_service.app.use_reloader = False
    iap_thread = threading.Thread(target=iap_service.run, daemon=True)
    iap_thread.start()
    threads.append(iap_thread)
    print("🚀 IAP Proxy started on port 8443")
    time.sleep(2)
    
    print("\n" + "=" * 60)
    print("✅ ALL SERVICES RUNNING")
    print("=" * 60)
    print(f"""
          Login - https://localhost:8443/login
    🌐 IAP PROXY (Main Entry):     https://localhost:8443
    🔐 Auth Server:                https://localhost:8501
    🔀 API Gateway:                https://localhost:8502
    📄 Document Service:           https://localhost:8503

    """)
    
    # Open browser automatically
    time.sleep(3)
    webbrowser.open("https://localhost:8443")
    
    print("\n⚠️  Browser will show certificate warning - click 'Advanced' → 'Proceed to localhost'")
    print("Press Ctrl+C to stop all services\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down all services...")
        sys.exit(0)

if __name__ == "__main__":
    main()