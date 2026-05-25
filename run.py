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

# Add current directory to path FIRST
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def generate_certificates():
    """Generate self-signed certificates for HTTPS"""
    os.makedirs('certs', exist_ok=True)
    
    if os.path.exists('certs/iap.crt') and os.path.exists('certs/iap.key'):
        print("✅ Certificates already exist")
        return
    
    print("🔐 Generating SSL certificates...")
    
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BD"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Dhaka"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Dhaka"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ZTA Research"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.DNSName(u"127.0.0.1"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    with open("certs/iap.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("certs/iap.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Copy for API and Document services
    import shutil
    shutil.copy("certs/iap.key", "certs/api.key")
    shutil.copy("certs/iap.crt", "certs/api.crt")
    
    print("✅ Certificates generated successfully")

def generate_rsa_keys():
    """Generate RSA keys for AES encryption"""
    os.makedirs('keys', exist_ok=True)
    
    if os.path.exists('keys/private_key.pem') and os.path.exists('keys/public_key.pem'):
        print("✅ RSA keys already exist")
        return
    
    print("🔑 Generating RSA keys for AES encryption...")
    
    # Direct import after path is set
    from app.crypto.rsa_aes import RSA_AES_Encryptor
    encryptor = RSA_AES_Encryptor()
    encryptor.generate_keys()
    
    print("✅ RSA keys generated")

def run_service(service_class, port, name, **kwargs):
    """Run a service in a separate thread"""
    def target():
        try:
            service = service_class(port=port, **kwargs)
            print(f"🚀 {name} started on port {port}")
            service.run()
        except Exception as e:
            print(f"❌ Failed to start {name}: {e}")
            import traceback
            traceback.print_exc()
    
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
    
    # Import services - use absolute imports
    from app.auth_server import AuthServer
    from app.services.api_server import APIGatewayService
    from app.services.document_service import DocumentService
    from app.iap_proxy import IAPProxy
    
    threads = []
    
    # Start services in order
    print("\n📡 Starting services...")
    
    # 1. Document Service (Port 8503)
    threads.append(run_service(DocumentService, 8503, "📄 Document Service"))
    time.sleep(2)
    
    # 2. API Gateway (Port 8502)
    threads.append(run_service(APIGatewayService, 8502, "🔀 API Gateway"))
    time.sleep(1)
    
    # 3. Auth Server (Port 8501)
    threads.append(run_service(AuthServer, 8501, "🔐 Auth Server"))
    time.sleep(1)
    
    # 4. IAP Proxy (Port 8443 - main entry)
    threads.append(run_service(IAPProxy, 8443, "🛡️ IAP Proxy"))
    time.sleep(2)
    
    print("\n" + "=" * 60)
    print("✅ ALL SERVICES RUNNING")
    print("=" * 60)
    print("""
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