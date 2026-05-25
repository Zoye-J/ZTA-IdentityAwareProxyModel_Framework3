#!/usr/bin/env python
"""
Framework 3: Identity-Aware Proxy (IAP) Model
Zero Trust Architecture with IAP + RSA+AES Encryption
"""

import os
import sys
import subprocess
import time
import threading
import webbrowser

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def generate_certificates():
    """Generate self-signed certificates for HTTPS"""
    os.makedirs('certs', exist_ok=True)
    
    # Check if certs exist
    if os.path.exists('certs/iap.crt') and os.path.exists('certs/iap.key'):
        print("✅ Certificates already exist")
        return
    
    print("🔐 Generating SSL certificates...")
    
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Generate certificate
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
    
    # Save private key
    with open("certs/iap.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    with open("certs/iap.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Copy for API server
    with open("certs/api.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("certs/api.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("✅ Certificates generated successfully")

def generate_rsa_keys():
    """Generate RSA keys for AES encryption"""
    os.makedirs('keys', exist_ok=True)
    
    if os.path.exists('keys/private_key.pem') and os.path.exists('keys/public_key.pem'):
        print("✅ RSA keys already exist")
        return
    
    print("🔑 Generating RSA keys for AES encryption...")
    
    from app.crypto.rsa_aes import RSA_AES_Encryptor
    encryptor = RSA_AES_Encryptor()
    encryptor.generate_keys()
    
    print("✅ RSA keys generated")

def run_service(service_class, port, name):
    """Run a service in a separate thread"""
    try:
        service = service_class(port=port)
        print(f"🚀 Starting {name} on port {port}")
        service.run()
    except Exception as e:
        print(f"❌ Failed to start {name}: {e}")

def main():
    print("=" * 60)
    print("🔐 FRAMEWORK 3: IDENTITY-AWARE PROXY (IAP) MODEL")
    print("Zero Trust Architecture with RSA+AES Encryption")
    print("=" * 60)
    
    # Generate certificates and keys
    generate_certificates()
    generate_rsa_keys()
    
    # Import services
    from app.iap_proxy import IAPProxy
    from app.api_server import APIResourceServer
    from app.auth_server import AuthServer
    
    threads = []
    
    # Start Auth Server (Port 8501)
    auth_thread = threading.Thread(
        target=run_service,
        args=(AuthServer, 8501, "Auth Server"),
        daemon=True
    )
    threads.append(auth_thread)
    
    # Start API Server (Port 8502)
    api_thread = threading.Thread(
        target=run_service,
        args=(APIResourceServer, 8502, "API Server"),
        daemon=True
    )
    threads.append(api_thread)
    
    # Start IAP Proxy (Port 8443 - main entry)
    iap_thread = threading.Thread(
        target=run_service,
        args=(IAPProxy, 8443, "IAP Proxy"),
        daemon=True
    )
    threads.append(iap_thread)
    
    # Start all threads
    for thread in threads:
        thread.start()
        time.sleep(2)  # Stagger startup
    
    print("\n" + "=" * 60)
    print("✅ ALL SERVICES RUNNING")
    print("=" * 60)
    print(f"""
    🌐 IAP PROXY (Main Entry):  https://localhost:8443
    🔐 Auth Server:             https://localhost:8501
    📁 API Server:              https://localhost:8502
    
    🎯 HOW IT WORKS:
    1. Browser connects to IAP Proxy on port 8443
    2. IAP authenticates user via Auth Server
    3. IAP injects JWT token (X-IAP-JWT-Assertion header)
    4. IAP forwards request to API Server
    5. API Server decrypts RSA+AES encrypted content
    6. Response returns through IAP to browser
    
    📝 TEST ACCOUNTS:
    - intelligence_officer / pass123 (TOP_SECRET, Intelligence Dept)
    - defense_staff / pass123 (SECRET, Defense Dept)
    - general_user / pass123 (BASIC, General Dept)
    
    🔐 ENCRYPTION LAYERS:
    - Transport: TLS 1.3 (HTTPS)
    - Application: JWT Tokens (HS256)
    - Resource: RSA+AES Hybrid Encryption
    
    🆚 COMPARED TO FW1 & FW2:
    - FW1: Gateway-centric with custom per-request encryption
    - FW2: Overlay network with mTLS
    - FW3: Identity-Aware Proxy with header injection
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