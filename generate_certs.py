#!/usr/bin/env python
"""
Generate self-signed certificates for HTTPS in Framework 3
Run this script once before starting the framework
"""

import os
from OpenSSL import crypto
import datetime

def generate_self_signed_cert(cert_path, key_path, common_name="localhost"):
    """Generate a self-signed certificate"""
    
    # Create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    # Create a self-signed certificate
    cert = crypto.X509()
    cert.get_subject().C = "BD"
    cert.get_subject().ST = "Dhaka"
    cert.get_subject().L = "Dhaka"
    cert.get_subject().O = "ZTA Research"
    cert.get_subject().OU = "Framework 3"
    cert.get_subject().CN = common_name
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for one year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    
    # Save certificate
    with open(cert_path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    # Save private key
    with open(key_path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    print(f"✅ Generated: {cert_path} and {key_path}")

def main():
    # Create directories
    os.makedirs('certs', exist_ok=True)
    os.makedirs('keys', exist_ok=True)
    
    # Generate certificates for all services
    print("🔐 Generating SSL certificates for all services...")
    
    # IAP Proxy certificate
    generate_self_signed_cert('certs/iap.crt', 'certs/iap.key', 'localhost')
    
    # API and Document service certificate (same for simplicity)
    generate_self_signed_cert('certs/api.crt', 'certs/api.key', 'localhost')
    
    print("\n✅ All certificates generated successfully!")
    print("   - certs/iap.crt / certs/iap.key")
    print("   - certs/api.crt / certs/api.key")
    
    # Generate RSA keys for encryption
    print("\n🔑 Generating RSA keys for AES encryption...")
    from app.crypto.rsa_aes import RSA_AES_Encryptor
    encryptor = RSA_AES_Encryptor()
    encryptor.generate_keys()
    print("✅ RSA keys generated in keys/ directory")

if __name__ == "__main__":
    main()