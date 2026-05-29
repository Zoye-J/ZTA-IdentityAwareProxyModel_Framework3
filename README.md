# Framework 3: Identity-Aware Proxy (IAP) Model

## Overview

Framework 3 implements a Zero Trust Architecture using the Identity-Aware Proxy (IAP) pattern. All requests must authenticate through a central proxy before accessing any protected resource, with RSA+AES hybrid encryption for document storage.

## Architecture Components



**IAP Proxy** | 8443 | Main entry point, authenticates users, injects JWT tokens |
**Auth Server** | 8501 | Handles user login and token issuance |
**API Gateway** | 8502 | Routes requests to document service |
**Document Service** | 8503 | Manages encrypted document storage |

## Tools & Technologies

<div align="center">

| | | | |
|:---:|:---:|:---:|:---:|
| ![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white) | ![Flask](https://img.shields.io/badge/Flask-2.3.3-000000?style=for-the-badge&logo=flask&logoColor=white) | ![JWT](https://img.shields.io/badge/JWT-8.0-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white) | ![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white) |
| **Python 3.13** | **Flask** | **PyJWT** | **SQLite** |

| | | |
|:---:|:---:|:---:|
| ![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0-721412?style=for-the-badge&logo=openssl&logoColor=white) | ![Cryptography](https://img.shields.io/badge/Cryptography-41.0-7B4F9B?style=for-the-badge&logo=cryptography&logoColor=white) | ![Requests](https://img.shields.io/badge/Requests-2.31-005FAD?style=for-the-badge&logo=python&logoColor=white) |
| **OpenSSL** | **Cryptography** | **Requests** |

</div>

## Security Implementation

| Layer | Technology | Purpose |
|-------|------------|---------|
| Transport | TLS 1.3 | Encrypts all network communication |
| Authentication | JWT (HS256) | Stateless token-based auth |
| Data at Rest | RSA-2048 + AES-256-GCM | Hybrid encryption for documents |
| Access Control | Clearance + Department | Policy-based authorization |

## Access Rules

| User | Clearance | Department | Access |
|------|-----------|------------|--------|
| intelligence_officer | TOP_SECRET | Intelligence | Intelligence + General |
| defense_staff | SECRET | Defense | Defense + General |
| general_user | BASIC | General | General only |




## Running the Framework

```bash
# Install dependencies
pip install -r requirements.txt

# Generate certificates
python generate_certs.py

# Start all services
python run.py