"""
Configuration management for Framework 3
All secrets are loaded from environment variables or .env file
"""

import os
import secrets
from pathlib import Path

# Load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    # Find the project root (where .env file should be)
    env_path = Path(__file__).parent.parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
        print(f"✅ Loaded configuration from {env_path}")
    else:
        print(f"⚠️  .env file not found at {env_path}. Using environment variables or defaults.")
except ImportError:
    print("⚠️  python-dotenv not installed. Install with: pip install python-dotenv")
    print("   Using environment variables only.")

class Config:
    """Central configuration for all services"""
    
    # JWT Configuration
    JWT_SECRET = os.environ.get('JWT_SECRET', None)
    
    # Internal API tokens for service-to-service authentication
    INTERNAL_API_TOKEN = os.environ.get('INTERNAL_API_TOKEN', None)
    
    # Flask session secret
    FLASK_SECRET = os.environ.get('FLASK_SECRET', None)
    
    # Environment
    ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    @classmethod
    def get_jwt_secret(cls):
        """Get JWT secret - must be set in environment for production"""
        if cls.JWT_SECRET:
            return cls.JWT_SECRET
        
        if cls.ENVIRONMENT == 'production':
            raise ValueError(
                "JWT_SECRET environment variable is required in production!\n"
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        
        # Generate a secure random secret for development only
        generated = secrets.token_urlsafe(32)
        print(f"⚠️  WARNING: JWT_SECRET not set. Using generated secret for development.")
        print(f"   Generated secret: {generated}")
        print(f"   Add this to your .env file for consistency.")
        return generated
    
    @classmethod
    def get_internal_token(cls):
        """Get internal API token - must be set in environment for production"""
        if cls.INTERNAL_API_TOKEN:
            return cls.INTERNAL_API_TOKEN
        
        if cls.ENVIRONMENT == 'production':
            raise ValueError(
                "INTERNAL_API_TOKEN environment variable is required in production!\n"
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        
        # Generate secure token for development
        generated = secrets.token_urlsafe(32)
        print(f"⚠️  INTERNAL_API_TOKEN not set. Using generated token for development.")
        print(f"   Generated token: {generated}")
        print(f"   Add this to your .env file for consistency.")
        return generated
    
    @classmethod
    def get_flask_secret(cls):
        """Get Flask session secret"""
        if cls.FLASK_SECRET:
            return cls.FLASK_SECRET
        
        if cls.ENVIRONMENT == 'production':
            raise ValueError("FLASK_SECRET environment variable is required in production!")
        
        generated = secrets.token_urlsafe(32)
        print(f"⚠️  FLASK_SECRET not set. Using generated secret for development.")
        return generated


# Initialize configuration
JWT_SECRET = Config.get_jwt_secret()
INTERNAL_API_TOKEN = Config.get_internal_token()
FLASK_SECRET = Config.get_flask_secret()
ENVIRONMENT = Config.ENVIRONMENT
DEBUG = Config.DEBUG