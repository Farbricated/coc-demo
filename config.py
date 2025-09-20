"""
COC - Configuration Management
=============================
Environment-based configuration for Chain of Custody system
"""

import os
from datetime import timedelta

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ Environment variables loaded from .env")
except ImportError:
    print("⚠️ python-dotenv not installed - using system environment variables only")

class Config:
    """COC System Configuration"""
    
    # Project Information
    PROJECT_NAME = "COC"
    SYSTEM_NAME = "Chain of Custody Evidence Management System"
    VERSION = "1.0.0"
    ENVIRONMENT = os.getenv('ENVIRONMENT', 'production')
    
    # Security Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'coc-evidence-management-system-2025')
    SESSION_LIFETIME = timedelta(hours=2)
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=30)
    
    # Database Configuration
    MONGO_URI = os.getenv('MONGO_URI')
    MONGODB_DB_NAME = 'coc'
    
    # Server Configuration  
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    PORT = int(os.getenv('PORT', 8050))
    HOST = os.getenv('HOST', '0.0.0.0')
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_FILE_SIZE', 100 * 1024 * 1024))
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx',
        'zip', 'rar', '7z', 'mp4', 'avi', 'mp3', 'wav', 'exe', 'msi'
    }
    
    # AI Configuration
    AI_ENABLED = os.getenv('AI_ENABLED', 'true').lower() == 'true'
    CONFIDENCE_THRESHOLD = float(os.getenv('CONFIDENCE_THRESHOLD', 0.85))
    
    # Blockchain Configuration
    BLOCKCHAIN_ENABLED = os.getenv('BLOCKCHAIN_ENABLED', 'true').lower() == 'true'
    GANACHE_URL = os.getenv('GANACHE_URL', 'http://127.0.0.1:7545')
    GANACHE_NETWORK_ID = int(os.getenv('GANACHE_NETWORK_ID', 5777))
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/coc.log')
    
    # Legal Compliance
    JURISDICTION = os.getenv('JURISDICTION', 'India')
    COMPLIANCE_STANDARDS = ['Section_65B', 'BSA_2023', 'ISO_27001']
    
    @classmethod
    def validate_config(cls):
        """Validate configuration settings"""
        print("🔍 Validating COC configuration...")
        
        if cls.MONGO_URI:
            print(f"✅ MONGO_URI found: {cls.MONGO_URI[:50]}...")
        else:
            print("❌ MONGO_URI not found in environment variables")
        
        print(f"🗃️ Database name: {cls.MONGODB_DB_NAME}")
        print(f"🌐 Server: {cls.HOST}:{cls.PORT}")
        print(f"📁 Project: {cls.PROJECT_NAME}")
        
        return bool(cls.MONGO_URI)

# Global config instance
config = Config()

if __name__ == "__main__":
    config.validate_config()
