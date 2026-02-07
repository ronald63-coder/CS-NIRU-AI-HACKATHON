import os

class Config:
    # Security thresholds
    MALWARE_THRESHOLD = 0.7
    BEHAVIOR_THRESHOLD = 0.6
    AUTO_BLOCK_ENABLED = True
    
    # Alert settings
    IT_EMAIL = "security-team@company.com"
    SLACK_WEBHOOK = os.getenv('SLACK_WEBHOOK_URL', '')
    
    # Analysis settings
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    ALLOWED_FILE_TYPES = ['.exe', '.dll', '.pdf', '.doc', '.docx', '.zip', '.rar']
    
    # Response settings
    AUTO_BLOCK_DURATION = 24  # hours
    ALERT_ESCALATION_TIME = 5  # minutes
    
    # Database settings
    DATABASE_PATH = "cybersentry.db"

    # Scanner settings
    YARA_RULES_DIR = "rules"
    MIN_CONFIDENCE = 0.60

     # Security & Authentication
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
    
    # Password policy
    MIN_PASSWORD_LENGTH = 8
    REQUIRE_SPECIAL_CHARS = True
    REQUIRE_NUMBERS = True
    REQUIRE_UPPERCASE = True
    
    # Login security
    MAX_FAILED_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_MINUTES = 30
    
    # Session management
    SESSION_TIMEOUT_MINUTES = 30
    MAX_CONCURRENT_SESSIONS = 5