from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import bcrypt

Base = declarative_base()

class User(Base):
    """User model with authentication"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100))
    
    # Password hash (never store plain passwords!)
    hashed_password = Column(String(200), nullable=False)
    
    # Account status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    
    # Security
    failed_login_attempts = Column(Integer, default=0)
    last_login = Column(DateTime, nullable=True)
    last_password_change = Column(DateTime, default=datetime.utcnow)
    
    # Profile
    department = Column(String(50))
    role = Column(String(50))
    risk_level = Column(String(20), default="low")  # low, medium, high
    status = Column(String(20), default="active")   # active, blocked, suspended
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def verify_password(self, plain_password: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(plain_password.encode('utf-8'), self.hashed_password.encode('utf-8'))

class LoginHistory(Base):
    """Track login attempts for security"""
    __tablename__ = "login_history"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    username = Column(String(50))
    
    # Login details
    ip_address = Column(String(50))
    user_agent = Column(String(500))
    location = Column(String(100))
    device_type = Column(String(50))
    
    # Status
    success = Column(Boolean, default=False)
    failure_reason = Column(String(100))
    
    # Security flags
    is_suspicious = Column(Boolean, default=False)
    suspicious_reason = Column(String(200))
    
    timestamp = Column(DateTime, default=datetime.utcnow)

class Session(Base):
    """Active user sessions"""
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    session_token = Column(String(500), unique=True, index=True)
    ip_address = Column(String(50))
    user_agent = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)

# Database setup
DATABASE_URL = "sqlite:///./cybersentry.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)
    
    # Create admin user if doesn't exist
    db = SessionLocal()
    try:
        from auth.security import get_password_hash
        
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin_user = User(
                username="admin",
                email="admin@cybersentry.local",
                full_name="System Administrator",
                hashed_password=get_password_hash("Admin@123"),  # Change in production!
                is_admin=True,
                is_verified=True,
                department="IT",
                role="Administrator"
            )
            db.add(admin_user)
            db.commit()
            print("✅ Admin user created: admin / Admin@123")
    finally:
        db.close()

def get_db():
    """Database session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()