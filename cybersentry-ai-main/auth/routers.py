from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List

from database.models import get_db, User, LoginHistory, Session as DBSession
from .security import (
    verify_password, create_access_token, 
    ACCESS_TOKEN_EXPIRE_MINUTES, create_bcrypt_hash, check_bcrypt_password,get_password_hash
)
from .dependencies import get_current_active_user, get_current_admin_user
from .schemas import (
    UserCreate, UserResponse, UserUpdate, 
    Token, LoginRequest, PasswordChange,
    LoginHistoryResponse, SessionResponse
)
from security.alert_system import AlertSystem
import uuid

router = APIRouter(prefix="/auth", tags=["authentication"])
alert_system = AlertSystem()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,  # This uses UserCreate schema
    request: Request,
    db: Session = Depends(get_db)
):
    """Register a new user - FIXED VERSION"""
    try:
        # Check if user exists
        existing_user = db.query(User).filter(
            (User.username == user_data.username) | (User.email == user_data.email)
        ).first()
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already registered"
            )
        
        # Hash password
        hashed_password = get_password_hash(user_data.password)
        
        # Create new user
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name or user_data.username,
            hashed_password=hashed_password,
            department=user_data.department or "General",
            role=user_data.role or "User",
            is_active=True,
            is_verified=True,  # For demo, auto-verify
            risk_level="low",
            status="active"
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Log registration
        alert_system.send_alert(
            "USER_REGISTERED",
            "info",
            f"New user registered: {user_data.username}",
            {
                "ip": request.client.host,
                "user_agent": request.headers.get("user-agent", "unknown"),
                "email": user_data.email
            }
        )
        
        return new_user
        
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """User login with JWT token generation"""
    # Get user
    user = db.query(User).filter(User.username == form_data.username).first()
    
    # Log login attempt
    login_history = LoginHistory(
        username=form_data.username,
        ip_address=request.client.host if request else "unknown",
        user_agent=request.headers.get("user-agent") if request else "unknown",
        success=False
    )
    
    # Check user exists
    if not user:
        login_history.failure_reason = "User not found"
        db.add(login_history)
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is active
    if not user.is_active or user.status in ["blocked", "suspended"]:
        login_history.user_id = user.id
        login_history.failure_reason = f"Account {user.status}"
        db.add(login_history)
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is {user.status}"
        )
    
    # Verify password
    if not check_bcrypt_password(form_data.password, user.hashed_password):
        # Increment failed attempts
        user.failed_login_attempts += 1
        
        # Auto-block after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.status = "blocked"
            alert_system.send_alert(
                "AUTO_BLOCKED",
                "high",
                f"User {user.username} auto-blocked after 5 failed login attempts",
                {"ip": request.client.host if request else "unknown"}
            )
        
        login_history.user_id = user.id
        login_history.failure_reason = "Invalid password"
        db.add(login_history)
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Reset failed attempts on successful login
    user.failed_login_attempts = 0
    user.last_login = datetime.utcnow()
    
    # Check for suspicious login
    is_suspicious = False
    suspicious_reason = ""
    
    # Example: Login from foreign IP at unusual hour
    # You can add more sophisticated checks here
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id, "is_admin": user.is_admin},
        expires_delta=access_token_expires
    )
    
    # Create session
    session_token = str(uuid.uuid4())
    new_session = DBSession(
        user_id=user.id,
        session_token=session_token,
        ip_address=request.client.host if request else "unknown",
        user_agent=request.headers.get("user-agent") if request else "unknown",
        expires_at=datetime.utcnow() + access_token_expires
    )
    
    # Update login history
    login_history.user_id = user.id
    login_history.success = True
    login_history.is_suspicious = is_suspicious
    login_history.suspicious_reason = suspicious_reason
    
    db.add(login_history)
    db.add(new_session)
    db.commit()
    
    # Alert if suspicious
    if is_suspicious:
        alert_system.send_alert(
            "SUSPICIOUS_LOGIN",
            "medium",
            f"Suspicious login detected for user {user.username}",
            {"reason": suspicious_reason, "ip": request.client.host if request else "unknown"}
        )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": user.is_admin
        }
    }

@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Logout user (invalidate session)"""
    # In production, you'd invalidate the JWT token
    # For now, just delete the session
    db.query(DBSession).filter(DBSession.user_id == current_user.id).delete()
    db.commit()
    
    return {"message": "Successfully logged out"}

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user information"""
    return current_user

@router.post("/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Change user password"""
    # Verify current password
    if not check_bcrypt_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password
    current_user.hashed_password = create_bcrypt_hash(password_data.new_password)
    current_user.last_password_change = datetime.utcnow()
    
    db.commit()
    
    alert_system.send_alert(
        "PASSWORD_CHANGED",
        "info",
        f"Password changed for user {current_user.username}",
        {}
    )
    
    return {"message": "Password changed successfully"}

@router.get("/login-history", response_model=List[LoginHistoryResponse])
async def get_login_history(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    limit: int = 20
):
    """Get user's login history"""
    history = db.query(LoginHistory)\
        .filter(LoginHistory.user_id == current_user.id)\
        .order_by(LoginHistory.timestamp.desc())\
        .limit(limit)\
        .all()
    
    return history

@router.get("/active-sessions", response_model=List[SessionResponse])
async def get_active_sessions(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get user's active sessions"""
    sessions = db.query(DBSession)\
        .filter(
            DBSession.user_id == current_user.id,
            DBSession.is_active == True,
            DBSession.expires_at > datetime.utcnow()
        )\
        .order_by(DBSession.created_at.desc())\
        .all()
    
    return sessions

@router.post("/logout-all")
async def logout_all_sessions(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Logout from all devices"""
    db.query(DBSession).filter(DBSession.user_id == current_user.id).delete()
    db.commit()
    
    alert_system.send_alert(
        "LOGOUT_ALL",
        "info",
        f"All sessions terminated for user {current_user.username}",
        {}
    )
    
    return {"message": "Logged out from all devices"}