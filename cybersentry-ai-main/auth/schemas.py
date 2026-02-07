from pydantic import BaseModel, EmailStr, validator
from datetime import datetime
from typing import Optional, List

class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    password: str
    department: Optional[str] = None
    role: Optional[str] = None
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one number')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        return v

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    department: Optional[str] = None
    role: Optional[str] = None

class UserResponse(UserBase):
    id: int
    is_active: bool
    is_admin: bool
    is_verified: bool
    risk_level: str
    status: str
    last_login: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

class PasswordChange(BaseModel):
    current_password: str
    new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('New password must be at least 8 characters')
        return v

class LoginHistoryResponse(BaseModel):
    id: int
    username: str
    ip_address: Optional[str]
    location: Optional[str]
    device_type: Optional[str]
    success: bool
    failure_reason: Optional[str]
    is_suspicious: bool
    suspicious_reason: Optional[str]
    timestamp: datetime
    
    class Config:
        from_attributes = True

class SessionResponse(BaseModel):
    id: int
    session_token: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]
    
    class Config:
        from_attributes = True