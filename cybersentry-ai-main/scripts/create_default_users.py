#!/usr/bin/env python3
import sys
sys.path.append('.')

from database.models import SessionLocal, User
from auth.security import get_password_hash

def create_default_users():
    """Create default user accounts"""
    db = SessionLocal()
    
    default_users = [
        {
            "username": "admin",
            "email": "admin@cybersentry.local",
            "password": "Admin@123",
            "full_name": "System Administrator",
            "department": "IT",
            "role": "Administrator",
            "is_admin": True,
            "is_verified": True
        },
        {
            "username": "analyst",
            "email": "analyst@cybersentry.local", 
            "password": "Analyst@123",
            "full_name": "Security Analyst",
            "department": "Security",
            "role": "Analyst",
            "is_admin": False,
            "is_verified": True
        },
        {
            "username": "user",
            "email": "user@cybersentry.local",
            "password": "User@123",
            "full_name": "Regular User",
            "department": "General",
            "role": "User",
            "is_admin": False,
            "is_verified": True
        },
        {
            "username": "hr_manager",
            "email": "hr@cybersentry.local",
            "password": "Hr@123456",
            "full_name": "HR Manager",
            "department": "HR",
            "role": "Manager",
            "is_admin": False,
            "is_verified": True
        }
    ]
    
    created_count = 0
    for user_data in default_users:
        # Check if user exists
        existing = db.query(User).filter(User.username == user_data["username"]).first()
        
        if not existing:
            # Create new user
            new_user = User(
                username=user_data["username"],
                email=user_data["email"],
                full_name=user_data["full_name"],
                hashed_password=get_password_hash(user_data["password"]),
                department=user_data["department"],
                role=user_data["role"],
                is_admin=user_data.get("is_admin", False),
                is_verified=user_data.get("is_verified", True),
                risk_level="low",
                status="active"
            )
            
            db.add(new_user)
            created_count += 1
            print(f"✅ Created user: {user_data['username']} / {user_data['password']}")
    
    db.commit()
    db.close()
    
    print(f"\n🎯 Created {created_count} default users")
    print("\n🔐 Default Login Credentials:")
    print("   Admin:     admin / Admin@123")
    print("   Analyst:   analyst / Analyst@123")
    print("   User:      user / User@123")
    print("   HR Manager: hr_manager / Hr@123456")

if __name__ == "__main__":
    create_default_users()