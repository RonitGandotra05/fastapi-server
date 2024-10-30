from fastapi import APIRouter, Depends, HTTPException, Form
from sqlalchemy.orm import Session
from database import get_db
from models import User
from auth import get_password_hash, get_user_by_email, verify_password, create_access_token, RoleChecker
from typing import List
from datetime import timedelta
import os
from fastapi.security import OAuth2PasswordRequestForm


router = APIRouter()

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', 1440))

# Registration Endpoint (Admin Only)
@router.post("/register")
def register_user(
    name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    existing_user = get_user_by_email(db, email=email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        name=name,
        email=email,
        phone=phone,
        password_hash=get_password_hash(password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User registered successfully"}

# Login Endpoint (User Login)
@router.post("/login")
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if user.is_admin:
        raise HTTPException(status_code=403, detail="Please use the admin login endpoint")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Admin Login Endpoint
@router.post("/admin_login")
def admin_login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Logout Endpoint (Accessible by all authenticated users)
@router.post("/logout")
async def logout(
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    # Token invalidation logic can be implemented here if needed
    return {"message": "Logout successful"}

# Endpoint to get all registered users (Admin Only)
@router.get("/users", response_model=List[str])
async def get_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    users = db.query(User).all()
    return [user.name for user in users]

# Optional: Endpoint to get current user info (Accessible by both users and admins)
@router.get("/users/me")
async def get_current_user_info(
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    return current_user
