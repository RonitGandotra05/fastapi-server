from fastapi import APIRouter, Depends, HTTPException, Form, Path
from sqlalchemy.orm import Session
from database import get_db
from models import User, BugReport
from auth import get_password_hash, get_user_by_email, verify_password, create_access_token, RoleChecker
from typing import List
from datetime import timedelta
import os
from fastapi.security import OAuth2PasswordRequestForm
from schemas import UserResponse, UserUpdate
from utils import send_text_message

from random import randint
from datetime import datetime, timedelta

router = APIRouter()

# Store OTPs securely; in production, use a persistent store or database
otp_store = {}  # Key: email, Value: {'otp': otp, 'expires_at': datetime}

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', 1440))

@router.post("/forgot_password")
async def forgot_password(
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, email=email)
    if not user:
        # To prevent user enumeration, return the same response
        return {"message": "If an account with that email exists, an OTP has been sent to the registered phone number."}

    # Generate a 6-digit OTP
    otp = randint(100000, 999999)
    expires_at = datetime.utcnow() + timedelta(minutes=5)

    # Store the OTP and expiry
    otp_store[email] = {'otp': otp, 'expires_at': expires_at}

    # Send the OTP via WhatsApp with better formatting
    try:
        message = (
            f"*Password Reset OTP*\n"
            f"━━━━━━━━━━━━━━━━\n\n"
            f"Hello {user.name},\n\n"
            f"You have requested to reset your password.\n\n"
            f"*Your OTP is:*\n{otp}\n\n"
            f"This OTP will expire in 5 minutes.\n\n"
            f"If you did not request this password reset, please ignore this message."
        )
        await send_text_message(user.phone, message)
    except Exception as e:
        print(f"Error sending OTP: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to send OTP: {str(e)}")

    return {"message": "If an account with that email exists, an OTP has been sent to the registered phone number."}

@router.post("/reset_password")
def reset_password(
    email: str = Form(...),
    otp: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Verify if the OTP is valid
    otp_entry = otp_store.get(email)
    if not otp_entry or otp_entry['otp'] != int(otp) or otp_entry['expires_at'] < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    user = get_user_by_email(db, email=email)
    if not user:
        # Should not happen if OTP was sent, but handle just in case
        raise HTTPException(status_code=404, detail="User not found")

    # Update the user's password
    user.password_hash = get_password_hash(new_password)
    db.commit()

    # Invalidate the OTP
    del otp_store[email]

    return {"message": "Your password has been reset successfully"}

# Registration Endpoint (Admin Only)
@router.post("/register")
async def register_user(
    name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    # Trim whitespace from name before proceeding
    name = name.strip()
    
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
    
    # Send credentials via WhatsApp with better formatting
    try:
        message = (
            f"*Welcome to BugsZap!*\n"
            f"━━━━━━━━━━━━━━━━\n\n"
            f"Hello {name},\n\n"
            f"Your account has been created successfully by {current_user.name}.\n\n"
            f"*Login Credentials*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"*Email:*\n{email}\n\n"
            f"*Password:*\n{password}\n\n"
            f"*Next Steps*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"1. Install the Chrome Extension\n"
            f"2. Log in with your credentials\n"
            f"3. Start reporting bugs!\n\n"
            f"*Download Extension:*\n"
            f"https://chromewebstore.google.com/detail/bugs-report-rz/egjnfjgaagjiigmdedeobeineeopnbff\n\n"
            f"For any assistance, please contact your administrator."
        )
        await send_text_message(phone, message)
    except Exception as e:
        print(f"Error sending message to user: {e}")
        # handle failure
        db.delete(user)
        db.commit()
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to send credentials to user: {str(e)}"
        )
    
    return {"message": "User registered successfully"}

# Merged Login Endpoint (User and Admin Login)
@router.post("/login")
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "is_admin": user.is_admin,
        "id": user.id
    }

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
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    users = db.query(User).all()
    # Remove the first two users (admin and deleted user) from the list
    return [user.name for user in users[2:]]

@router.get("/all_users", response_model=List[UserResponse])
async def get_all_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    users = db.query(User).all()
    # Remove the first two users (admin and deleted user) from the list
    return users[2:]

# Optional: Endpoint to get current user info (Accessible by both users and admins)
@router.get("/users/me")
async def get_current_user_info(
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    return current_user

# Update User Endpoint (Admin Only)
@router.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_update: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Handle nullable fields
    if user_update.phone is not None:
        db_user.phone = user_update.phone
    # ... rest of the code ...

    db.commit()
    db.refresh(db_user)
    return db_user

# Endpoint to toggle a user as admin (Admin Only)
@router.put("/users/{user_id}/toggle_admin")
def toggle_admin(
    user_id: int = Path(..., description="The ID of the user to toggle admin status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
         raise HTTPException(status_code=404, detail="User not found")
    user.is_admin = not user.is_admin
    db.commit()
    db.refresh(user)
    return {"message": f"User {user.name} is now {'an admin' if user.is_admin else 'not an admin'}"}

# Delete User Endpoint (Admin Only)
@router.delete("/users/{user_id}")
def delete_user(
    user_id: int = Path(..., description="The ID of the user to delete"),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")

    if user_to_delete.id == current_user.id:
        raise HTTPException(status_code=400, detail="Admin cannot delete themselves")

    deleted_user = db.query(User).filter(User.name == "Deleted User").first()
    if not deleted_user:
        raise HTTPException(status_code=500, detail="Deleted User placeholder not found")

    db.query(BugReport).filter(BugReport.creator_id == user_id).update({BugReport.creator_id: deleted_user.id})
    db.query(BugReport).filter(BugReport.recipient_id == user_id).update({BugReport.recipient_id: deleted_user.id})

    # Delete the user
    db.delete(user_to_delete)
    db.commit()
    return {"message": f"User with ID {user_id} has been deleted and their bug reports reassigned"}
