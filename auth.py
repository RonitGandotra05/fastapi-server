from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from typing import List, Optional
from passlib.context import CryptContext
from datetime import datetime, timedelta
from models import User
from database import get_db
from sqlalchemy.orm import Session
import os

SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')  # Use a secure method in production
ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 14400  # Removed, no longer used

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Utility functions for authentication
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Create a JWT token without an expiration time.

    Args:
        data (dict): The data to encode in the token.
        expires_delta (Optional[timedelta], optional): Time until expiration. Defaults to None.

    Returns:
        str: The encoded JWT token.
    """
    to_encode = data.copy()
    # Remove expiration logic to make token inexorable
    # if expires_delta:
    #     expire = datetime.utcnow() + expires_delta
    # else:
    #     expire = datetime.utcnow() + timedelta(minutes=30)
    # to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency to get current user
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user

# Role-based dependency
def RoleChecker(roles: List[str]):
    async def role_checker(
        current_user: User = Depends(get_current_user)
    ):
        if current_user.is_admin and 'admin' in roles:
            return current_user
        elif not current_user.is_admin and 'user' in roles:
            return current_user
        else:
            raise HTTPException(status_code=403, detail="Access forbidden")
    return role_checker  # Return the function itself
