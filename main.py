from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional, List
import boto3
import uuid
import os
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship, joinedload
from sqlalchemy.types import Enum as SQLAlchemyEnum
from dotenv import load_dotenv
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from enum import Enum

load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')  # Use a secure method in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.getenv('AWS_REGION')
AWS_BUCKET_NAME = os.getenv('AWS_BUCKET_NAME')

if not all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_BUCKET_NAME]):
    raise RuntimeError("AWS credentials and bucket information must be set in environment variables")

s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./bug_reports.db')

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Define the database models
class BugStatus(str, Enum):
    assigned = "assigned"
    resolved = "resolved"

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    received_bug_reports = relationship(
        "BugReport",
        foreign_keys="[BugReport.recipient_id]",
        back_populates="recipient"
    )
    created_bug_reports = relationship(
        "BugReport",
        foreign_keys="[BugReport.creator_id]",
        back_populates="creator"
    )

class BugReport(Base):
    __tablename__ = 'bug_reports'

    id = Column(Integer, primary_key=True, index=True)
    image_url = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    recipient_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    recipient = relationship(
        "User",
        foreign_keys=[recipient_id],
        back_populates="received_bug_reports"
    )
    creator_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    creator = relationship(
        "User",
        foreign_keys=[creator_id],
        back_populates="created_bug_reports"
    )
    status = Column(
        SQLAlchemyEnum(BugStatus),
        default=BugStatus.assigned,
        nullable=False
    )

# Create the database tables
Base.metadata.create_all(bind=engine)

# Define the FastAPI app
app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware to log every request and the user who made the request
async def log_requests_middleware(request: Request, call_next):
    user_email = "Anonymous"
    if "authorization" in request.headers:
        auth_header = request.headers.get("authorization")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                user_email = payload.get("sub", "Anonymous")
            except JWTError:
                pass
    response = await call_next(request)
    print(f"User: {user_email} made a request to {request.method} {request.url}")
    return response

app.add_middleware(BaseHTTPMiddleware, dispatch=log_requests_middleware)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions for authentication
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
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

# Pydantic models
class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    phone: Optional[str] = None
    is_admin: bool

    class Config:
        from_attributes = True

class BugReportResponse(BaseModel):
    id: int
    image_url: str
    description: str
    recipient_id: int
    creator_id: int
    status: BugStatus
    recipient: str
    creator: str

    class Config:
        from_attributes = True
        use_enum_values = True

    @classmethod
    def from_bug_report(cls, bug_report: BugReport):
        return cls(
            id=bug_report.id,
            image_url=bug_report.image_url,
            description=bug_report.description,
            recipient_id=bug_report.recipient_id,
            creator_id=bug_report.creator_id,
            status=bug_report.status.value,
            recipient=bug_report.recipient.email,
            creator=bug_report.creator.email
        )

# Registration Endpoint (Admin Only)
@app.post("/register")
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
@app.post("/login")
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
@app.post("/admin_login")
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
@app.post("/logout")
async def logout(
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    # Token invalidation logic can be implemented here if needed
    return {"message": "Logout successful"}

# Upload Endpoint (Accessible by both users and admins)
@app.post("/upload")
async def upload_screenshot(
    file: UploadFile = File(...),
    description: str = Form(...),
    recipient_email: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    # Find the recipient user
    recipient_user = get_user_by_email(db, email=recipient_email)
    if not recipient_user:
        raise HTTPException(status_code=404, detail="Recipient user not found")

    try:
        file_content = await file.read()
        file_name = f"screenshot-{uuid.uuid4()}.png"
        s3_client.put_object(
            Bucket=AWS_BUCKET_NAME,
            Key=file_name,
            Body=file_content,
            ContentType='image/png'
        )

        image_url = f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{file_name}"

        bug_report = BugReport(
            image_url=image_url,
            description=description,
            recipient_id=recipient_user.id,
            creator_id=current_user.id,
            status=BugStatus.assigned
        )

        db.add(bug_report)
        db.commit()
        db.refresh(bug_report)

        return {
            "message": "Upload successful",
            "id": bug_report.id,
            "url": image_url,
            "description": description,
            "recipient": recipient_user.email
        }
    except Exception as e:
        db.rollback()
        print(f"Error uploading to S3 or saving to DB: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Read Bug Report (Accessible by both users and admins)
@app.get("/bug_reports/{bug_id}", response_model=BugReportResponse)
async def read_bug_report(
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    bug_report = db.query(BugReport).options(
        joinedload(BugReport.recipient),
        joinedload(BugReport.creator)
    ).filter(BugReport.id == bug_id).first()
    if bug_report is None:
        raise HTTPException(status_code=404, detail="Bug report not found")

    # Check if the current user is involved in the bug report
    if not current_user.is_admin and current_user.id not in [bug_report.creator_id, bug_report.recipient_id]:
        raise HTTPException(status_code=403, detail="Access forbidden")

    return BugReportResponse.from_bug_report(bug_report)

# Update Bug Report (Accessible by both users and admins)
@app.put("/bug_reports/{bug_id}")
async def update_bug_report(
    bug_id: int,
    description: Optional[str] = Form(None),
    recipient_email: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if bug_report is None:
        raise HTTPException(status_code=404, detail="Bug report not found")

    # Check if the current user is the creator or admin
    if not current_user.is_admin and bug_report.creator_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access forbidden")

    if description:
        bug_report.description = description
    if recipient_email:
        recipient_user = get_user_by_email(db, email=recipient_email)
        if not recipient_user:
            raise HTTPException(status_code=404, detail="Recipient user not found")
        bug_report.recipient_id = recipient_user.id

    db.commit()
    db.refresh(bug_report)
    return {
        "message": "Bug report updated",
        "bug_report": BugReportResponse.from_bug_report(bug_report)
    }

# Delete Bug Report (Accessible by both users and admins)
@app.delete("/bug_reports/{bug_id}")
async def delete_bug_report(
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if bug_report is None:
        raise HTTPException(status_code=404, detail="Bug report not found")

    # Check if the current user is the creator or admin
    if not current_user.is_admin and bug_report.creator_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access forbidden")

    # Delete the image from S3
    try:
        s3_key = bug_report.image_url.split(
            f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/"
        )[1]
        s3_client.delete_object(Bucket=AWS_BUCKET_NAME, Key=s3_key)
    except Exception as e:
        print(f"Error deleting image from S3: {e}")

    db.delete(bug_report)
    db.commit()
    return {"message": "Bug report deleted"}

# List Bug Reports (Admin Only)
@app.get("/bug_reports", response_model=List[BugReportResponse])
async def list_bug_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    bug_reports = db.query(BugReport).options(
        joinedload(BugReport.recipient),
        joinedload(BugReport.creator)
    ).all()
    return [BugReportResponse.from_bug_report(bug) for bug in bug_reports]

# Toggle Bug Report Status (Accessible by both users and admins)
@app.put("/bug_reports/{bug_id}/toggle_status")
async def toggle_bug_report_status(
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if bug_report is None:
        raise HTTPException(status_code=404, detail="Bug report not found")

    # Check if the current user is involved in the bug report
    if not current_user.is_admin and current_user.id not in [bug_report.creator_id, bug_report.recipient_id]:
        raise HTTPException(status_code=403, detail="Access forbidden")

    # Toggle the status
    if bug_report.status == BugStatus.assigned:
        bug_report.status = BugStatus.resolved
    elif bug_report.status == BugStatus.resolved:
        bug_report.status = BugStatus.assigned
    else:
        raise HTTPException(status_code=400, detail="Invalid bug report status")
    db.commit()
    db.refresh(bug_report)
    return {
        "message": "Bug report status toggled",
        "bug_report": BugReportResponse.from_bug_report(bug_report)
    }

# Endpoint to get all registered users (Admin Only)
@app.get("/users", response_model=List[str])
async def get_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    users = db.query(User).all()
    return [user.email for user in users]

# Get Bug Reports Created by User (Accessible by both users and admins)
@app.get("/users/{user_id}/created_bug_reports", response_model=List[BugReportResponse])
async def get_bug_reports_created_by_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if the current user is the user in question or admin
    if not current_user.is_admin and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Access forbidden")

    bug_reports = db.query(BugReport).options(
        joinedload(BugReport.recipient),
        joinedload(BugReport.creator)
    ).filter(BugReport.creator_id == user_id).all()
    return [BugReportResponse.from_bug_report(bug) for bug in bug_reports]

# Get Bug Reports Assigned to User (Accessible by both users and admins)
@app.get("/users/{user_id}/received_bug_reports", response_model=List[BugReportResponse])
async def get_bug_reports_assigned_to_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if the current user is the user in question or admin
    if not current_user.is_admin and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Access forbidden")

    bug_reports = db.query(BugReport).options(
        joinedload(BugReport.recipient),
        joinedload(BugReport.creator)
    ).filter(BugReport.recipient_id == user_id).all()
    return [BugReportResponse.from_bug_report(bug) for bug in bug_reports]

# Optional: Endpoint to get current user info (Accessible by both users and admins)
@app.get("/users/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    return current_user
