from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional, List
import boto3
import uuid
import os
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship, joinedload
from dotenv import load_dotenv
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel


# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware to log every request and the user who made the request
async def log_requests_middleware(request: Request, call_next):
    user_email = "Anonymous"
    if "authorization" in request.headers:
        token = request.headers.get("authorization").split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_email = payload.get("sub", "Anonymous")
        except JWTError:
            pass
    response = await call_next(request)
    print(f"User: {user_email} made a request to {request.method} {request.url}")
    return response

app.add_middleware(BaseHTTPMiddleware, dispatch=log_requests_middleware)

# Security - Password Hashing and Token Generation
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')  # Use a secure method in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# AWS S3 Configuration from environment variables
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.getenv('AWS_REGION')
AWS_BUCKET_NAME = os.getenv('AWS_BUCKET_NAME')

if not all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_BUCKET_NAME]):
    raise RuntimeError("AWS credentials and bucket information must be set in environment variables")

s3_client = boto3.client('s3',
                         aws_access_key_id=AWS_ACCESS_KEY_ID,
                         aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                         region_name=AWS_REGION)

# Database Configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./bug_reports.db')

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Define the database models
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    bug_reports = relationship("BugReport", back_populates="recipient")

class BugReport(Base):
    __tablename__ = 'bug_reports'

    id = Column(Integer, primary_key=True, index=True)
    image_url = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    recipient_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    recipient = relationship("User", back_populates="bug_reports")
    
class BugReportBase(BaseModel):
    id: int
    image_url: str
    description: str
    recipient_id: int

    class Config:
        orm_mode = True

class BugReportResponse(BugReportBase):
    recipient: str

# Create the database tables
Base.metadata.create_all(bind=engine)

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
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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

# Registration Endpoint
@app.post("/register")
def register_user(
    name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
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

# Login Endpoint
@app.post("/login")
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
    return {"access_token": access_token, "token_type": "bearer"}

# Logout Endpoint
@app.post("/logout")
def logout():
    return {"message": "Logout successful"}

# Upload Endpoint
@app.post("/upload")
async def upload_screenshot(
    file: UploadFile = File(...),
    description: str = Form(...),
    recipient_email: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Find the recipient user
    recipient_user = get_user_by_email(db, email=recipient_email)
    if not recipient_user:
        raise HTTPException(status_code=404, detail="Recipient user not found")

    try:
        # Read the file contents
        file_content = await file.read()

        # Generate a unique file name
        file_name = f"screenshot-{uuid.uuid4()}.png"

        # Upload to S3
        s3_client.put_object(
            Bucket=AWS_BUCKET_NAME,
            Key=file_name,
            Body=file_content,
            ContentType='image/png'
        )

        # Construct the image URL
        image_url = f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{file_name}"

        # Create a new BugReport entry
        bug_report = BugReport(
            image_url=image_url,
            description=description,
            recipient_id=recipient_user.id
        )

        # Add to the database
        db.add(bug_report)
        db.commit()
        db.refresh(bug_report)

        # Return the response
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

# Read Bug Report
@app.get("/bug_reports/{bug_id}")
def read_bug_report(
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if bug_report is None:
        raise HTTPException(status_code=404, detail="Bug report not found")
    return bug_report

# Update Bug Report
@app.put("/bug_reports/{bug_id}")
def update_bug_report(
    bug_id: int,
    description: Optional[str] = Form(None),
    recipient_email: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if bug_report is None:
        raise HTTPException(status_code=404, detail="Bug report not found")

    if description:
        bug_report.description = description
    if recipient_email:
        recipient_user = get_user_by_email(db, email=recipient_email)
        if not recipient_user:
            raise HTTPException(status_code=404, detail="Recipient user not found")
        bug_report.recipient_id = recipient_user.id

    db.commit()
    db.refresh(bug_report)
    return {"message": "Bug report updated", "bug_report": bug_report}

# Delete Bug Report
@app.delete("/bug_reports/{bug_id}")
def delete_bug_report(
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if bug_report is None:
        raise HTTPException(status_code=404, detail="Bug report not found")

    # Delete the image from S3
    try:
        s3_key = bug_report.image_url.split(f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/")[1]
        s3_client.delete_object(Bucket=AWS_BUCKET_NAME, Key=s3_key)
    except Exception as e:
        print(f"Error deleting image from S3: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete image from S3")

    # Delete from the database
    db.delete(bug_report)
    db.commit()
    return {"message": "Bug report deleted"}

@app.get("/bug_reports", response_model=List[BugReportResponse])
def list_bug_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    bug_reports = db.query(BugReport).options(joinedload(BugReport.recipient)).all()
    return [
        BugReportResponse(
            id=bug.id,
            image_url=bug.image_url,
            description=bug.description,
            recipient_id=bug.recipient_id,
            recipient=bug.recipient.email
        )
        for bug in bug_reports
    ]

# Endpoint to get all registered users (for recipient selection)
@app.get("/users", response_model=List[str])
def get_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    users = db.query(User).all()
    return [user.email for user in users]
