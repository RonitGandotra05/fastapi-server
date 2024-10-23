from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import boto3
import uuid
import os
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from dotenv import load_dotenv
from enum import Enum

class RecipientEnum(str, Enum):
    Ronit = "Ronit"
    Kapil = "Kapil"
    Yash = "Yash"
    Saurabh = "Saurabh"
    Sandeep_Yadav = "Sandeep Yadav"
    Shubham_Sachdeva = "Shubham Sachdeva"
    Piyush_Suneja = "Piyush Suneja"
    Yash_Kumar_Pal = "Yash Kumar Pal"
    Kapil_Sharma = "Kapil Sharma"
    Arun_Kumar = "Arun Kumar"
    Rohan_Thakur = "Rohan Thakur"
    Subhashish_Behera = "Subhashish Behera"
    Boby = "Boby"
    Ankita_Singh = "Ankita Singh"
    CP_Dhaundiyal = "CP Dhaundiyal"
    Sajal = "Sajal"
    Ryan = "Ryan"
    Karan_Grover = "Karan Grover"
    Karan_Sachdeva = "Karan Sachdeva"
    Vikas_Singh = "Vikas Singh"
    None_ = "None"

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

# Security - Authentication Token
security = HTTPBearer()

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

# Authentication Token from environment variable
API_TOKEN = os.getenv('API_TOKEN')
if not API_TOKEN:
    raise RuntimeError("API token must be set in environment variables")

# Define the database model
class BugReport(Base):
    __tablename__ = 'bug_reports'

    id = Column(Integer, primary_key=True, index=True)
    image_url = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    recipient = Column(String, nullable=False)

# Create the database tables
Base.metadata.create_all(bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Authentication dependency
def authenticate(credentials: HTTPAuthorizationCredentials = Depends(security)):
    received_token = credentials.credentials
    print(f"Received token: {received_token}")
    print(f"Expected token: {API_TOKEN}")
    if received_token != API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing API token")

# Upload Endpoint
@app.post("/upload")
async def upload_screenshot(
    file: UploadFile = File(...),
    description: str = Form(...),
    recipient: RecipientEnum = Form(...),
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    # Authenticate the request
    authenticate(credentials)

    # Log the received description and recipient name
    print(f"Received description: {description}")
    print(f"Received recipient name: {recipient}")

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
            recipient=recipient
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
            "recipient": recipient
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
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    # Authenticate the request
    authenticate(credentials)

    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if bug_report is None:
        raise HTTPException(status_code=404, detail="Bug report not found")
    return bug_report

# Update Bug Report
@app.put("/bug_reports/{bug_id}")
def update_bug_report(
    bug_id: int,
    description: Optional[str] = Form(None),
    recipient: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    # Authenticate the request
    authenticate(credentials)

    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if bug_report is None:
        raise HTTPException(status_code=404, detail="Bug report not found")

    if description:
        bug_report.description = description
    if recipient:
        bug_report.recipient = recipient

    db.commit()
    db.refresh(bug_report)
    return {"message": "Bug report updated", "bug_report": bug_report}

# Delete Bug Report
@app.delete("/bug_reports/{bug_id}")
def delete_bug_report(
    bug_id: int,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    # Authenticate the request
    authenticate(credentials)

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