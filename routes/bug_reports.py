from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session, joinedload
from database import get_db
from models import User, BugReport, BugStatus, SeverityLevel
from auth import RoleChecker, get_user_by_email
from schemas import BugReportResponse
from typing import List, Optional
from utils import send_media_with_caption
import boto3
import uuid
import os
from datetime import datetime


router = APIRouter()

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

# Upload Endpoint (Accessible by both users and admins)
@router.post("/upload")
async def upload_screenshot(
    file: UploadFile = File(...),
    description: str = Form(...),
    recipient_name: Optional[str] = Form(None),
    severity: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    # Define allowed file types and size limits
    ALLOWED_IMAGE_TYPES = {
        'image/jpeg': '.jpg',
        'image/png': '.png',
        'image/gif': '.gif',
        'image/webp': '.webp',
        'image/heic': '.heic',
        'image/heif': '.heif'
    }
    
    ALLOWED_VIDEO_TYPES = {
        'video/mp4': '.mp4',
        'video/quicktime': '.mov',
        'video/x-msvideo': '.avi',
        'video/webm': '.webm',
        'video/3gpp': '.3gp'
    }
    
    MAX_IMAGE_SIZE = 50 * 1024 * 1024  # 10MB
    MAX_VIDEO_SIZE = 500 * 1024 * 1024  # 100MB

    # Validate file type
    content_type = file.content_type.lower()
    if content_type not in ALLOWED_IMAGE_TYPES and content_type not in ALLOWED_VIDEO_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type. Allowed types: {list(ALLOWED_IMAGE_TYPES.keys()) + list(ALLOWED_VIDEO_TYPES.keys())}"
        )

    # Determine media type and extension
    if content_type in ALLOWED_IMAGE_TYPES:
        media_type = 'image'
        file_extension = ALLOWED_IMAGE_TYPES[content_type]
    else:
        media_type = 'video'
        file_extension = ALLOWED_VIDEO_TYPES[content_type]

    # Read and validate file size
    file_content = await file.read()
    file_size = len(file_content)
    
    if media_type == 'image' and file_size > MAX_IMAGE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Image size exceeds maximum limit of {MAX_IMAGE_SIZE // (1024 * 1024)}MB"
        )
    elif media_type == 'video' and file_size > MAX_VIDEO_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Video size exceeds maximum limit of {MAX_VIDEO_SIZE // (1024 * 1024)}MB"
        )

    # Handle recipient
    if recipient_name:
        recipient_user = db.query(User).filter(User.name == recipient_name).first()
        if not recipient_user:
            raise HTTPException(status_code=404, detail="Recipient user not found")
        recipient_id = recipient_user.id
    else:
        recipient_user = None
        recipient_id = None

    # Handle severity
    if severity is not None:
        try:
            severity = SeverityLevel(severity)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid severity level")
    else:
        severity = SeverityLevel.low

    try:
        # Generate unique filename and upload to S3
        file_name = f"{uuid.uuid4()}{file_extension}"
        
        # Add metadata for better file management
        metadata = {
            'original_filename': file.filename,
            'upload_date': datetime.utcnow().isoformat(),
            'uploader': current_user.name,
            'media_type': media_type
        }
        
        s3_client.put_object(
            Bucket=AWS_BUCKET_NAME,
            Key=file_name,
            Body=file_content,
            ContentType=content_type,
            Metadata=metadata
        )

        image_url = f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{file_name}"

        # For very large videos, store as link
        if media_type == 'video' and file_size > 16 * 1024 * 1024:
            media_type = 'video_link'

        # Create bug report
        bug_report = BugReport(
            image_url=image_url,
            description=description,
            recipient_id=recipient_id,
            creator_id=current_user.id,
            status=BugStatus.assigned,
            media_type=media_type,
            severity=severity,
            file_size=file_size,
            original_filename=file.filename
        )

        db.add(bug_report)
        db.commit()
        db.refresh(bug_report)

        # Send notification if recipient exists
        if recipient_user:
            try:
                caption = f"""You have been assigned a new bug report by {current_user.name}.\n\nDescription: {description}"""
                send_media_with_caption(recipient_user.phone, image_url, caption, media_type)
            except Exception as e:
                print(f"Error sending message to recipient: {e}")
                # Continue execution even if notification fails

        return {
            "message": "Upload successful",
            "id": bug_report.id,
            "url": image_url,
            "description": description,
            "recipient": recipient_user.name if recipient_user else None,
            "severity": severity.value,
            "media_type": media_type,
            "file_size": file_size,
            "original_filename": file.filename
        }

    except Exception as e:
        db.rollback()
        print(f"Error uploading to S3 or saving to DB: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Read Bug Report (Accessible by both users and admins)
@router.get("/bug_reports/{bug_id}", response_model=BugReportResponse)
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
@router.put("/bug_reports/{bug_id}")
async def update_bug_report(
    bug_id: int,
    description: Optional[str] = Form(None),
    recipient_email: Optional[str] = Form(None),
    severity: Optional[str] = Form(None),
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
    if severity:
        try:
            bug_report.severity = SeverityLevel(severity)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid severity level")

    db.commit()
    db.refresh(bug_report)
    return {
        "message": "Bug report updated",
        "bug_report": BugReportResponse.from_bug_report(bug_report)
    }

# Delete Bug Report (Accessible by both users and admins)
@router.delete("/bug_reports/{bug_id}")
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
@router.get("/bug_reports", response_model=List[BugReportResponse])
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
@router.put("/bug_reports/{bug_id}/toggle_status")
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

# Get Bug Reports Created by User (Accessible by both users and admins)
@router.get("/users/{user_id}/created_bug_reports", response_model=List[BugReportResponse])
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
@router.get("/users/{user_id}/received_bug_reports", response_model=List[BugReportResponse])
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

# Assign or Reassign Recipient to Bug Report (Admin Only)
@router.put("/bug_reports/{bug_id}/assign")
async def assign_bug_report(
    bug_id: int,
    recipient_name: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    # Fetch the bug report by ID
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if not bug_report:
        raise HTTPException(status_code=404, detail="Bug report not found")

    # Fetch the recipient user by name
    recipient_user = db.query(User).filter(User.name == recipient_name).first()
    if not recipient_user:
        raise HTTPException(status_code=404, detail="Recipient user not found")

    # Update the recipient of the bug report
    bug_report.recipient_id = recipient_user.id
    db.commit()
    db.refresh(bug_report)
    
    try:
        caption = f"""You have been assigned a bug report (ID: {bug_report.id}) by {current_user.name}.
        Description: {bug_report.description}
        """
        send_media_with_caption(recipient_user.phone, bug_report.image_url, caption, bug_report.media_type)
    except Exception as e:
        print(f"Error sending message to recipient: {e}")

    return {
        "message": "Bug report recipient updated",
        "bug_report": BugReportResponse.from_bug_report(bug_report)
    }
