from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session, joinedload
from database import get_db
from models import User, BugReport, BugStatus, SeverityLevel, Project, BugReportCC, BugReportComment  # Added BugReportCC and BugReportComment here
from auth import RoleChecker, get_user_by_email
from schemas import BugReportResponse, BugReportCommentCreate, BugReportCommentResponse
from typing import List, Optional
from utils import send_media_with_caption, send_text_message
import boto3
import uuid
import os
from datetime import datetime, timezone, timedelta
import aiohttp
from fastapi.responses import StreamingResponse
import io
from pydantic import BaseModel
import logging
from events import notify_bug_report_update, notify_comment_update
import ffmpeg
from tempfile import NamedTemporaryFile

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

# Update the response models to handle timezone properly
class BugReportResponse(BaseModel):
    id: int
    image_url: str
    description: str
    recipient_id: Optional[int]
    creator_id: Optional[int]
    status: str
    recipient: Optional[str] = None
    creator: Optional[str] = None
    media_type: str
    modified_date: datetime
    severity: str
    project_id: Optional[int]
    project_name: Optional[str]
    tab_url: Optional[str]
    cc_recipients: List[str]

    class Config:
        json_encoders = {
            # Ensure all datetime fields are converted to UTC ISO format
            datetime: lambda dt: dt.replace(tzinfo=timezone.utc).isoformat()
        }

    @classmethod
    def from_bug_report(cls, bug_report):
        return cls(
            id=bug_report.id,
            image_url=bug_report.image_url,
            description=bug_report.description,
            recipient_id=bug_report.recipient_id,
            creator_id=bug_report.creator_id,
            status=bug_report.status.value,
            recipient=bug_report.recipient.name if bug_report.recipient else "",
            creator=bug_report.creator.email if bug_report.creator else None,
            media_type=bug_report.media_type,
            # Add UTC timezone info to the timestamp
            modified_date=bug_report.modified_date.replace(tzinfo=timezone.utc),
            severity=bug_report.severity.value,
            project_id=bug_report.project_id,
            project_name=bug_report.project.name if bug_report.project else None,
            tab_url=bug_report.tab_url,
            cc_recipients=[cc.cc_recipient.name for cc in bug_report.cc_recipients] if bug_report.cc_recipients else []
        )

class BugReportCommentResponse(BaseModel):
    id: int
    bug_report_id: int
    user_name: str
    comment: str
    created_at: datetime

    class Config:
        json_encoders = {
            datetime: lambda dt: dt.replace(tzinfo=timezone.utc).isoformat()
        }

    @classmethod
    def from_comment(cls, comment):
        return cls(
            id=comment.id,
            bug_report_id=comment.bug_report_id,
            user_name=comment.user_name,
            comment=comment.comment,
            # Add UTC timezone info to the timestamp
            created_at=comment.created_at.replace(tzinfo=timezone.utc)
        )

@router.post("/upload")
async def upload_screenshot(
    file: UploadFile = File(...),
    description: str = Form(...),
    recipient_name: Optional[str] = Form(None),
    cc_recipients: Optional[str] = Form(None),
    severity: Optional[str] = Form(None),
    project_id: Optional[int] = Form(None),
    tab_url: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    """
    Upload a bug report with media (image or video).
    Supported video formats: mp4, mov, 3gp
    Maximum video size: 16MB
    """
    try:
        print("\n=== ROLE CHECK ===")
        print(f"Required Roles: ['user', 'admin']")
        print(f"User: {current_user.name}")
        print(f"User Roles: {'admin' if current_user.is_admin else 'user'}")

        # Validate file type
        content_type = file.content_type.lower()
        allowed_image_types = ["image/png", "image/jpeg", "image/jpg", "image/gif"]
        allowed_video_types = ["video/mp4", "video/quicktime", "video/3gpp"]  # mov is video/quicktime
        
        if content_type not in allowed_image_types + allowed_video_types:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type. Allowed types: PNG, JPEG, JPG, GIF, MP4, MOV, 3GP"
            )

        # Read file content
        content = await file.read()
        size_mb = len(content) / (1024 * 1024)  # Convert to MB
        
        print(f"Video size: {size_mb:.2f}MB")
        
        # Initialize media_type based on content type
        media_type = 'video' if file.content_type.startswith('video/') else 'image'
        
        if size_mb > 15 and file.content_type.startswith('video/'):
            print(f"Large video detected ({size_mb:.2f}MB). Attempting compression...")
            
            try:
                # Create temporary files for input and output
                with NamedTemporaryFile(suffix=os.path.splitext(file.filename)[1], delete=False) as temp_in, \
                     NamedTemporaryFile(suffix='.mp4', delete=False) as temp_out:
                    
                    # Write original video to temp file
                    temp_in.write(content)
                    temp_in.flush()
                    
                    # Compress video using ffmpeg
                    stream = ffmpeg.input(temp_in.name)
                    stream = ffmpeg.output(stream, temp_out.name, 
                        vcodec='libx264',
                        acodec='aac',
                        preset='medium',
                        crf=28,  # Adjust compression quality (23-28 is good range)
                        movflags='+faststart'
                    )
                    ffmpeg.run(stream, overwrite_output=True)
                    
                    # Read compressed file
                    with open(temp_out.name, 'rb') as f:
                        compressed_content = f.read()
                    
                    compressed_size_mb = len(compressed_content) / (1024 * 1024)
                    print(f"Compressed video size: {compressed_size_mb:.2f}MB")
                    
                    # If compression was successful and size is now acceptable
                    if compressed_size_mb <= 15:
                        content = compressed_content
                        size_mb = compressed_size_mb
                        print("Using compressed video")
                    else:
                        print("Compressed video still too large, will send as link")
                        media_type = 'video_link'
                
                # Cleanup temp files
                os.unlink(temp_in.name)
                os.unlink(temp_out.name)
                
            except Exception as e:
                print(f"Compression failed: {str(e)}, will send as link")
                media_type = 'video_link'
        
        # Find recipient
        recipient = None
        if recipient_name:
            recipient = db.query(User).filter(User.name == recipient_name).first()
            if not recipient:
                raise HTTPException(status_code=404, detail=f"Recipient {recipient_name} not found")
            print(f"Main recipient found: {recipient.name} (ID: {recipient.id})")

        # Find project
        project = None
        if project_id:
            project = db.query(Project).filter(Project.id == project_id).first()
            if project:
                print(f"Project found: {project.name} (ID: {project.id})")

        # File upload to S3
        try:
            # Generate unique filename with correct extension
            file_name = f"screenshot-{uuid.uuid4()}{os.path.splitext(file.filename)[1]}"
            
            print(f"Uploading file: {file_name} (size: {size_mb:.2f}MB, type: {content_type})")
            
            s3_client.put_object(
                Bucket=AWS_BUCKET_NAME,
                Key=file_name,
                Body=content,
                ContentType=content_type
            )

            image_url = f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{file_name}"
            print(f"File uploaded successfully: {image_url}")

        except Exception as e:
            print(f"S3 upload error: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to upload file to S3")

        # Create bug report
        bug_report = BugReport(
            image_url=image_url,
            description=description,
            recipient_id=recipient.id if recipient else None,
            creator_id=current_user.id,
            status=BugStatus.assigned,
            media_type=media_type,
            modified_date=datetime.now(timezone.utc),
            severity=SeverityLevel(severity) if severity else SeverityLevel.low,
            project_id=project.id if project else None,
            tab_url=tab_url
        )
        
        db.add(bug_report)
        db.commit()
        db.refresh(bug_report)
        print(f"Bug report created with ID: {bug_report.id}")

        # Process CC recipients
        if cc_recipients:
            cc_names = [name.strip() for name in cc_recipients.split(',') if name]
            
            # Validate CC recipient count
            if len(cc_names) > 4:
                raise HTTPException(status_code=400, detail="Maximum 4 CC recipients allowed")
            
            cc_recipient_users = []  # Keep track of added CC recipients
            for cc_name in cc_names:
                cc_user = db.query(User).filter(User.name == cc_name).first()
                if not cc_user:
                    raise HTTPException(status_code=404, detail=f"CC recipient '{cc_name}' not found")
                
                # Check if CC recipient is the main recipient
                if recipient and cc_user.id == recipient.id:
                    raise HTTPException(status_code=400, detail=f"Main recipient '{cc_name}' cannot be CC recipient")
                
                # Check for duplicate CC recipients
                if any(existing_cc.id == cc_user.id for existing_cc in cc_recipient_users):
                    raise HTTPException(status_code=400, detail=f"Duplicate CC recipient: {cc_name}")
                
                cc_recipient_users.append(cc_user)
                cc_entry = BugReportCC(
                    bug_report_id=bug_report.id,
                    cc_recipient_id=cc_user.id
                )
                db.add(cc_entry)
                print(f"Added CC recipient: {cc_user.name} (ID: {cc_user.id})")
            db.commit()

        # Send WhatsApp notification to recipient
        if recipient and recipient.phone:
            print(f"Sending WhatsApp notification to: {recipient.phone}")
            caption = (
                f"*New Bug Report*\n"
                f"━━━━━━━━━━━━━━━━\n\n"
                f"Hello {recipient.name},\n\n"
                f"You have been assigned a new bug report by {current_user.name}.\n\n"
                f"*Description:*\n{description}\n\n"
                f"*Severity:*\n{severity}\n\n"
                f"*Project:*\n{project.name if project else 'No Project'}\n\n"
                f"*CC Recipients:*\n{cc_recipients if cc_recipients else 'None'}"
            )
            await send_media_with_caption(
                phone_number=recipient.phone,
                media_url=image_url,
                caption=caption,
                media_type=media_type,
                tab_url=tab_url
            )
            print("WhatsApp notification sent successfully")

        # Send notifications to CC recipients
        if cc_recipients:
            cc_names = [name.strip() for name in cc_recipients.split(',')]
            for cc_name in cc_names:
                cc_user = db.query(User).filter(User.name == cc_name).first()
                if cc_user and cc_user.phone:
                    cc_caption = (
                        f"*CC: New Bug Report*\n"
                        f"━━━━━━━━━━━━━━━━\n\n"
                        f"Hello {cc_user.name},\n\n"
                        f"You have been CC'd on a new bug report.\n\n"
                        f"*Assigned to:* {recipient.name if recipient else 'Unassigned'}\n\n"
                        f"*Description:*\n{description}\n\n"
                        f"*Severity:*\n{severity}\n\n"
                        f"*Project:*\n{project.name if project else 'No Project'}\n\n"
                        f"*Created by:*\n{current_user.name}"
                    )
                    await send_media_with_caption(
                        phone_number=cc_user.phone,
                        media_url=image_url,
                        caption=cc_caption,
                        media_type=media_type,
                        tab_url=tab_url
                    )

        # Broadcast the update via WebSocket
        await notify_bug_report_update(
            bug_report.id,
            "created",
            {recipient.id} if recipient else set(),
            {"description": description},
            db
        )

        return {
            "message": "Upload successful",
            "id": bug_report.id,
            "url": image_url,
            "description": description,
            "recipient": recipient_name,
            "cc_recipients": cc_recipients.split(',') if cc_recipients else [],
            "severity": severity,
            "project_name": project.name if project else None,
            "tab_url": tab_url,
            "media_type": media_type
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error in upload_screenshot: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/bug_reports/{bug_id}", response_model=BugReportResponse)
async def read_bug_report(
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    bug_report = db.query(BugReport).options(
        joinedload(BugReport.recipient),
        joinedload(BugReport.creator),
        joinedload(BugReport.cc_recipients).joinedload(BugReportCC.cc_recipient)
    ).filter(BugReport.id == bug_id).first()
    
    if bug_report is None:
        raise HTTPException(status_code=404, detail="Bug report not found")

    if not current_user.is_admin and current_user.id not in [
        bug_report.creator_id, 
        bug_report.recipient_id, 
        *[cc.cc_recipient_id for cc in bug_report.cc_recipients]
    ]:
        raise HTTPException(status_code=403, detail="Access forbidden")

    return BugReportResponse.from_bug_report(bug_report)

    
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

@router.delete("/bug_reports/{bug_id}")
async def delete_bug_report(
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if bug_report is None:
        raise HTTPException(status_code=404, detail="Bug report not found")

    if not current_user.is_admin and bug_report.creator_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access forbidden")

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

@router.get("/bug_reports", response_model=List[BugReportResponse])
async def list_bug_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    try:
        bug_reports = db.query(BugReport).options(
            joinedload(BugReport.recipient),
            joinedload(BugReport.creator),
            joinedload(BugReport.project),
            joinedload(BugReport.cc_recipients).joinedload(BugReportCC.cc_recipient)
        ).all()
        
        return [BugReportResponse.from_bug_report(bug) for bug in bug_reports]
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error while fetching bug reports: {str(e)}"
        )

@router.put("/bug_reports/{bug_id}/toggle_status")
async def toggle_bug_report_status(
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    bug_report = db.query(BugReport).options(
        joinedload(BugReport.creator),
        joinedload(BugReport.recipient),
        joinedload(BugReport.project),
        joinedload(BugReport.cc_recipients).joinedload(BugReportCC.cc_recipient)  # Add this line
    ).filter(BugReport.id == bug_id).first()

    if not bug_report:
        raise HTTPException(status_code=404, detail="Bug report not found")

    # Check if current user is admin, creator, recipient, or CC recipient
    is_cc_recipient = any(cc.cc_recipient_id == current_user.id for cc in bug_report.cc_recipients)
    if not current_user.is_admin and current_user.id not in [bug_report.creator_id, bug_report.recipient_id] and not is_cc_recipient:
        raise HTTPException(status_code=403, detail="Access forbidden")

    previous_status = bug_report.status
    if bug_report.status == BugStatus.assigned:
        bug_report.status = BugStatus.resolved
    elif bug_report.status == BugStatus.resolved:
        bug_report.status = BugStatus.assigned
    else:
        raise HTTPException(status_code=400, detail="Invalid bug report status")

    db.commit()
    db.refresh(bug_report)

    # If status changed to resolved, notify the creator and CC recipients
    if previous_status != BugStatus.resolved and bug_report.status == BugStatus.resolved:
        # Base message for main recipient and creator
        base_caption = (
            f"*Bug {bug_report.status.value.title()}*\n"
            f"━━━━━━━━━━━━━━━━━━\n\n"
            f"Hello {bug_report.recipient.name},\n\n"
            f"*Bug Report ID:*\n{bug_report.id}\n\n"
            f"*Description:*\n{bug_report.description}\n\n"
            f"*Severity:*\n{bug_report.severity.value}\n\n"
            f"*Project:*\n{bug_report.project.name if bug_report.project else 'No Project'}\n\n"
            f"*Status:*\n{bug_report.status.value}\n\n"
            f"*Updated by:*\n{current_user.name} ({current_user.email})"
        )

        # Base URL for bug reports
        base_url = "https://bugszap.netlify.app/homeV2/"
        bug_link = f"{base_url}{bug_id}"

        # Notify creator with their own greeting
        creator = bug_report.creator
        if creator and creator.phone:
            creator_caption = (
                f"*Bug {bug_report.status.value.title()}*\n"
                f"━━━━━━━━━━━━━━━━━━━\n\n"
                f"Hello {creator.name},\n\n"
                f"*Bug Report ID:*\n{bug_report.id}\n\n"
                f"*Description:*\n{bug_report.description}\n\n"
                f"*Severity:*\n{bug_report.severity.value}\n\n"
                f"*Project:*\n{bug_report.project.name if bug_report.project else 'No Project'}\n\n"
                f"*Status:*\n{bug_report.status.value}\n\n"
                f"*Updated by:*\n{current_user.name} ({current_user.email})\n\n"
                f"*View Bug Report:*\n{bug_link}"
                + (f"\n\n*Tab URL:*\n{bug_report.tab_url}" if bug_report.tab_url else "")
            )
            try:
                await send_media_with_caption(
                    phone_number=creator.phone,
                    media_url=bug_report.image_url,
                    caption=creator_caption,
                    media_type=bug_report.media_type,
                    tab_url=bug_report.tab_url
                )
                print(f"Notification sent to creator: {creator.name}")
            except Exception as e:
                print(f"Failed to send message to creator {creator.name} ({creator.phone}): {e}")

        # Notify CC recipients with their own greeting
        for cc_entry in bug_report.cc_recipients:
            cc_recipient = cc_entry.cc_recipient
            if cc_recipient and cc_recipient.phone:
                cc_caption = (
                    f"*CC: Bug {bug_report.status.value.title()}*\n"
                    f"━━━━━━━━━━━━━━━\n\n"
                    f"Hello {cc_recipient.name},\n\n"
                    f"*Bug Report ID:*\n{bug_report.id}\n\n"
                    f"*Description:*\n{bug_report.description}\n\n"
                    f"*Severity:*\n{bug_report.severity.value}\n\n"
                    f"*Project:*\n{bug_report.project.name if bug_report.project else 'No Project'}\n\n"
                    f"*Status:*\n{bug_report.status.value}\n\n"
                    f"*Updated by:*\n{current_user.name} ({current_user.email})\n\n"
                    f"*View Bug Report:*\n{bug_link}"
                    + (f"\n\n*Tab URL:*\n{bug_report.tab_url}" if bug_report.tab_url else "")
                )
                try:
                    await send_media_with_caption(
                        phone_number=cc_recipient.phone,
                        media_url=bug_report.image_url,
                        caption=cc_caption,
                        media_type=bug_report.media_type,
                        tab_url=bug_report.tab_url
                    )
                    print(f"Notification sent to CC recipient: {cc_recipient.name}")
                except Exception as e:
                    print(f"Failed to send message to CC recipient {cc_recipient.name} ({cc_recipient.phone}): {e}")

        # Notify main recipient if different from creator and resolver
        recipient = bug_report.recipient
        if (recipient and recipient.phone and 
            recipient.id != creator.id and 
            recipient.id != current_user.id):
            recipient_caption = (
                f"*Bug {bug_report.status.value.title()}*\n"
                f"━━━━━━━━━━━━━━━━━━━\n\n"
                f"Hello {recipient.name},\n\n"
                f"*Bug Report ID:*\n{bug_report.id}\n\n"
                f"*Description:*\n{bug_report.description}\n\n"
                f"*Severity:*\n{bug_report.severity.value}\n\n"
                f"*Project:*\n{bug_report.project.name if bug_report.project else 'No Project'}\n\n"
                f"*Status:*\n{bug_report.status.value}\n\n"
                f"*Updated by:*\n{current_user.name} ({current_user.email})\n\n"
                f"*View Bug Report:*\n{bug_link}"
                + (f"\n\n*Tab URL:*\n{bug_report.tab_url}" if bug_report.tab_url else "")
            )
            try:
                await send_media_with_caption(
                    phone_number=recipient.phone,
                    media_url=bug_report.image_url,
                    caption=recipient_caption,
                    media_type=bug_report.media_type,
                    tab_url=bug_report.tab_url
                )
                print(f"Notification sent to recipient: {recipient.name}")
            except Exception as e:
                print(f"Failed to send message to recipient {recipient.name} ({recipient.phone}): {e}")

    return {
        "message": "Bug report status toggled",
        "bug_report": BugReportResponse.from_bug_report(bug_report),
        "toggled_by": {
            "id": current_user.id,
            "name": current_user.name,
            "email": current_user.email
        }
    }
@router.get("/users/{user_id}/created_bug_reports", response_model=List[BugReportResponse])
async def get_bug_reports_created_by_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not current_user.is_admin and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Access forbidden")

    bug_reports = db.query(BugReport).options(
        joinedload(BugReport.recipient),
        joinedload(BugReport.creator)
    ).filter(BugReport.creator_id == user_id).all()
    return [BugReportResponse.from_bug_report(bug) for bug in bug_reports]

@router.get("/users/{user_id}/received_bug_reports", response_model=List[BugReportResponse])
async def get_bug_reports_assigned_to_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access forbidden")

    bug_reports = db.query(BugReport).options(
        joinedload(BugReport.recipient),
        joinedload(BugReport.creator)
    ).filter(BugReport.recipient_id == user_id).all()
    return [BugReportResponse.from_bug_report(bug) for bug in bug_reports]

@router.put("/bug_reports/{bug_id}/assign")
async def assign_bug_report(
    bug_id: int,
    recipient_name: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if not bug_report:
        raise HTTPException(status_code=404, detail="Bug report not found")

    recipient_user = db.query(User).filter(User.name == recipient_name).first()
    if not recipient_user:
        raise HTTPException(status_code=404, detail="Recipient user not found")

    bug_report.recipient_id = recipient_user.id
    db.commit()
    db.refresh(bug_report)

    try:
        caption = (
            f"*Bug Reassigned*\n"
            f"━━━━━━━━━━━━━━━━\n\n"
            f"Hello {recipient_user.name},\n\n"
            f"You have been assigned a bug report by {current_user.name}.\n\n"
            f"*Bug Report ID:*\n{bug_report.id}\n\n"
            f"*Description:*\n{bug_report.description}"
        )
        await send_media_with_caption(
            phone_number=recipient_user.phone,
            media_url=bug_report.image_url,
            caption=caption,
            media_type=bug_report.media_type,
            tab_url=bug_report.tab_url
        )
    except Exception as e:
        print(f"Error sending message to recipient: {e}")

    return {
        "message": "Bug report recipient updated",
        "bug_report": BugReportResponse.from_bug_report(bug_report)
    }

@router.post("/bug_reports/{bug_id}/send_reminder")
async def send_bug_report_reminder(
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    try:
        bug_report = db.query(BugReport).options(
            joinedload(BugReport.recipient),
            joinedload(BugReport.creator),
            joinedload(BugReport.project),
            joinedload(BugReport.cc_recipients).joinedload(BugReportCC.cc_recipient)
        ).filter(BugReport.id == bug_id).first()

        if not bug_report:
            raise HTTPException(status_code=404, detail="Bug report not found")

        if not current_user.is_admin and bug_report.creator_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only admins or the bug report creator can send reminders")

        # Convert UTC to IST by adding 5 hours and 30 minutes
        modified_date = bug_report.modified_date + timedelta(hours=5, minutes=30)
        formatted_date = modified_date.strftime("%d %B %I:%M %p")  # e.g., "17 December 10:30 PM"

        notifications_sent = []
        failed_notifications = []

        # Define the base URL for the bug report link
        base_url = "https://bugszap.netlify.app/homeV2/"
        bug_link = f"{base_url}{bug_id}"

        # Main recipient message
        caption = (
            f"*Reminder: Update Required*\n"
            f"━━━━━━━━━━━━━━━━\n\n"
            f"Hello {bug_report.recipient.name},\n\n"
            f"This is a reminder about a bug report assigned to you on {formatted_date} IST.\n\n"
            f"Could you please provide an update on its status on the following link: {bug_link}\n\n"
            f"*Bug Report Details*\n"
            f"━━━━━━━━━━━━━━━━\n\n"
            f"*ID:*\n{bug_report.id}\n\n"
            f"*Description:*\n{bug_report.description}\n\n"
            f"*Severity:*\n{bug_report.severity.value}\n\n"
            f"*Status:*\n{bug_report.status.value}\n\n"
            f"*Project:*\n{bug_report.project.name if bug_report.project else 'No Project'}\n\n"
            f"*Reminder from:*\n{current_user.name}"
        )

        # Send to main recipient
        if bug_report.recipient and bug_report.recipient.phone:
            try:
                await send_media_with_caption(
                    phone_number=bug_report.recipient.phone,
                    media_url=bug_report.image_url,
                    caption=caption,
                    media_type=bug_report.media_type,
                    tab_url=bug_report.tab_url
                )
                notifications_sent.append(bug_report.recipient.name)
            except Exception as e:
                failed_notifications.append({
                    "user": bug_report.recipient.name,
                    "error": str(e)
                })

        # Send to CC recipients
        for cc_entry in bug_report.cc_recipients:
            cc_recipient = cc_entry.cc_recipient
            if cc_recipient and cc_recipient.phone:
                # CC recipients message - moved inside the loop
                cc_caption = (
                    f"*CC: Update Requested*\n"
                    f"━━━━━━━━━━━━━━━━\n\n"
                    f"Hello {cc_recipient.name},\n\n"
                    f"A reminder has been sent for a bug report you're following.\n\n"
                    f"{current_user.name} has requested an update from {bug_report.recipient.name}. "
                    f"You can track the progress here: {bug_link}\n\n"
                    f"*Bug Report Details*\n"
                    f"━━━━━━━━━━━━━━━━\n\n"
                    f"*ID:*\n{bug_report.id}\n\n"
                    f"*Description:*\n{bug_report.description}\n\n"
                    f"*Severity:*\n{bug_report.severity.value}\n\n"
                    f"*Status:*\n{bug_report.status.value}\n\n"
                    f"*Project:*\n{bug_report.project.name if bug_report.project else 'No Project'}\n\n"
                    f"*Originally Assigned:*\n{formatted_date} IST"
                )
                try:
                    await send_media_with_caption(
                        phone_number=cc_recipient.phone,
                        media_url=bug_report.image_url,
                        caption=cc_caption,
                        media_type=bug_report.media_type,
                        tab_url=bug_report.tab_url
                    )
                    notifications_sent.append(cc_recipient.name)
                except Exception as e:
                    failed_notifications.append({
                        "user": cc_recipient.name,
                        "error": str(e)
                    })

        # Get current time in IST
        current_time_ist = datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)
        response = {
            "message": "Reminder sent",
            "notifications_sent": notifications_sent,
            "failed_notifications": failed_notifications,
            "bug_report_id": bug_report.id,
            "requested_by": current_user.name,
            "timestamp": current_time_ist.strftime("%d %B %I:%M %p IST")
        }

        if failed_notifications:
            response["warning"] = "Some notifications failed to send"

        return response

    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error in send_bug_report_reminder: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# Endpoint to add a comment
@router.post("/bug_reports/{bug_id}/comments", response_model=BugReportCommentResponse)
async def add_bug_report_comment(
    bug_id: int,
    comment_data: BugReportCommentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    print(f"Adding comment to bug {bug_id} by user {current_user.name}")
    
    # Check if bug report exists with all necessary relationships loaded
    bug_report = db.query(BugReport).options(
        joinedload(BugReport.creator),
        joinedload(BugReport.recipient),
        joinedload(BugReport.project),
        joinedload(BugReport.cc_recipients).joinedload(BugReportCC.cc_recipient)
    ).filter(BugReport.id == bug_id).first()
    
    if not bug_report:
        raise HTTPException(status_code=404, detail="Bug report not found")

    print(f"Found bug report. Creator: {bug_report.creator.name if bug_report.creator else 'None'}, "
          f"Recipient: {bug_report.recipient.name if bug_report.recipient else 'None'}")

    # Create new comment
    new_comment = BugReportComment(
        bug_report_id=bug_id,
        user_name=current_user.name,
        comment=comment_data.comment,
        created_at=datetime.now(timezone.utc)
    )
    
    try:
        db.add(new_comment)
        db.commit()
        db.refresh(new_comment)
        print(f"Comment added successfully. ID: {new_comment.id}")
        
        # Keep track of who has been notified to avoid duplicates
        notified_users = set()
        notification_results = []
        
        # Base message with better formatting
        base_message = (
            f"*New Comment on Bug Report*\n"
            f"━━━━━━━━━━━━━━━━\n\n"
            f"*Bug Report Details*\n"
            f"ID: {bug_id}\n"
            f"Project: {bug_report.project.name if bug_report.project else 'No Project'}\n"
            f"Status: {bug_report.status.value}\n"
            f"Severity: {bug_report.severity.value}\n\n"
            f"*New Comment by {current_user.name}*\n"
            f"{comment_data.comment}\n\n"
            f"*View Bug Report:*\n"
            f"https://bugszap.netlify.app/homeV2/{bug_id}"
            + (f"\n\n*Original Tab URL:*\n{bug_report.tab_url}" if bug_report.tab_url else "")
        )
        
        # Notify creator
        if bug_report.creator and bug_report.creator.phone:
            print(f"Attempting to notify creator: {bug_report.creator.name} at {bug_report.creator.phone}")
            if bug_report.creator.id != current_user.id and bug_report.creator.id not in notified_users:
                creator_message = (
                    f"*New Comment on Your Bug Report*\n"
                    f"━━━━━━━━━━━━━━━━\n\n"
                    f"Hello {bug_report.creator.name},\n\n"
                    + base_message
                )
                try:
                    await send_text_message(bug_report.creator.phone, creator_message)
                    notification_results.append(f"Notified creator: {bug_report.creator.name}")
                    notified_users.add(bug_report.creator.id)
                    print(f"Successfully notified creator {bug_report.creator.name}")
                except Exception as e:
                    print(f"Failed to notify creator: {str(e)}")
                    notification_results.append(f"Failed to notify creator {bug_report.creator.name}: {str(e)}")
            else:
                print(f"Skipping creator notification - same as commenter or already notified")

        # Notify recipient
        if bug_report.recipient and bug_report.recipient.phone:
            print(f"Attempting to notify recipient: {bug_report.recipient.name} at {bug_report.recipient.phone}")
            if bug_report.recipient.id != current_user.id and bug_report.recipient.id not in notified_users:
                recipient_message = (
                    f"*New Comment on Assigned Bug Report*\n"
                    f"━━━━━━━━━━━━━━━━\n\n"
                    f"Hello {bug_report.recipient.name},\n\n"
                    + base_message
                )
                try:
                    await send_text_message(bug_report.recipient.phone, recipient_message)
                    notification_results.append(f"Notified recipient: {bug_report.recipient.name}")
                    notified_users.add(bug_report.recipient.id)
                    print(f"Successfully notified recipient {bug_report.recipient.name}")
                except Exception as e:
                    print(f"Failed to notify recipient: {str(e)}")
                    notification_results.append(f"Failed to notify recipient {bug_report.recipient.name}: {str(e)}")
            else:
                print(f"Skipping recipient notification - same as commenter or already notified")

        # Notify CC recipients
        for cc_entry in bug_report.cc_recipients:
            if cc_entry.cc_recipient and cc_entry.cc_recipient.phone:
                print(f"Attempting to notify CC recipient: {cc_entry.cc_recipient.name} at {cc_entry.cc_recipient.phone}")
                if cc_entry.cc_recipient.id != current_user.id and cc_entry.cc_recipient.id not in notified_users:
                    cc_message = (
                        f"*CC: New Comment on Bug Report*\n"
                        f"━━━━━━━━━━━━━━━━\n\n"
                        f"Hello {cc_entry.cc_recipient.name},\n\n"
                        + base_message
                    )
                    try:
                        await send_text_message(cc_entry.cc_recipient.phone, cc_message)
                        notification_results.append(f"Notified CC recipient: {cc_entry.cc_recipient.name}")
                        notified_users.add(cc_entry.cc_recipient.id)
                        print(f"Successfully notified CC recipient {cc_entry.cc_recipient.name}")
                    except Exception as e:
                        print(f"Failed to notify CC recipient: {str(e)}")
                        notification_results.append(f"Failed to notify CC recipient {cc_entry.cc_recipient.name}: {str(e)}")
                else:
                    print(f"Skipping CC recipient notification - same as commenter or already notified")

        # Log final results
        print("\nNotification Results:")
        for result in notification_results:
            print(result)
            
        # Get affected users (creator, recipient, CC recipients)
        affected_users = {bug_report.creator_id, bug_report.recipient_id}
        affected_users.update(cc.cc_recipient_id for cc in bug_report.cc_recipients)
        affected_users.discard(None)  # Remove None values

        # Notify via WebSocket
        await notify_comment_update(
            comment_id=new_comment.id,
            bug_report_id=bug_id,
            event_type="comment_created",
            affected_users=affected_users,
            data={
                "id": new_comment.id,
                "bug_report_id": bug_id,
                "user_name": current_user.name,
                "comment": comment_data.comment,
                "created_at": new_comment.created_at.isoformat()
            }
        )

        return BugReportCommentResponse.from_comment(new_comment)
        
    except Exception as e:
        print(f"Error in add_bug_report_comment: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to add comment: {str(e)}")

# Endpoint to view comments
@router.get("/bug_reports/{bug_id}/comments", response_model=List[BugReportCommentResponse])
async def get_bug_report_comments(
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    # First check if the bug report exists
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if not bug_report:
        raise HTTPException(status_code=404, detail="Bug report not found")

    # Check if user has permission to view this bug report
    is_cc_recipient = any(cc.cc_recipient_id == current_user.id for cc in bug_report.cc_recipients)
    if not current_user.is_admin and current_user.id not in [bug_report.creator_id, bug_report.recipient_id] and not is_cc_recipient:
        raise HTTPException(status_code=403, detail="Access forbidden")

    # Get all comments for this bug report, ordered by creation time (newest first)
    comments = db.query(BugReportComment).filter(
        BugReportComment.bug_report_id == bug_id
    ).order_by(BugReportComment.created_at.desc()).all()

    return [BugReportCommentResponse.from_comment(comment) for comment in comments]

@router.get("/image/{image_name}")
async def get_image(image_name: str):
    try:
        url = f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{image_name}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    content = await response.read()
                    return StreamingResponse(
                        io.BytesIO(content),
                        media_type=response.headers.get('Content-Type', 'image/png')
                    )
                return {"error": "Image not found"}, 404
    except Exception as e:
        print(f"Error fetching image: {e}")
        return {"error": str(e)}, 500

@router.get("/all_comments", response_model=List[BugReportCommentResponse])
async def get_all_comments(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    """
    Get all comments across all bug reports.
    """
    try:
        # Get all comments with related bug report information
        comments = (
            db.query(BugReportComment)
            .join(BugReport, BugReportComment.bug_report_id == BugReport.id)
            .options(
                joinedload(BugReportComment.bug_report)
                .joinedload(BugReport.creator),
                joinedload(BugReportComment.bug_report)
                .joinedload(BugReport.recipient),
                joinedload(BugReportComment.bug_report)
                .joinedload(BugReport.project)
            )
            .order_by(BugReportComment.created_at.desc())
            .all()
        )

        # Create a more detailed response
        class DetailedCommentResponse(BugReportCommentResponse):
            bug_report_description: str
            bug_report_status: str
            bug_report_severity: str
            bug_report_creator: Optional[str]
            bug_report_recipient: Optional[str]
            project_name: Optional[str]

            class Config:
                from_attributes = True

        detailed_comments = []
        for comment in comments:
            bug_report = comment.bug_report
            detailed_comment = DetailedCommentResponse(
                id=comment.id,
                bug_report_id=comment.bug_report_id,
                user_name=comment.user_name,
                comment=comment.comment,
                created_at=comment.created_at,
                bug_report_description=bug_report.description if bug_report else "N/A",
                bug_report_status=bug_report.status.value if bug_report else "N/A",
                bug_report_severity=bug_report.severity.value if bug_report else "N/A",
                bug_report_creator=bug_report.creator.name if bug_report and bug_report.creator else "N/A",
                bug_report_recipient=bug_report.recipient.name if bug_report and bug_report.recipient else "N/A",
                project_name=bug_report.project.name if bug_report and bug_report.project else "N/A"
            )
            detailed_comments.append(detailed_comment)

        return detailed_comments

    except Exception as e:
        print(f"Error fetching all comments: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch comments: {str(e)}"
        )