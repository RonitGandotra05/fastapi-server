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
    try:
        # Handle main recipient
        recipient_user = None
        recipient_id = None
        if recipient_name:
            recipient_user = db.query(User).filter(User.name == recipient_name).first()
            if not recipient_user:
                raise HTTPException(status_code=404, detail=f"Recipient user '{recipient_name}' not found")
            recipient_id = recipient_user.id
            print(f"Main recipient found: {recipient_user.name} (ID: {recipient_user.id})")

        # Handle CC recipients
        cc_recipient_users = []
        if cc_recipients:
            print(f"Processing CC recipients: {cc_recipients}")
            cc_names = [name for name in cc_recipients.split(',') if name]
            
            if len(cc_names) > 4:
                raise HTTPException(status_code=400, detail="Maximum 4 CC recipients allowed")
            
            for cc_name in cc_names:
                print(f"Looking up CC recipient: {cc_name}")
                cc_user = db.query(User).filter(User.name == cc_name).first()
                
                if not cc_user:
                    raise HTTPException(status_code=404, detail=f"CC recipient '{cc_name}' not found")
                if recipient_id and cc_user.id == recipient_id:
                    raise HTTPException(status_code=400, detail=f"Main recipient '{cc_name}' cannot be CC recipient")
                if any(existing_cc.id == cc_user.id for existing_cc in cc_recipient_users):
                    raise HTTPException(status_code=400, detail=f"Duplicate CC recipient: {cc_name}")
                
                cc_recipient_users.append(cc_user)
                print(f"Added CC recipient: {cc_user.name} (ID: {cc_user.id})")

        # Handle project
        project = None
        if project_id:
            project = db.query(Project).filter(Project.id == project_id).first()
            if not project:
                raise HTTPException(status_code=404, detail=f"Project with ID {project_id} not found")
            print(f"Project found: {project.name} (ID: {project.id})")

        # Handle severity
        try:
            severity_level = SeverityLevel(severity) if severity else SeverityLevel.low
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity level: {severity}")

        # File upload to S3
        try:
            file_content = await file.read()
            file_size = len(file_content)
            file_extension = os.path.splitext(file.filename)[1].lower()
            file_name = f"screenshot-{uuid.uuid4()}{file_extension}"
            
            print(f"Uploading file: {file_name} (size: {file_size} bytes)")
            
            s3_client.put_object(
                Bucket=AWS_BUCKET_NAME,
                Key=file_name,
                Body=file_content,
                ContentType=file.content_type
            )

            image_url = f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{file_name}"
            print(f"File uploaded successfully: {image_url}")

        except Exception as e:
            print(f"S3 upload error: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to upload file to S3")

        # Determine media type
        allowed_video_extensions = ['.mp4', '.mov', '.3gp']
        media_type = 'video' if 'video' in file.content_type else 'image'
        if media_type == 'video' and (file_size > 16 * 1024 * 1024 or file_extension not in allowed_video_extensions):
            media_type = 'video_link'
        print(f"Media type determined: {media_type}")

        # Create bug report
        try:
            bug_report = BugReport(
                image_url=image_url,
                description=description,
                recipient_id=recipient_id,
                creator_id=current_user.id,
                project_id=project.id if project else None,  # Now project is defined
                status=BugStatus.assigned,
                media_type=media_type,
                severity=severity_level,
                tab_url=tab_url
            )
            
            db.add(bug_report)
            db.flush()  # Get the bug report ID
            print(f"Bug report created with ID: {bug_report.id}")

            # Add CC recipients
            for cc_user in cc_recipient_users:
                cc_entry = BugReportCC(
                    bug_report_id=bug_report.id,
                    cc_recipient_id=cc_user.id
                )
                db.add(cc_entry)
                print(f"Added CC entry for user: {cc_user.name}")

            db.commit()
            db.refresh(bug_report)

        except Exception as e:
            db.rollback()
            print(f"Database error: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to create bug report: {str(e)}")

        # Send notifications
        try:
            # Notify main recipient
            if recipient_user and recipient_user.phone:
                caption = (
                    f"*New Bug Report*\n"
                    f"━━━━━━━━━━━━━━━━\n\n"
                    f"You have been assigned a new bug report by {current_user.name}.\n\n"
                    f"*Description:*\n{description}\n\n"
                    f"*Severity:*\n{severity_level.value}\n\n"
                    f"*Project:*\n{project.name if project else 'No Project'}\n\n"
                    f"*CC Recipients:*\n{', '.join(cc_user.name for cc_user in cc_recipient_users) if cc_recipient_users else 'None'}"
                )
                
                send_media_with_caption(
                    phone_number=recipient_user.phone,
                    media_link=image_url,
                    caption=caption,
                    media_type=media_type,
                    tab_url=tab_url
                )
                print(f"Notification sent to main recipient: {recipient_user.name}")

            # Notify CC recipients
            if cc_recipient_users and recipient_user:
                cc_caption = (
                    f"*CC: New Bug Report*\n"
                    f"━━━━━━━━━━━━━━━\n\n"
                    f"Hey {cc_user.name},\n\n"
                    f"You have been CC'd on a new bug report.\n\n"
                    f"*Assigned To:*\n{recipient_user.name}\n\n"
                    f"*Created By:*\n{current_user.name}\n\n"
                    f"*Description:*\n{description}\n\n"
                    f"*Severity:*\n{severity_level.value}\n\n"
                    f"*Project:*\n{project.name if project else 'No Project'}"
                )
                
                for cc_user in cc_recipient_users:
                    if cc_user.phone:
                        send_media_with_caption(
                            phone_number=cc_user.phone,
                            media_link=image_url,
                            caption=cc_caption,
                            media_type=media_type,
                            tab_url=tab_url
                        )
                        print(f"Notification sent to CC recipient: {cc_user.name}")

        except Exception as e:
            print(f"Notification error: {str(e)}")
            # Don't raise an exception here, as the bug report was already created successfully

        return {
            "message": "Upload successful",
            "id": bug_report.id,
            "url": image_url,
            "description": description,
            "recipient": recipient_user.name if recipient_user else None,
            "cc_recipients": [cc_user.name for cc_user in cc_recipient_users],
            "severity": severity_level.value,
            "project_name": project.name if project else None,
            "tab_url": tab_url,
            "media_type": media_type
        }

    except HTTPException as he:
        # Re-raise HTTP exceptions
        raise he
    except Exception as e:
        # Log unexpected errors
        print(f"Unexpected error: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

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
    bug_reports = db.query(BugReport).options(
        joinedload(BugReport.recipient),
        joinedload(BugReport.creator)
    ).all()
    return [BugReportResponse.from_bug_report(bug) for bug in bug_reports]

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
        base_caption = (
            f"*Bug {bug_report.status.value.title()}*\n"
            f"━━━━━━━━━━━━━━━━━━━\n\n"
            f"*Bug Report ID:*\n{bug_report.id}\n\n"
            f"*Description:*\n{bug_report.description}\n\n"
            f"*Severity:*\n{bug_report.severity.value}\n\n"
            f"*Project:*\n{bug_report.project.name if bug_report.project else 'No Project'}\n\n"
            f"*Status:*\n{bug_report.status.value}\n\n"
            f"*Updated by:*\n{current_user.name} ({current_user.email})"
        )

        # Notify creator
        creator = bug_report.creator
        if creator and creator.phone:
            creator_caption = f"Hello {creator.name}, " + base_caption
            try:
                send_media_with_caption(
                    creator.phone,
                    bug_report.image_url,
                    creator_caption,
                    bug_report.media_type,
                    tab_url=bug_report.tab_url
                )
                print(f"Notification sent to creator: {creator.name}")
            except Exception as e:
                print(f"Failed to send message to creator {creator.name} ({creator.phone}): {e}")

        # Notify CC recipients
        for cc_entry in bug_report.cc_recipients:
            cc_recipient = cc_entry.cc_recipient
            if cc_recipient and cc_recipient.phone:
                cc_caption = (
                    f"Hello {cc_recipient.name}, \n"
                    f"A bug report you were CC'd on has been resolved.\n\n"
                    + base_caption
                )
                try:
                    send_media_with_caption(
                        cc_recipient.phone,
                        bug_report.image_url,
                        cc_caption,
                        bug_report.media_type,
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
            recipient_caption = f"Hello {recipient.name}, " + base_caption
            try:
                send_media_with_caption(
                    recipient.phone,
                    bug_report.image_url,
                    recipient_caption,
                    bug_report.media_type,
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
            f"You have been assigned a bug report by {current_user.name}.\n\n"
            f"*Bug Report ID:*\n{bug_report.id}\n\n"
            f"*Description:*\n{bug_report.description}"
        )
        send_media_with_caption(
            recipient_user.phone,
            bug_report.image_url,
            caption,
            bug_report.media_type,
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

        # Format the modified date
        modified_date = bug_report.modified_date
        formatted_date = modified_date.strftime("%d %B %I:%M %p")  # e.g., "17 December 10:30 PM"

        notifications_sent = []
        failed_notifications = []

        # Define the base URL for the bug report link
        base_url = "https://exquisite-tarsier-27371d.netlify.app/homeV2/"
        bug_link = f"{base_url}{bug_id}"

        # Main recipient message
        caption = (
            f"*Reminder: Update Required*\n"
            f"━━━━━━━━━━━━━━━━\n\n"
            f"Hi {bug_report.recipient.name},\n\n"
            f"This is a reminder about a bug report assigned to you on {formatted_date}. \n\n"
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
                send_media_with_caption(
                    phone_number=bug_report.recipient.phone,
                    media_link=bug_report.image_url,
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
                    f"Hi {cc_recipient.name},\n\n"
                    f"A reminder has been sent for a bug report you're following. \n\n"
                    f"{current_user.name} has requested an update from {bug_report.recipient.name}. "
                    f"You can track the progress here: {bug_link}\n\n"
                    f"*Bug Report Details*\n"
                    f"━━━━━━━━━━━━━━━━\n\n"
                    f"*ID:*\n{bug_report.id}\n\n"
                    f"*Description:*\n{bug_report.description}\n\n"
                    f"*Severity:*\n{bug_report.severity.value}\n\n"
                    f"*Status:*\n{bug_report.status.value}\n\n"
                    f"*Project:*\n{bug_report.project.name if bug_report.project else 'No Project'}\n\n"
                    f"*Originally Assigned:*\n{formatted_date}"
                )
                try:
                    send_media_with_caption(
                        phone_number=cc_recipient.phone,
                        media_link=bug_report.image_url,
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

        response = {
            "message": "Reminder sent",
            "notifications_sent": notifications_sent,
            "failed_notifications": failed_notifications,
            "bug_report_id": bug_report.id,
            "requested_by": current_user.name,
            "timestamp": datetime.utcnow().strftime("%d %B %I:%M %p")
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
    # Check if bug report exists
    bug_report = db.query(BugReport).options(
        joinedload(BugReport.creator),
        joinedload(BugReport.recipient),
        joinedload(BugReport.cc_recipients).joinedload(BugReportCC.cc_recipient)
    ).filter(BugReport.id == bug_id).first()
    
    if not bug_report:
        raise HTTPException(status_code=404, detail="Bug report not found")

    # Create new comment
    new_comment = BugReportComment(
        bug_report_id=bug_id,
        user_name=current_user.name,
        comment=comment_data.comment
    )
    
    try:
        db.add(new_comment)
        db.commit()
        db.refresh(new_comment)
        
        # Prepare the base message for notifications
        base_message = (
            f"*Update on Bug Report from {current_user.name}*\n"
            f"━━━━━━━━━━━━━━━━\n\n"
            f"*Bug ID:*\n{bug_id}\n\n"
            f"*Update Message:*\n{comment_data.comment}\n\n"
            f"*View Bug Report:*\nhttps://exquisite-tarsier-27371d.netlify.app/homeV2/{bug_id}"
        )
        
        # Send notifications
        try:
            # Notify creator if they're not the commenter
            if bug_report.creator and bug_report.creator.phone and bug_report.creator.name != current_user.name:
                creator_message = f"Hi {bug_report.creator.name},\n\n" + base_message
                send_text_message(bug_report.creator.phone, creator_message)
                print(f"Notification sent to creator: {bug_report.creator.name}")

            # Notify recipient if they're not the commenter
            if bug_report.recipient and bug_report.recipient.phone and bug_report.recipient.name != current_user.name:
                recipient_message = f"Hi {bug_report.recipient.name},\n\n" + base_message
                send_text_message(bug_report.recipient.phone, recipient_message)
                print(f"Notification sent to recipient: {bug_report.recipient.name}")

            # Notify CC recipients
            for cc_entry in bug_report.cc_recipients:
                if (cc_entry.cc_recipient and 
                    cc_entry.cc_recipient.phone and 
                    cc_entry.cc_recipient.name != current_user.name):
                    cc_message = f"Hi {cc_entry.cc_recipient.name},\n\n" + base_message
                    send_text_message(cc_entry.cc_recipient.phone, cc_message)
                    print(f"Notification sent to CC recipient: {cc_entry.cc_recipient.name}")

        except Exception as e:
            print(f"Error sending notifications: {e}")
            # Continue even if notifications fail
            
        return BugReportCommentResponse.from_comment(new_comment)
        
    except Exception as e:
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