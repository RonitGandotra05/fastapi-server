from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from models import BugStatus, SeverityLevel
from datetime import datetime

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
    recipient_id: Optional[int] = None
    creator_id: Optional[int] = None  
    status: BugStatus
    recipient: Optional[str] = None
    creator: Optional[str] = None  
    media_type: str
    modified_date: datetime
    severity: SeverityLevel
    project_id: Optional[int] = None
    project_name: Optional[str] = None
    tab_url: Optional[str] = None
    cc_recipients: List[str] = []

    class Config:
        from_attributes = True
        use_enum_values = True

    @classmethod
    def from_bug_report(cls, bug_report):
        return cls(
            id=bug_report.id,
            image_url=bug_report.image_url,
            description=bug_report.description,
            recipient_id=bug_report.recipient_id,
            creator_id=bug_report.creator_id,
            status=bug_report.status.value,
            recipient=bug_report.recipient.name if bug_report.recipient else None,
            creator=bug_report.creator.email if bug_report.creator else None,  
            media_type=bug_report.media_type,
            modified_date=bug_report.modified_date,
            severity=bug_report.severity.value,
            project_id=bug_report.project_id,
            project_name=bug_report.project.name if bug_report.project else None,
            tab_url=bug_report.tab_url,
            cc_recipients=[cc.cc_recipient.name for cc in bug_report.cc_recipients]
        )
class UserUpdate(BaseModel):
    name: Optional[str]
    email: Optional[EmailStr]
    phone: Optional[str]
    is_admin: Optional[bool]

    class Config:
        from_attributes = True
        
        
class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectCreate(ProjectBase):
    pass

class ProjectUpdate(BaseModel):
    name: Optional[str]
    description: Optional[str] = None

class ProjectResponse(ProjectBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class BugReportCommentCreate(BaseModel):
    comment: str

class BugReportCommentResponse(BaseModel):
    id: int
    bug_report_id: int
    user_name: str
    comment: str
    created_at: datetime

    class Config:
        from_attributes = True

    @classmethod
    def from_comment(cls, comment):
        return cls(
            id=comment.id,
            bug_report_id=comment.bug_report_id,
            user_name=comment.user_name,
            comment=comment.comment,
            created_at=comment.created_at
        )