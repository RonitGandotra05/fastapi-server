from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from models import BugStatus

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
            media_type=bug_report.media_type
        )

class UserUpdate(BaseModel):
    name: Optional[str]
    email: Optional[EmailStr]
    phone: Optional[str]
    is_admin: Optional[bool]

    class Config:
        from_attributes = True