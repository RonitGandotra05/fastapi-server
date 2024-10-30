from pydantic import BaseModel
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
    creator_id: int
    status: BugStatus
    recipient: Optional[str] = None
    creator: str
    media_type: str

    class Config:
        from_attributes = True

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
            creator=bug_report.creator.email,
            media_type=bug_report.media_type
        )
