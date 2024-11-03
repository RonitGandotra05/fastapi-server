from sqlalchemy import Column, Integer, String, Text, ForeignKey, Boolean, Enum as SQLAlchemyEnum, DateTime
from datetime import datetime
from sqlalchemy.orm import relationship
from enum import Enum
from database import Base

class SeverityLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


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
    recipient_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    recipient = relationship(
        "User",
        foreign_keys=[recipient_id],
        back_populates="received_bug_reports"
    )
    creator_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
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
    media_type = Column(String, nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    severity = Column(
        SQLAlchemyEnum(SeverityLevel),
        default=SeverityLevel.low,
        nullable=False
    )

