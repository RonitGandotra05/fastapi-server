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

class BugReportCC(Base):
    __tablename__ = 'bug_report_cc'
    
    id = Column(Integer, primary_key=True, index=True)
    bug_report_id = Column(Integer, ForeignKey('bug_reports.id', ondelete='CASCADE'))
    cc_recipient_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    
    bug_report = relationship("BugReport", back_populates="cc_recipients")
    cc_recipient = relationship("User")

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
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_bug_reports")
    creator_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    creator = relationship("User", foreign_keys=[creator_id], back_populates="created_bug_reports")
    status = Column(SQLAlchemyEnum(BugStatus), default=BugStatus.assigned, nullable=False)
    media_type = Column(String, nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    severity = Column(SQLAlchemyEnum(SeverityLevel), default=SeverityLevel.low, nullable=False)
    project_id = Column(Integer, ForeignKey('projects.id', ondelete='SET NULL'), nullable=True)
    project = relationship('Project', back_populates='bug_reports')
    tab_url = Column(String, nullable=True)
    cc_recipients = relationship("BugReportCC", back_populates="bug_report", cascade="all, delete-orphan")
    comments = relationship("BugReportComment", back_populates="bug_report", cascade="all, delete-orphan")

class Project(Base):
    __tablename__ = 'projects'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    bug_reports = relationship('BugReport', back_populates='project')

class BugReportComment(Base):
    __tablename__ = 'bug_report_comments'

    id = Column(Integer, primary_key=True, index=True)
    bug_report_id = Column(Integer, ForeignKey('bug_reports.id', ondelete='CASCADE'))
    user_name = Column(String, nullable=False)
    comment = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Only keep the bug_report relationship
    bug_report = relationship("BugReport", back_populates="comments")