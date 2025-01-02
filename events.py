from websocket_manager import manager
from datetime import datetime
from typing import Set, Optional
from sqlalchemy.orm import Session
from models import BugReport

async def notify_bug_report_update(
    bug_report_id: int,
    event_type: str,
    affected_users: Set[int],
    data: dict,
    db: Session
):
    """
    Notify users about bug report updates with complete data.
    """
    bug_report = db.query(BugReport).get(bug_report_id)
    if bug_report:
        await manager.broadcast_bug_report(bug_report, event_type)

async def notify_comment_update(
    comment_id: int,
    bug_report_id: int,
    event_type: str,
    affected_users: Set[int],
    data: dict
):
    """
    Notify users about comment updates.
    """
    message = {
        "type": "comment",
        "payload": {
            "event": event_type,
            "comment_id": comment_id,
            "bug_id": bug_report_id,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    await manager.broadcast_to_users(affected_users, message)

async def notify_project_update(
    project_id: int,
    event_type: str,
    data: dict
):
    """
    Notify all users about project updates.
    """
    message = {
        "type": "project",
        "payload": {
            "event": event_type,
            "project_id": project_id,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    await manager.broadcast_to_all(message)

async def notify_user_update(
    user_id: int,
    event_type: str,
    data: dict
):
    """
    Notify all users about user updates.
    """
    message = {
        "type": "user",
        "payload": {
            "event": event_type,
            "user_id": user_id,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    await manager.broadcast_to_all(message) 