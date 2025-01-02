from websocket_manager import manager
from datetime import datetime
from typing import Set, Optional

async def notify_bug_report_update(
    bug_report_id: int,
    event_type: str,
    affected_users: Set[int],
    data: dict
):
    message = {
        "type": "bug_report",
        "payload": {
            "event": event_type,
            "bug_id": bug_report_id,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    await manager.broadcast_to_users(affected_users, message)

async def notify_comment_update(
    comment_id: int,
    bug_report_id: int,
    event_type: str,
    affected_users: Set[int],
    data: dict
):
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