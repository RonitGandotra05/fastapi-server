from fastapi import WebSocket
from typing import Dict, Set
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        # Store active connections by user_id
        self.active_connections: Dict[int, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        self.active_connections[user_id].add(websocket)
        logger.info(f"User {user_id} connected. Total connections: {len(self.active_connections[user_id])}")

    async def disconnect(self, websocket: WebSocket, user_id: int):
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
            logger.info(f"User {user_id} disconnected")

    async def send_personal_message(self, message: dict, user_id: int):
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_json(message)
                    logger.debug(f"Sent message to user {user_id}")
                except Exception as e:
                    logger.error(f"Error sending message to user {user_id}: {str(e)}")

    async def broadcast(self, message: dict, exclude_user: int = None):
        for user_id, connections in self.active_connections.items():
            if exclude_user and user_id == exclude_user:
                continue
            for connection in connections:
                try:
                    await connection.send_json(message)
                    logger.debug(f"Broadcast message to user {user_id}")
                except Exception as e:
                    logger.error(f"Error broadcasting to user {user_id}: {str(e)}")

    async def broadcast_bug_report(self, bug_report, event: str):
        """Broadcast bug report with complete data, safely handling null fields."""
        try:
            # Safely get values with null checks
            try:
                status = bug_report.status.value if bug_report.status else "unknown"
            except AttributeError:
                status = "unknown"

            try:
                severity = bug_report.severity.value if bug_report.severity else "unknown"
            except AttributeError:
                severity = "unknown"

            # Safely get related object values
            creator = {
                "id": bug_report.creator_id,
                "name": bug_report.creator.name if bug_report.creator else None,
                "email": bug_report.creator.email if bug_report.creator else None
            } if bug_report.creator_id is not None else None

            recipient = {
                "id": bug_report.recipient_id,
                "name": bug_report.recipient.name if bug_report.recipient else None,
                "email": bug_report.recipient.email if bug_report.recipient else None
            } if bug_report.recipient_id is not None else None

            project = {
                "id": bug_report.project_id,
                "name": bug_report.project.name if bug_report.project else None
            } if bug_report.project_id is not None else None

            # Safely get CC recipients
            cc_recipients = []
            if hasattr(bug_report, 'cc_recipients') and bug_report.cc_recipients:
                for cc in bug_report.cc_recipients:
                    try:
                        if cc.cc_recipient:
                            cc_recipients.append({
                                "id": cc.cc_recipient_id,
                                "name": cc.cc_recipient.name
                            })
                    except Exception as cc_error:
                        logger.error(f"Error processing CC recipient: {str(cc_error)}")

            payload = {
                "type": "bug_report",
                "payload": {
                    "event": event,
                    "bug_report": {
                        "id": bug_report.id,
                        "description": bug_report.description or "",
                        "status": status,
                        "severity": severity,
                        "image_url": bug_report.image_url or None,
                        "creator": creator,
                        "recipient": recipient,
                        "project": project,
                        "media_type": bug_report.media_type or "unknown",
                        "modified_date": bug_report.modified_date.isoformat() if bug_report.modified_date else None,
                        "tab_url": bug_report.tab_url or None,
                        "cc_recipients": cc_recipients
                    },
                    "timestamp": datetime.utcnow().isoformat()
                }
            }

            # Log the payload for debugging
            logger.debug(f"Broadcasting bug report payload: {json.dumps(payload, indent=2)}")

            await self.broadcast(payload)
            logger.info(f"Broadcast bug report update: {event} for bug ID {bug_report.id}")
        except Exception as e:
            logger.error(f"Error broadcasting bug report: {str(e)}")
            logger.exception("Full traceback:")

    async def broadcast_to_users(self, user_ids: Set[int], message: dict):
        """Broadcast message to specific users."""
        for user_id in user_ids:
            if user_id in self.active_connections:
                await self.send_personal_message(message, user_id)

    async def broadcast_to_all(self, message: dict):
        """Broadcast message to all connected users."""
        await self.broadcast(message)

manager = ConnectionManager() 