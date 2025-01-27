from fastapi import WebSocket
from typing import Dict, Set, Optional, List
import logging
import json
from datetime import datetime
from firebase_manager import FirebaseManager
import asyncio

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        # Store active connections by user_id
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        self.user_fcm_tokens: Dict[int, Set[str]] = {}  # Store FCM tokens
        self.firebase = FirebaseManager.get_instance()
        self.token_cleanup_lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, user_id: int):
        """Connect a WebSocket client."""
        try:
            if user_id not in self.active_connections:
                self.active_connections[user_id] = set()
            self.active_connections[user_id].add(websocket)
            logger.info(f"Client connected. User ID: {user_id}")
        except Exception as e:
            logger.error(f"Error connecting WebSocket for user {user_id}: {str(e)}")
            raise

    async def disconnect(self, websocket: WebSocket, user_id: int):
        """Disconnect a WebSocket connection."""
        try:
            if user_id in self.active_connections:
                self.active_connections[user_id].discard(websocket)
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]
            logger.info(f"Client disconnected. User ID: {user_id}")
        except Exception as e:
            logger.error(f"Error during disconnect for user {user_id}: {str(e)}")

    async def store_fcm_token(self, user_id: int, token: str):
        """Store FCM token for a user with validation."""
        try:
            if user_id not in self.user_fcm_tokens:
                self.user_fcm_tokens[user_id] = set()
            self.user_fcm_tokens[user_id].add(token)
            logger.info(f"FCM token stored for user {user_id}")
            
            # Try validating token but don't fail if Firebase is not configured
            try:
                await self.validate_token(user_id, token)
            except Exception as e:
                logger.warning(f"FCM token validation failed but continuing: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error storing FCM token for user {user_id}: {str(e)}")
            # Don't re-raise to prevent WebSocket disconnection

    async def validate_token(self, user_id: int, token: str):
        """Validate FCM token without sending a test notification."""
        try:
            # Use a silent notification for validation
            response = await self.firebase.send_notification(
                tokens=[token],
                title="",
                body="",
                data={"type": "validation"},
                is_silent=True  # This will be a silent notification
            )
            
            if response and response.failure_count > 0:
                error = response.responses[0].exception
                if 'InvalidRegistration' in str(error) or 'NotRegistered' in str(error):
                    await self.remove_fcm_token(user_id, token)
                    logger.warning(f"Removed invalid FCM token for user {user_id}")
                    raise ValueError("Invalid FCM token")
                elif 'MessageTooBig' in str(error):
                    # Token is valid but message was too big
                    return True
            return True
        except Exception as e:
            logger.error(f"Error validating FCM token for user {user_id}: {str(e)}")
            raise

    async def remove_fcm_token(self, user_id: int, token: str):
        """Remove FCM token for a user."""
        try:
            if user_id in self.user_fcm_tokens:
                self.user_fcm_tokens[user_id].discard(token)
                if not self.user_fcm_tokens[user_id]:
                    del self.user_fcm_tokens[user_id]
                logger.info(f"FCM token removed for user {user_id}")
        except Exception as e:
            logger.error(f"Error removing FCM token for user {user_id}: {str(e)}")
            raise

    async def cleanup_invalid_tokens(self):
        """Cleanup invalid FCM tokens periodically."""
        async with self.token_cleanup_lock:
            for user_id, tokens in list(self.user_fcm_tokens.items()):
                for token in list(tokens):
                    try:
                        await self.validate_token(user_id, token)
                    except Exception:
                        # Token validation failed, it will be removed in validate_token
                        pass

    async def send_personal_message(self, message: dict, user_id: int):
        """Send message to a specific user."""
        if user_id in self.active_connections:
            message_type = message.get('type', '')
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_json(message)
                    if message_type in ['ping', 'pong']:
                        logger.info(f"→ Sent {message_type} to user {user_id}")
                    else:
                        logger.debug(f"Sent message type '{message_type}' to user {user_id}")
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
        """Broadcast bug report update with enhanced notification handling."""
        try:
            # Prepare notification data
            title = "New Bug Report" if event == "created" else "Bug Report Updated"
            body = f"Bug: {bug_report.description[:100]}..."
            
            # Get relevant user IDs
            notify_users = {bug_report.creator_id, bug_report.recipient_id}
            if hasattr(bug_report, 'cc_recipients'):
                notify_users.update(cc.cc_recipient_id for cc in bug_report.cc_recipients)

            # Prepare WebSocket payload
            payload = {
                "type": "bug_report",
                "payload": {
                    "event": event,
                    "bug_report": {
                        "id": bug_report.id,
                        "description": bug_report.description,
                        "status": bug_report.status.value if hasattr(bug_report, 'status') else None,
                        "severity": bug_report.severity.value if hasattr(bug_report, 'severity') else None,
                        "creator_id": bug_report.creator_id,
                        "recipient_id": bug_report.recipient_id,
                        "project_id": bug_report.project_id if hasattr(bug_report, 'project_id') else None,
                        "modified_date": bug_report.modified_date.isoformat() if hasattr(bug_report, 'modified_date') else None
                    }
                }
            }

            # Send notifications with batching
            batch_size = 500  # FCM maximum batch size
            for user_id in notify_users:
                if user_id:
                    # Send WebSocket message
                    if user_id in self.active_connections:
                        await self.send_personal_message(payload, user_id)
                    
                    # Send FCM notification
                    if user_id in self.user_fcm_tokens:
                        tokens = list(self.user_fcm_tokens[user_id])
                        if tokens:
                            # Process tokens in batches
                            for i in range(0, len(tokens), batch_size):
                                batch_tokens = tokens[i:i + batch_size]
                                data = {
                                    "bug_id": str(bug_report.id),
                                    "event": event,
                                    "click_action": "FLUTTER_NOTIFICATION_CLICK"
                                }
                                await self.send_fcm_notification(batch_tokens, title, body, data)

        except Exception as e:
            logger.error(f"Error in broadcast_bug_report: {str(e)}")
            logger.exception("Full traceback:")

    async def send_fcm_notification(
        self,
        tokens: List[str],
        title: str,
        body: str,
        data: Optional[Dict] = None,
        max_retries: int = 3,
        is_silent: bool = False
    ):
        """Send FCM notification with enhanced error handling and silent notification support."""
        if not tokens:
            logger.warning("No FCM tokens provided for notification")
            return

        for attempt in range(max_retries):
            try:
                # Add notification priority and channel settings
                notification_config = {
                    "tokens": tokens,
                    "title": title,
                    "body": body,
                    "data": {
                        **(data or {}),
                        "click_action": "FLUTTER_NOTIFICATION_CLICK",
                        "priority": "high"
                    },
                    "is_silent": is_silent
                }

                response = await self.firebase.send_notification(**notification_config)
                
                # Handle failed tokens
                if response and response.failure_count > 0:
                    for idx, result in enumerate(response.responses):
                        if not result.success:
                            token = tokens[idx]
                            error = str(result.exception)
                            
                            # Log specific error types
                            if 'InvalidRegistration' in error:
                                logger.error(f"Invalid FCM token format: {token[:10]}...")
                            elif 'NotRegistered' in error:
                                logger.error(f"FCM token not registered: {token[:10]}...")
                            elif 'MessageTooBig' in error:
                                logger.error("FCM message payload too large")
                            else:
                                logger.error(f"FCM error: {error}")
                            
                            # Remove invalid tokens
                            for user_id, user_tokens in self.user_fcm_tokens.items():
                                if token in user_tokens:
                                    if 'InvalidRegistration' in error or 'NotRegistered' in error:
                                        await self.remove_fcm_token(user_id, token)
                                        logger.info(f"Removed invalid FCM token for user {user_id}")
                                    break
                
                if response and response.success_count > 0:
                    logger.info(f"Successfully sent FCM notification to {response.success_count} devices")
                
                return response
                
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"Failed to send FCM notification after {max_retries} attempts: {str(e)}")
                    raise
                else:
                    logger.warning(f"FCM notification attempt {attempt + 1} failed, retrying...")
                    await asyncio.sleep(1)  # Wait before retry

    async def broadcast_to_users(self, user_ids: Set[int], message: dict):
        """Broadcast message to specific users."""
        for user_id in user_ids:
            if user_id in self.active_connections:
                await self.send_personal_message(message, user_id)

    async def broadcast_to_all(self, message: dict):
        """Broadcast message to all connected users."""
        await self.broadcast(message)

manager = ConnectionManager() 