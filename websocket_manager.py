from fastapi import WebSocket
from typing import Dict, Set, Optional, List
import logging
import json
from datetime import datetime
from firebase_manager import FirebaseManager
import asyncio
import time

logger = logging.getLogger(__name__)

class ConnectionManager:
    PROJECT_ID = "bugzapp-950df"
    PACKAGE_NAME = "com.example.bugzapp"

    def __init__(self):
        # Store active connections by user_id
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        self.user_fcm_tokens: Dict[int, Set[str]] = {}  # Store FCM tokens
        self.firebase = FirebaseManager.get_instance()
        self.token_cleanup_lock = asyncio.Lock()
        self.fcm_tokens: Dict[int, Set[str]] = {}  # Added for the new store_fcm_token method

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
        """Store FCM token with validation and duplicate checking."""
        try:
            # Basic token validation
            if not token or len(token) < 50:
                logger.warning(f"Invalid FCM token format for user {user_id}")
                return False

            # Check if token already exists
            if user_id in self.fcm_tokens and token in self.fcm_tokens[user_id]:
                logger.info(f"FCM token already exists for user {user_id}")
                return True

            # Initialize set if not exists
            if user_id not in self.fcm_tokens:
                self.fcm_tokens[user_id] = set()

            # Store token
            self.fcm_tokens[user_id].add(token)
            logger.info(f"FCM token stored for user {user_id}")

            # Validate token with Firebase
            await self.validate_token(user_id, token)
            return True

        except Exception as e:
            logger.error(f"Error storing FCM token: {str(e)}")
            return False

    async def validate_token(self, user_id: int, token: str):
        """Validate FCM token with Firebase."""
        try:
            # Send a silent notification to validate token
            await self.firebase.send_notification(
                tokens=[token],
                title="Token Validation",
                body="Validating FCM token",
                is_silent=True
            )
            logger.info(f"FCM token validated for user {user_id}")
            return True
        except Exception as e:
            if "Requested entity was not found" in str(e):
                logger.warning(f"Invalid FCM token for user {user_id}: {str(e)}")
                await self.remove_fcm_token(user_id, token)
            elif "Temporary FCM service error" in str(e):
                logger.warning(f"Temporary FCM service error for user {user_id}: {str(e)}")
            else:
                logger.error(f"Error validating FCM token: {str(e)}")
            return False

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
        """Send FCM notification with enhanced error handling and data validation."""
        if not tokens:
            logger.warning("No FCM tokens provided for notification")
            return

        # Ensure all data values are strings
        sanitized_data = {}
        if data:
            try:
                for key, value in data.items():
                    sanitized_data[str(key)] = str(value)
            except Exception as e:
                logger.error(f"Error sanitizing FCM data: {e}")
                return

        for attempt in range(max_retries):
            try:
                response = await self.firebase.send_notification(
                    tokens=tokens,
                    title=title,
                    body=body,
                    data=sanitized_data,
                    is_silent=is_silent
                )
                
                if response and response.success_count > 0:
                    logger.info(f"Successfully sent FCM notification to {response.success_count} devices")
                
                # Handle failed tokens
                if response and response.failure_count > 0:
                    await self._handle_fcm_failures(response, tokens)
                
                return response
                
            except ValueError as e:
                if 'non-string values' in str(e):
                    logger.error(f"Data validation error: {e}")
                    return None
                raise
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"Failed to send FCM notification after {max_retries} attempts: {str(e)}")
                    raise
                else:
                    logger.warning(f"FCM notification attempt {attempt + 1} failed, retrying...")
                    await asyncio.sleep(1)

    async def _handle_fcm_failures(self, response, tokens):
        """Handle FCM notification failures."""
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

    async def broadcast_to_users(self, user_ids: Set[int], message: dict):
        """Broadcast message to specific users."""
        for user_id in user_ids:
            if user_id in self.active_connections:
                await self.send_personal_message(message, user_id)

    async def broadcast_to_all(self, message: dict):
        """Broadcast message to all connected users."""
        await self.broadcast(message)

manager = ConnectionManager() 