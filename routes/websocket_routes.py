from fastapi import APIRouter, WebSocket, HTTPException, Depends
from auth import verify_token, get_current_user
from models import User, BugReport, Project
from websocket_manager import manager
import json
from datetime import datetime, timedelta
from typing import Optional, Dict
import logging
from database import SessionLocal
from sqlalchemy.orm import Session
from sqlalchemy import event
import asyncio
from collections import defaultdict
import time
from sqlalchemy.orm import joinedload
from models import BugReportCC
import re

router = APIRouter()
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Rate limiting
RATE_LIMITS = {
    "messages_per_minute": 60,
    "max_connections_per_user": 10,
    "max_message_size": 64 * 1024  # 64KB
}

# Store message counts for rate limiting
message_counts: Dict[int, list] = defaultdict(list)
connection_counts: Dict[int, int] = defaultdict(int)

async def get_current_user_from_token(token: str, db: Session) -> Optional[User]:
    try:
        payload = verify_token(token)
        user_email = payload.get("sub")
        if user_email is None:
            return None
        user = db.query(User).filter(User.email == user_email).first()
        return user
    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        return None

def check_rate_limit(user_id: int) -> bool:
    """Check if user has exceeded rate limits."""
    current_time = time.time()
    # Clean up old messages
    message_counts[user_id] = [t for t in message_counts[user_id] 
                             if current_time - t < 60]
    
    # Check limits
    if len(message_counts[user_id]) >= RATE_LIMITS["messages_per_minute"]:
        return False
    if connection_counts[user_id] >= RATE_LIMITS["max_connections_per_user"]:
        return False
    
    return True

async def handle_message(message: dict, user: User, websocket: WebSocket, db: Session):
    """Handle different types of messages."""
    try:
        # Check message size
        message_size = len(json.dumps(message))
        if message_size > RATE_LIMITS["max_message_size"]:
            await websocket.send_json({
                "type": "error",
                "payload": {
                    "code": "message_too_large",
                    "message": "Message exceeds size limit"
                }
            })
            return

        # Check rate limit
        if not check_rate_limit(user.id):
            await websocket.send_json({
                "type": "error",
                "payload": {
                    "code": "rate_limit",
                    "message": "Rate limit exceeded"
                }
            })
            return

        # Record message timestamp for rate limiting
        message_counts[user.id].append(time.time())

        message_type = message.get("type", "")
        
        if message_type == "ping":
            await websocket.send_json({
                "type": "pong",
                "payload": {
                    "timestamp": datetime.utcnow().isoformat()
                }
            })
            return

        if message_type == "bug_report":
            # Handle bug report updates
            bug_id = message.get("payload", {}).get("bug_id")
            if bug_id:
                bug = db.query(BugReport).options(
                    joinedload(BugReport.creator),
                    joinedload(BugReport.recipient),
                    joinedload(BugReport.project),
                    joinedload(BugReport.cc_recipients).joinedload(BugReportCC.cc_recipient)
                ).get(bug_id)
                if bug:
                    await manager.broadcast_bug_report(bug, "updated")

        elif message_type == "comment":
            # Handle comment updates
            await manager.broadcast({
                "type": "comment",
                "payload": {
                    "user": {
                        "id": user.id,
                        "name": user.name,
                        "email": user.email
                    },
                    "comment": message.get("payload", {}),
                    "timestamp": datetime.utcnow().isoformat()
                }
            })

        elif message_type == "project":
            # Handle project updates
            project_id = message.get("payload", {}).get("project_id")
            if project_id:
                project = db.query(Project).get(project_id)
                if project:
                    await manager.broadcast({
                        "type": "project",
                        "payload": {
                            "user": {
                                "id": user.id,
                                "name": user.name,
                                "email": user.email
                            },
                            "project": {
                                "id": project.id,
                                "name": project.name,
                                "description": project.description,
                                "created_at": project.created_at.isoformat() if project.created_at else None,
                                "updated_at": project.updated_at.isoformat() if project.updated_at else None
                            },
                            "timestamp": datetime.utcnow().isoformat()
                        }
                    })

        else:
            # Handle unknown message types
            await websocket.send_json({
                "type": "error",
                "payload": {
                    "code": "invalid_message",
                    "message": f"Unknown message type: {message_type}"
                }
            })

    except Exception as e:
        logger.error(f"Error handling message: {str(e)}")
        await websocket.send_json({
            "type": "error",
            "payload": {
                "code": "server_error",
                "message": "Internal server error"
            }
        })

def validate_fcm_token(token: str) -> bool:
    """Validate FCM token format."""
    # Basic FCM token validation
    if not token or len(token) < 100:
        return False
    # Check if token matches FCM format (alphanumeric with colons)
    if not re.match(r'^[a-zA-Z0-9:_-]{100,}$', token):
        return False
    return True

@router.post("/fcm/token")
async def register_fcm_token(
    token: str,
    current_user: User = Depends(get_current_user)
):
    """Register FCM token for a user with enhanced validation and logging."""
    logger.info(f"FCM token registration request for user {current_user.id}")
    
    if not validate_fcm_token(token):
        logger.error(f"Invalid FCM token format for user {current_user.id}")
        raise HTTPException(status_code=400, detail="Invalid FCM token format")
    
    try:
        # Check if token is already registered
        if (current_user.id in manager.user_fcm_tokens and 
            token in manager.user_fcm_tokens[current_user.id]):
            logger.info(f"FCM token already registered for user {current_user.id}")
            return {"message": "Token already registered"}
            
        await manager.store_fcm_token(current_user.id, token)
        logger.info(f"FCM token registered for user {current_user.id}")
        return {"message": "Token registered successfully"}
    except ValueError as e:
        logger.error(f"Validation error for FCM token: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error registering FCM token for user {current_user.id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/fcm/token")
async def remove_fcm_token(
    token: str,
    current_user: User = Depends(get_current_user)
):
    """Remove FCM token for a user."""
    if not validate_fcm_token(token):
        logger.error(f"Invalid FCM token format for user {current_user.id}")
        raise HTTPException(status_code=400, detail="Invalid FCM token format")
    
    try:
        await manager.remove_fcm_token(current_user.id, token)
        logger.info(f"FCM token removed for user {current_user.id}")
        return {"message": "Token removed successfully"}
    except Exception as e:
        logger.error(f"Error removing FCM token for user {current_user.id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    ping_task = None
    db = None
    user = None
    fcm_token = None
    connection_successful = False
    
    try:
        # Get token from query parameters
        token = websocket.query_params.get("token")
        if not token:
            logger.error("WebSocket connection attempt without token")
            await websocket.close(code=4001, reason="Token not provided")
            return

        # Get FCM token from query parameters
        fcm_token = websocket.query_params.get("fcm_token")
        
        # Create database session
        db = SessionLocal()
        
        try:
            # Verify token synchronously first
            payload = verify_token(token)
            user_email = payload.get("sub")
            if user_email is None:
                raise ValueError("Invalid token payload")
                
            # Get user from database
            user = db.query(User).filter(User.email == user_email).first()
            if not user:
                raise ValueError("User not found")
                
        except Exception as e:
            logger.error(f"Token verification failed: {str(e)}")
            await websocket.close(code=4002, reason="Invalid token")
            return

        # Accept the connection
        await websocket.accept()
        connection_successful = True
        
        # Add connection to manager
        await manager.connect(websocket, user.id)
        
        # Store FCM token if provided
        if fcm_token and validate_fcm_token(fcm_token):
            await manager.store_fcm_token(user.id, fcm_token)
            
        # Start ping task
        async def send_ping():
            while True:
                try:
                    await asyncio.sleep(30)
                    await websocket.send_json({"type": "ping"})
                except:
                    break
                    
        ping_task = asyncio.create_task(send_ping())
        
        # Handle incoming messages
        while True:
            try:
                data = await websocket.receive_text()
                if not data:
                    continue
                    
                try:
                    message = json.loads(data)
                    if not isinstance(message, dict):
                        logger.warning(f"Received non-dict message: {message}")
                        continue
                        
                    message_type = message.get('type')
                    if message_type == 'ping':
                        await websocket.send_json({
                            'type': 'pong',
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    else:
                        await handle_message(message, user, websocket, db)
                except json.JSONDecodeError as e:
                    if data != 'ping':  # Ignore JSON decode errors for ping messages
                        logger.warning(f"Invalid JSON received: {data[:100]}")
                    else:
                        await websocket.send_json({
                            'type': 'pong',
                            'timestamp': datetime.utcnow().isoformat()
                        })
            except Exception as e:
                if "websocket.receive" in str(e):
                    logger.info("Client disconnected")
                else:
                    logger.error(f"Error handling message: {str(e)}")
                break

    except Exception as e:
        logger.error(f"WebSocket connection error: {str(e)}")
    finally:
        if ping_task:
            ping_task.cancel()
        if db:
            db.close()
        
        # Update connection count
        if user and hasattr(user, 'id'):
            connection_counts[user.id] = max(0, connection_counts.get(user.id, 1) - 1)
            
        # Only remove FCM token if we had a successful connection and it's the last connection
        if (connection_successful and fcm_token and user and hasattr(user, 'id') and 
            connection_counts.get(user.id, 0) == 0):
            try:
                await manager.remove_fcm_token(user.id, fcm_token)
                logger.info(f"FCM token removed on disconnect for user {user.id}")
            except Exception as e:
                logger.error(f"Error removing FCM token for user {user.id}: {str(e)}")
        
        if user and hasattr(user, 'id'):
            try:
                await manager.disconnect(websocket, user.id)
                logger.info(f"WebSocket connection closed for user {user.id}")
            except Exception as e:
                logger.error(f"Error disconnecting WebSocket for user {user.id}: {str(e)}")

# Set up database event listeners
@event.listens_for(BugReport, 'after_insert')
def bug_report_inserted(mapper, connection, target):
    """Handle new bug report creation."""
    asyncio.create_task(manager.broadcast_bug_report(target, "created"))

@event.listens_for(BugReport, 'after_update')
def bug_report_updated(mapper, connection, target):
    """Handle bug report updates."""
    asyncio.create_task(manager.broadcast_bug_report(target, "updated")) 