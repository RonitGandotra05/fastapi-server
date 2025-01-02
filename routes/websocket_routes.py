from fastapi import APIRouter, WebSocket, HTTPException
from auth import verify_token
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

        # Prepare base message structure
        base_message = {
            "timestamp": datetime.utcnow().isoformat(),
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email
            }
        }

        if message_type == "bug_report":
            # Handle bug report updates
            bug_id = message.get("payload", {}).get("bug_id")
            if bug_id:
                bug = db.query(BugReport).get(bug_id)
                if bug:
                    await manager.broadcast({
                        "type": "bug_report",
                        "payload": {
                            **base_message,
                            "bug_report": {
                                "id": bug.id,
                                "description": bug.description,
                                "status": bug.status,
                                "severity": bug.severity,
                                "project_name": bug.project.name if bug.project else None
                            }
                        }
                    })

        elif message_type == "comment":
            # Handle comment updates
            await manager.broadcast({
                "type": "comment",
                "payload": {
                    **base_message,
                    "comment": message.get("payload", {})
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
                            **base_message,
                            "project": {
                                "id": project.id,
                                "name": project.name,
                                "description": project.description
                            }
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

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    db = None
    ping_task = None
    last_ping = datetime.utcnow()
    
    try:
        # Get token from query parameters
        token = websocket.query_params.get("token")
        logger.info(f"WebSocket connection attempt with token: {token[:10]}..." if token else "No token")
        
        if not token:
            logger.error("No token provided")
            await websocket.close(code=4001, reason="Authentication required")
            return

        # Create DB session
        db = SessionLocal()
        
        # Validate token and get user
        user = await get_current_user_from_token(token, db)
        if not user:
            logger.error("Invalid token or user not found")
            await websocket.close(code=4001, reason="Invalid token or user not found")
            return

        # Check connection limit
        if connection_counts[user.id] >= RATE_LIMITS["max_connections_per_user"]:
            logger.error(f"Too many connections for user {user.id}")
            await websocket.close(code=4009, reason="Too many connections")
            return

        logger.info(f"User authenticated: {user.email}")
        
        # Update connection count
        connection_counts[user.id] += 1
        
        # Accept the connection through the manager
        await manager.connect(websocket, user.id)
        logger.info(f"WebSocket connected for user {user.id}")
        
        # Send welcome message
        await websocket.send_json({
            "type": "system",
            "payload": {
                "message": f"Welcome {user.name}! You are now connected.",
                "timestamp": datetime.utcnow().isoformat()
            }
        })
        
        # Start ping timeout checker
        async def check_ping_timeout():
            while True:
                await asyncio.sleep(30)  # Check every 30 seconds
                if (datetime.utcnow() - last_ping) > timedelta(minutes=2):
                    logger.warning(f"Ping timeout for user {user.id}")
                    await websocket.close(code=4008, reason="Ping timeout")
                    break

        ping_task = asyncio.create_task(check_ping_timeout())
        
        try:
            while True:
                data = await websocket.receive_text()
                message = json.loads(data)
                logger.info(f"Received message from user {user.id}: {message}")
                
                if message.get("type") == "ping":
                    last_ping = datetime.utcnow()
                
                await handle_message(message, user, websocket, db)
                
        except Exception as e:
            logger.error(f"WebSocket error for user {user.id}: {str(e)}")
        finally:
            if ping_task:
                ping_task.cancel()
            connection_counts[user.id] -= 1
            await manager.disconnect(websocket, user.id)
            logger.info(f"WebSocket disconnected for user {user.id}")
    
    except Exception as e:
        logger.error(f"WebSocket connection error: {str(e)}")
        try:
            await websocket.close(code=4000, reason="Connection error")
        except:
            pass
    finally:
        if ping_task:
            ping_task.cancel()
        if db:
            db.close()

# Set up database event listeners
@event.listens_for(BugReport, 'after_insert')
def bug_report_inserted(mapper, connection, target):
    asyncio.create_task(manager.broadcast({
        "type": "bug_report",
        "payload": {
            "event": "created",
            "bug_report": {
                "id": target.id,
                "description": target.description,
                "status": target.status,
                "severity": target.severity
            }
        }
    })) 