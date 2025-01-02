from fastapi import APIRouter, WebSocket, Depends, HTTPException
from auth import get_current_user
from models import User, BugReport
from websocket_manager import manager
import json
from datetime import datetime
from typing import Optional
import logging

router = APIRouter()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    try:
        # Get token from query parameters
        token = websocket.query_params.get("token")
        logger.info(f"WebSocket connection attempt with token: {token[:10]}..." if token else "No token")
        
        if not token:
            logger.error("No token provided")
            await websocket.close(code=4001, reason="Authentication required")
            return

        # Validate token and get user
        try:
            user = await get_current_user(token)
            logger.info(f"User authenticated: {user.email}")
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            await websocket.close(code=4001, reason="Invalid token")
            return

        await manager.connect(websocket, user.id)
        logger.info(f"WebSocket connected for user {user.id}")
        
        try:
            while True:
                data = await websocket.receive_text()
                message = json.loads(data)
                logger.info(f"Received message from user {user.id}: {message}")
                
                if message.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                    logger.debug(f"Sent pong to user {user.id}")
                    continue
                
        except Exception as e:
            logger.error(f"WebSocket error for user {user.id}: {str(e)}")
        finally:
            await manager.disconnect(websocket, user.id)
            logger.info(f"WebSocket disconnected for user {user.id}")
    
    except Exception as e:
        logger.error(f"WebSocket connection error: {str(e)}")
        await websocket.close(code=4000, reason="Connection error") 