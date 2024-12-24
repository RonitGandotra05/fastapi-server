import logging
import os
import requests
from typing import Optional

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def send_media_with_caption(
    phone_number: str, 
    media_url: Optional[str] = None,
    media_link: Optional[str] = None,
    caption: str = "",
    media_type: str = "image",
    tab_url: Optional[str] = None
):
    logger.info(f"Starting send_media_with_caption: phone={phone_number}, media_url={media_url or media_link}")
    
    if not media_url and not media_link:
        logger.info("No media URL, falling back to text message")
        return await send_text_message(phone_number, caption)

    token = os.getenv('ULTRAMSG_API_TOKEN')
    logger.info(f"Token retrieved: {token[:4]}..." if token else "No token found!")

    url = "https://api.ultramsg.com/instance29265/messages/image"
    payload = {
        "token": token,
        "to": f"{phone_number}@c.us",
        "image": media_url or media_link,
        "caption": caption
    }
    
    logger.info(f"Sending request to: {url}")
    logger.info(f"With payload: {payload}")

    try:
        response = requests.post(url, json=payload, headers={"Content-Type": "application/json"})
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response content: {response.text}")
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Error sending WhatsApp message: {str(e)}")
        raise

async def send_text_message(phone_number: str, message: str):
    logger.info(f"Starting send_text_message: phone={phone_number}")
    
    token = os.getenv('ULTRAMSG_API_TOKEN')
    if not token:
        logger.error("ULTRAMSG_API_TOKEN not found in environment variables")
        raise ValueError("ULTRAMSG_API_TOKEN not configured")
    
    logger.info(f"Token retrieved: {token[:4]}...")

    url = "https://api.ultramsg.com/instance29265/messages/chat"
    payload = {
        "token": token,
        "to": f"{phone_number}@c.us",
        "body": message
    }
    
    logger.info(f"Sending request to: {url}")
    logger.info(f"With payload: {payload}")

    try:
        response = requests.post(url, json=payload, headers={"Content-Type": "application/json"})
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response content: {response.text}")
        
        if response.status_code != 200:
            logger.error(f"Error response from UltraMsg API: {response.text}")
            
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Error sending WhatsApp message: {str(e)}")
        logger.exception("Full traceback:")
        raise