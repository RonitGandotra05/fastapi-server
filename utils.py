import logging
import os
import requests
from typing import Optional
import aiohttp

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
    logger.info(f"Starting send_media_with_caption: phone={phone_number}, media_url={media_url or media_link}, type={media_type}")
    
    if not media_url and not media_link:
        logger.info("No media URL, falling back to text message")
        return await send_text_message(phone_number, caption)

    token = os.getenv('ULTRAMSG_API_TOKEN')
    logger.info(f"Token retrieved: {token[:4]}..." if token else "No token found!")

    # For video_link type, always send as text message with link
    if media_type == 'video_link':
        logger.info("Video link type detected, sending as text message with link")
        message = (
            f"{caption}\n\n"
            f"*Video Link:*\n{media_url or media_link}"
            + (f"\n\n*Tab URL:*\n{tab_url}" if tab_url else "")
        )
        return await send_text_message(phone_number, message)

    # Check file size if it's a video
    file_size_mb = 0
    if media_type == 'video':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(media_url or media_link) as response:
                    file_size = int(response.headers.get('Content-Length', 0))
                    file_size_mb = file_size / (1024 * 1024)  # Convert to MB
                    logger.info(f"Video file size: {file_size_mb:.2f} MB")
        except Exception as e:
            logger.error(f"Error checking file size: {str(e)}")
            file_size_mb = 16  # Default to large size to trigger link sharing

    # For videos larger than 15MB, send as a link in the message
    if media_type == 'video' and file_size_mb > 15:
        logger.info("Video larger than 15MB, sending as link in message")
        message = (
            f"{caption}\n\n"
            f"*Video Link:*\n{media_url or media_link}"
            + (f"\n\n*Tab URL:*\n{tab_url}" if tab_url else "")
        )
        return await send_text_message(phone_number, message)

    # Determine the correct endpoint and payload based on media type
    if media_type == 'video':
        url = "https://api.ultramsg.com/instance29265/messages/video"
        payload = {
            "token": token,
            "to": f"{phone_number}@c.us",
            "video": media_url or media_link,
            "caption": caption
        }
    else:
        url = "https://api.ultramsg.com/instance29265/messages/image"
        payload = {
            "token": token,
            "to": f"{phone_number}@c.us",
            "image": media_url or media_link,
            "caption": caption
        }
    
    logger.info(f"Sending {media_type} to: {url}")
    logger.info(f"With payload: {payload}")

    try:
        # Convert payload to URL-encoded format for videos
        if media_type == 'video':
            headers = {'content-type': 'application/x-www-form-urlencoded'}
            # Convert payload to URL-encoded string
            payload_str = "&".join(f"{key}={value}" for key, value in payload.items())
            response = requests.post(url, data=payload_str, headers=headers)
        else:
            # Keep JSON format for images
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

    # Format phone number correctly
    formatted_phone = phone_number.replace("+", "").replace(" ", "").replace("-", "")
    url = "https://api.ultramsg.com/instance29265/messages/chat"
    
    payload = {
        "token": token,
        "to": f"{formatted_phone}@c.us",
        "body": message
    }
    
    logger.info(f"Sending request to: {url}")
    logger.info(f"With payload (phone): {formatted_phone}@c.us")
    logger.info(f"Message content: {message[:100]}...")  # Log first 100 chars of message

    try:
        response = requests.post(url, json=payload, headers={"Content-Type": "application/json"})
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response content: {response.text}")
        
        if response.status_code != 200:
            logger.error(f"Error response from UltraMsg API: {response.text}")
            raise Exception(f"UltraMsg API error: {response.text}")
            
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Error sending WhatsApp message: {str(e)}")
        logger.exception("Full traceback:")
        raise