import os
import requests

def send_media_with_caption(phone_number, media_link, caption, media_type):
    token = os.getenv('ULTRAMSG_API_TOKEN')
    if not token:
        print("Error: ULTRAMSG_API_TOKEN is not set.")
        return

    if media_type == 'image':
        url = f"https://api.ultramsg.com/instance29265/messages/image"
        payload = {
            "token": token,
            "to": f"{phone_number}@c.us",
            "image": media_link,
            "caption": caption
        }
    elif media_type == 'video':
        url = f"https://api.ultramsg.com/instance29265/messages/video"
        payload = {
            "token": token,
            "to": f"{phone_number}@c.us",
            "video": media_link,
            "caption": caption
        }
    else:
        raise ValueError("Unsupported media type")
    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        raise
    except Exception as e:
        print(f"An error occurred: {e}")
        raise