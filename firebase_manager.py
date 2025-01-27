import firebase_admin
from firebase_admin import credentials, messaging
from typing import List, Dict, Optional
import os
import asyncio
from datetime import datetime, timedelta
import logging
import json

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window  # in seconds
        self.requests = []
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = datetime.now()
            # Remove old requests
            self.requests = [req_time for req_time in self.requests 
                           if now - req_time < timedelta(seconds=self.time_window)]
            
            if len(self.requests) >= self.max_requests:
                return False
            
            self.requests.append(now)
            return True

class FirebaseManager:
    _instance = None
    MAX_TOKENS_PER_REQUEST = 500
    MAX_RETRIES = 3
    RETRY_DELAY = 1  # seconds
    PROJECT_ID = "bugzapp-950df"

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        try:
            # Initialize Firebase Admin SDK
            if not firebase_admin._apps:
                cred = credentials.Certificate('config/credentials/firebase-service-key.json')
                firebase_admin.initialize_app(cred, {
                    'projectId': self.PROJECT_ID,
                    'storageBucket': f"{self.PROJECT_ID}.firebasestorage.app"
                })
                logger.info(f"Firebase Admin SDK initialized successfully with project ID: {self.PROJECT_ID}")
        except Exception as e:
            logger.error(f"Error initializing Firebase Admin SDK: {e}")
            raise

        # Initialize rate limiter (1000 requests per minute)
        self.rate_limiter = RateLimiter(max_requests=1000, time_window=60)

    async def send_notification(
        self,
        tokens: List[str],
        title: str,
        body: str,
        data: Optional[Dict] = None,
        is_silent: bool = False
    ):
        if not tokens:
            return

        # Sanitize data to ensure all values are strings
        sanitized_data = {}
        if data:
            for key, value in data.items():
                sanitized_data[str(key)] = str(value)

        try:
            message = messaging.MulticastMessage(
                tokens=tokens,
                notification=None if is_silent else messaging.Notification(
                    title=title,
                    body=body
                ),
                data=sanitized_data,
                android=messaging.AndroidConfig(
                    priority='high',
                    notification=messaging.AndroidNotification(
                        sound='default',
                        default_sound=True,
                        default_vibrate_timings=True,
                        default_light_settings=True,
                    )
                ),
                apns=messaging.APNSConfig(
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            sound='default',
                            badge=1
                        )
                    )
                ),
                webpush=messaging.WebpushConfig(
                    notification=messaging.WebpushNotification(
                        icon='/favicon.ico'
                    ),
                    headers={
                        'Urgency': 'high'
                    }
                )
            )

            response = messaging.send_multicast(message)
            
            if response.failure_count > 0:
                failures = []
                for idx, resp in enumerate(response.responses):
                    if not resp.success:
                        failures.append({
                            'token': tokens[idx],
                            'error': str(resp.exception)
                        })
                logger.warning(f"Failed to send to some devices: {failures}")
                
            return response

        except Exception as e:
            logger.error(f"Error sending FCM notification: {str(e)}")
            raise

    async def _send_batch(
        self,
        tokens: List[str],
        title: str,
        body: str,
        data: Optional[Dict] = None,
        is_silent: bool = False
    ):
        """Send a batch of notifications with retries and silent notification support."""
        # Configure the notification based on silent mode
        if is_silent:
            message = messaging.MulticastMessage(
                data=data or {},
                android=messaging.AndroidConfig(
                    priority='normal',
                    notification=messaging.AndroidNotification(
                        priority='default',
                        visibility='private',
                        notification_count=0
                    )
                ),
                tokens=tokens,
            )
        else:
            message = messaging.MulticastMessage(
                notification=messaging.Notification(
                    title=title,
                    body=body
                ),
                data=data or {},
                android=messaging.AndroidConfig(
                    priority='high',
                    notification=messaging.AndroidNotification(
                        sound='notification',
                        priority='max',
                        default_sound=True,
                        channel_id='bug_notifications',
                        visibility='public'
                    )
                ),
                tokens=tokens,
            )

        for attempt in range(self.MAX_RETRIES):
            try:
                response = messaging.send_multicast(message)
                
                # Log success/failure counts
                success_rate = (response.success_count / len(tokens)) * 100
                logger.info(
                    f'Batch sent: {response.success_count}/{len(tokens)} successful '
                    f'({success_rate:.1f}%)'
                )
                
                # Log failed tokens with specific error types
                if response.failure_count > 0:
                    for idx, resp in enumerate(response.responses):
                        if not resp.success:
                            error = str(resp.exception)
                            token_preview = tokens[idx][:10]
                            if 'InvalidRegistration' in error:
                                logger.error(f'Invalid token format: {token_preview}...')
                            elif 'NotRegistered' in error:
                                logger.error(f'Token not registered: {token_preview}...')
                            elif 'MessageTooBig' in error:
                                logger.error('Message payload too large')
                            else:
                                logger.error(f'Failed to send to token {token_preview}...: {error}')
                
                return response
                
            except Exception as e:
                if attempt == self.MAX_RETRIES - 1:
                    logger.error(f'Failed to send batch after {self.MAX_RETRIES} attempts: {str(e)}')
                    raise
                else:
                    logger.warning(f'Attempt {attempt + 1} failed, retrying after {self.RETRY_DELAY}s...')
                    await asyncio.sleep(self.RETRY_DELAY)

    def _aggregate_results(self, results: List[messaging.BatchResponse]):
        """Aggregate results from multiple batches."""
        if not results:
            return None
            
        total_success = sum(r.success_count for r in results)
        total_failure = sum(r.failure_count for r in results)
        
        logger.info(f'Total notifications sent: {total_success} successful, {total_failure} failed')
        
        return results[0]  # Return first batch response for compatibility 