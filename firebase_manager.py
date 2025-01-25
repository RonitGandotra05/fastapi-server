import firebase_admin
from firebase_admin import credentials, messaging
from typing import List, Dict, Optional
import os
import asyncio
from datetime import datetime, timedelta
import logging

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

    def __init__(self):
        # Get the absolute path to the root directory
        root_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Default credentials file in root directory
        default_cred_path = os.path.join(root_dir, 'bugzapp-950df-firebase-adminsdk-fbsvc-935ae16d72.json')
        
        # Use environment variable if set, otherwise use default path
        cred_path = os.getenv('FIREBASE_CREDENTIALS_PATH', default_cred_path)
        
        try:
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
            logger.info(f"Firebase initialized successfully with credentials from: {cred_path}")
        except ValueError as e:
            # App already initialized
            logger.warning(f"Firebase app already initialized: {str(e)}")
        except Exception as e:
            logger.error(f"Error initializing Firebase: {str(e)}")
            raise

        # Initialize rate limiter (1000 requests per minute)
        self.rate_limiter = RateLimiter(max_requests=1000, time_window=60)

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = FirebaseManager()
        return cls._instance

    async def send_notification(
        self,
        tokens: List[str],
        title: str,
        body: str,
        data: Optional[Dict] = None,
        is_silent: bool = False
    ):
        """Send FCM notification with batching, rate limiting and silent notification support."""
        if not tokens:
            logger.warning("No tokens provided for notification")
            return None

        if not await self.rate_limiter.acquire():
            logger.warning("Rate limit exceeded, delaying notification")
            await asyncio.sleep(1)
            return await self.send_notification(tokens, title, body, data, is_silent)

        results = []
        
        # Process tokens in batches
        for i in range(0, len(tokens), self.MAX_TOKENS_PER_REQUEST):
            batch = tokens[i:i + self.MAX_TOKENS_PER_REQUEST]
            batch_result = await self._send_batch(batch, title, body, data, is_silent)
            if batch_result:
                results.append(batch_result)
            
            # Small delay between batches to prevent rate limiting
            if i + self.MAX_TOKENS_PER_REQUEST < len(tokens):
                await asyncio.sleep(0.1)
        
        return self._aggregate_results(results)

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