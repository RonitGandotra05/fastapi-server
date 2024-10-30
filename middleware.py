from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from auth import SECRET_KEY, ALGORITHM
from jose import JWTError, jwt

# Middleware to log every request and the user who made the request
async def log_requests_middleware(request: Request, call_next):
    user_email = "Anonymous"
    if "authorization" in request.headers:
        auth_header = request.headers.get("authorization")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                user_email = payload.get("sub", "Anonymous")
            except JWTError:
                pass
    response = await call_next(request)
    print(f"User: {user_email} made a request to {request.method} {request.url}")
    return response
