from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv
from database import SessionLocal
from models import User, Base
import os
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

load_dotenv()

from middleware import log_requests_middleware
from routes import users, bug_reports, projects, websocket_routes
from database import Base, engine

Base.metadata.create_all(bind=engine)

def create_deleted_user():
    db = SessionLocal()
    try:
        deleted_user = db.query(User).filter(User.name == "Deleted User").first()
        if not deleted_user:
            deleted_user = User(
                id=0,
                name="Deleted User",
                email="deleted@gmail.com",
                phone=None,
                password_hash="",
                is_admin=False
            )
            db.add(deleted_user)
            db.commit()
    finally:
        db.close()

app = FastAPI()


create_deleted_user()

# Configure CORS with WebSocket support
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add middleware
app.add_middleware(BaseHTTPMiddleware, dispatch=log_requests_middleware)

# Include routers
app.include_router(users.router)
app.include_router(bug_reports.router)
app.include_router(projects.router)
app.include_router(websocket_routes.router, prefix="")  # No prefix for WebSocket routes

# Mount static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Add route for test page
@app.get("/ws-test", response_class=HTMLResponse)
async def get_ws_test_page():
    with open("static/websocket_test.html", "r") as f:
        return f.read()
