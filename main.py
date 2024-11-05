from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv
from database import SessionLocal
from models import User, Base
import os

load_dotenv()

from middleware import log_requests_middleware
from routes import users, bug_reports, projects
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

# Configure CORS
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
