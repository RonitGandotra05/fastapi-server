from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv
import os

load_dotenv()

from middleware import log_requests_middleware
from routes import users, bug_reports
from database import Base, engine

# Create the database tables
Base.metadata.create_all(bind=engine)

# Define the FastAPI app
app = FastAPI()

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
