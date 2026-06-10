import os
import sys

# Add backend directory to sys.path to ensure consistent imports
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Database and Models
from database import initialize_database

# Routers
from routes import upload, dashboard, logs, correlation, investigation

# Initialize Database Tables
initialize_database()

app = FastAPI(
    title="Offline Security Log Analyzer - API",
    description="Header Extraction, Normalization, and Correlation Backend"
)

# Enable CORS for development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(upload.router)
app.include_router(dashboard.router)
app.include_router(logs.router)
app.include_router(correlation.router)
app.include_router(investigation.router)

@app.get("/")
async def serve_index():
    """Root endpoint for the backend API."""
    return {"message": "AegisLog Analyzer API Backend is running."}
