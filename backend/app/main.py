"""
SUTRAM Main FastAPI Application Entrypoint.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="SUTRAM API",
    description="AI-Powered Multimedia Forensics Platform for Legal and Investigating Agencies",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "platform": "SUTRAM",
        "description": "AI-Powered Multimedia Forensics Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "online",
    }


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "platform": "SUTRAM",
        "version": "1.0.0",
        "mock_mode": True,
        "device": "cpu",
        "detectors_registered": 0,
        "storage_writable": True,
    }
