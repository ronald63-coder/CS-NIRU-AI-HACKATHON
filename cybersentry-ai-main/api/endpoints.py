from fastapi import APIRouter, UploadFile, File, HTTPException
from datetime import datetime
import json

router = APIRouter(prefix="/api/v1", tags=["cybersentry"])

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "cybersentry-ai",
        "version": "2.0",
        "timestamp": datetime.now().isoformat()
    }

@router.get("/stats")
async def get_stats():
    """Get system statistics"""
    # This will be implemented later with actual data
    return {
        "total_scans": 0,
        "threats_detected": 0,
        "users_blocked": 0,
        "system_uptime": "0 hours",
        "ai_model_status": "active"
    }