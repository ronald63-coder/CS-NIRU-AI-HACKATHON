from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class ScanRequest(BaseModel):
    """Request schema for file scan"""
    filename: str
    analyze_behavior: bool = True

class ScanResponse(BaseModel):
    """Response schema for file scan"""
    filename: str
    verdict: str
    confidence: float
    risk_score: int
    threat_level: str
    detection_reasons: List[str]
    timestamp: str
    ai_models_used: List[str]

class ThreatResponse(BaseModel):
    """Threat detection response"""
    id: int
    timestamp: str
    username: Optional[str]
    threat_level: str
    file_name: Optional[str]
    verdict: str
    confidence: float
    action_taken: str

class UserRiskProfile(BaseModel):
    """User risk profile"""
    username: str
    risk_score: int
    risk_level: str
    last_login: Optional[str]
    suspicious_actions: List[str]