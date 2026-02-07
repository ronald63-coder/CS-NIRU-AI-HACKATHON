from datetime import datetime
from typing import Dict, List

class UserBehaviorAnalyzer:
    """Analyze user behavior for anomalies"""
    
    def __init__(self):
        self.user_profiles = {}
    
    def analyze_login(self, username: str, login_data: Dict) -> Dict:
        """Analyze login behavior"""
        risk_score = 0
        reasons = []
        
        # Check login time
        login_time = login_data.get("time", "12:00")
        hour = int(login_time.split(":")[0])
        
        if 0 <= hour <= 4:  # Midnight to 4 AM
            risk_score += 30
            reasons.append("Unusual login time (midnight-4AM)")
        
        # Check location
        location = login_data.get("location", "")
        if location.lower() in ["foreign", "vpn", "proxy"]:
            risk_score += 20
            reasons.append(f"Suspicious location: {location}")
        
        # Check device
        device = login_data.get("device", "")
        if device.lower() == "new_device":
            risk_score += 15
            reasons.append("New device detected")
        
        # Determine risk level
        if risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "username": username,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reasons": reasons,
            "timestamp": datetime.now().isoformat()
        }
    
    def analyze_actions(self, username: str, actions: List[Dict]) -> Dict:
        """Analyze user actions"""
        risk_score = 0
        suspicious_actions = []
        
        suspicious_patterns = [
            "mass_download", "export_database", "access_hr_files",
            "change_permissions", "delete_logs", "disable_antivirus"
        ]
        
        for action in actions:
            action_type = action.get("type", "")
            if any(pattern in action_type.lower() for pattern in suspicious_patterns):
                risk_score += 10
                suspicious_actions.append(action_type)
        
        return {
            "username": username,
            "action_risk_score": risk_score,
            "suspicious_actions": suspicious_actions
        }