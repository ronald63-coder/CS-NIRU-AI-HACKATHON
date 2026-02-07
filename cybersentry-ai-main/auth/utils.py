import requests
from typing import Optional

def get_location_from_ip(ip_address: str) -> Optional[str]:
    """Get location from IP address (using free API)"""
    try:
        if ip_address == "127.0.0.1":
            return "Localhost"
        
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                return f"{data['city']}, {data['country']}"
    except:
        pass
    
    return "Unknown"

def get_device_type(user_agent: str) -> str:
    """Determine device type from user agent"""
    user_agent = user_agent.lower()
    
    if "mobile" in user_agent:
        return "Mobile"
    elif "tablet" in user_agent:
        return "Tablet"
    elif "windows" in user_agent:
        return "Windows PC"
    elif "mac" in user_agent:
        return "Mac"
    elif "linux" in user_agent:
        return "Linux"
    else:
        return "Unknown"