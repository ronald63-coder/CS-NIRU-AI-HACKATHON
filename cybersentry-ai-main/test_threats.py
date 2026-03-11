# test_threats.py
import requests
import random
import time

API_URL = "http://localhost:8000"

threat_levels = ["low", "medium", "high", "critical"]
users = ["ronny_ogeya", "bob_wilson", "demo_attacker", "brightone_omondi"]
file_names = ["invoice.exe", "document.pdf", "payload.dll", "report.doc", "script.js"]

print("🚀 Generating test threats with different levels...")

for i in range(10):
    level = random.choice(threat_levels)
    user = random.choice(users)
    
    # Set risk score based on level
    if level == "critical":
        risk = random.randint(85, 98)
    elif level == "high":
        risk = random.randint(65, 84)
    elif level == "medium":
        risk = random.randint(40, 64)
    else:
        risk = random.randint(10, 39)
    
    # Create a simulated threat
    response = requests.post(
        f"{API_URL}/simulate-threat",
        params={"target_user": user}
    )
    
    print(f"✅ Generated {level.upper()} threat for {user} (risk: {risk})")
    time.sleep(1)

print("\n🎯 Test threats generated! Check the agent output.")