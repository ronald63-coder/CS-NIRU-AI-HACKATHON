from datetime import datetime

class AlertSystem:
    """Send security alerts"""
    
    def send_alert(self, alert_type: str, severity: str, message: str, data: dict = None):
        """Send an alert"""
        alert = {
            "type": alert_type,
            "severity": severity,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "data": data or {}
        }
        
        # Print to console (in production, send email/SMS/webhook)
        print("\n" + "="*60)
        print(f"🚨 CYBERSENTRY ALERT - {severity.upper()}")
        print(f"Type: {alert_type}")
        print(f"Message: {message}")
        print(f"Time: {alert['timestamp']}")
        
        if data:
            print("Details:")
            for key, value in data.items():
                print(f"  {key}: {value}")
        
        print("="*60 + "\n")
        
        return alert