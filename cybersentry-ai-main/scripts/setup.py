#!/usr/bin/env python3
import subprocess
import sys

def run_command(command):
    """Run shell command"""
    print(f"Running: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
    return result

def main():
    print("🚀 Setting up CyberSentry AI...")
    
    # Install requirements
    print("\n📦 Installing dependencies...")
    run_command(f"{sys.executable} -m pip install -r requirements.txt")
    
    # Create necessary directories
    print("\n📁 Creating directories...")
    from config import Config
    Config.ensure_directories()
    
    # Train AI models
    print("\n🤖 Training AI models...")
    from ai_models.malware_classifier import MalwareClassifier
    from ai_models.anomaly_detector import AnomalyDetector
    
    # These will auto-train on import
    ml = MalwareClassifier()
    ad = AnomalyDetector()
    
    print("\n✅ Setup complete!")
    print("\n🎯 To start:")
    print("   Backend: python app.py")
    print("   Dashboard: streamlit run streamlit_app.py")
    print("\n📚 Documentation available at /docs when backend is running")

if __name__ == "__main__":
    main()