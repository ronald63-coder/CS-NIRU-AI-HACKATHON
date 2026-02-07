#!/usr/bin/env python3
import subprocess
import sys

REQUIRED_PACKAGES = {
    # Core Framework
    "fastapi": "0.104.1",
    "uvicorn": "0.24.0",
    "python-multipart": "0.0.6",
    
    # Authentication
    "python-jose": "3.3.0",
    "passlib": "1.7.4",
    "bcrypt": "4.1.2",
    "python-dotenv": "1.0.0",
    
    # Database
    "sqlalchemy": "2.0.23",
    
    # AI/ML
    "scikit-learn": "1.3.2",
    "joblib": "1.3.2",
    "numpy": "1.24.3",
    "pandas": "2.1.4",
    
    # Security Analysis
    "yara-python": "4.3.1",
    "pefile": "2023.2.7",
    "python-magic": "0.4.27",
    
    # Frontend
    "streamlit": "1.28.1",
    "plotly": "5.17.0",
    
    # Validation
    "pydantic": "2.5.0",
}

def check_package(package_name, expected_version=None):
    """Check if a package is installed"""
    try:
        if expected_version:
            # Try to import and check version
            module = __import__(package_name.replace("-", "_"))
            if hasattr(module, '__version__'):
                version = module.__version__
                if version == expected_version:
                    return True, version, "✅"
                else:
                    return True, version, f"⚠️ (expected {expected_version})"
            else:
                return True, "unknown", "✅"
        else:
            # Just check if importable
            __import__(package_name.replace("-", "_"))
            return True, "", "✅"
    except ImportError:
        return False, "", "❌"

def main():
    print("🔍 Checking CyberSentry AI Dependencies...")
    print("=" * 60)
    
    results = []
    for package, expected_version in REQUIRED_PACKAGES.items():
        installed, version, status = check_package(package, expected_version)
        results.append((package, expected_version, version, status))
    
    # Print results in a table
    print(f"{'Package':<20} {'Expected':<12} {'Installed':<12} {'Status':<10}")
    print("-" * 60)
    
    for package, expected, installed, status in results:
        if installed:  # Package is installed
            print(f"{package:<20} {expected:<12} {installed:<12} {status:<10}")
        else:  # Not installed
            print(f"{package:<20} {expected:<12} {'NOT INSTALLED':<12} {status:<10}")
    
    print("=" * 60)
    
    # Count stats
    total = len(results)
    installed_count = sum(1 for _, _, _, status in results if status == "✅")
    wrong_version = sum(1 for _, _, _, status in results if status.startswith("⚠️"))
    missing_count = sum(1 for _, _, _, status in results if status == "❌")
    
    print(f"\n📊 Summary:")
    print(f"   ✅ Correctly installed: {installed_count}/{total}")
    print(f"   ⚠️  Wrong version: {wrong_version}/{total}")
    print(f"   ❌ Missing: {missing_count}/{total}")
    
    # Installation commands
    if missing_count > 0 or wrong_version > 0:
        print(f"\n🚀 To install missing packages:")
        print(f"   pip install -r requirements.txt")
        
        # List specifically missing packages
        missing_packages = [pkg for pkg, _, _, status in results if status == "❌"]
        if missing_packages:
            print(f"\n📦 Specifically missing:")
            for pkg in missing_packages:
                print(f"   pip install {pkg}")

if __name__ == "__main__":
    main()