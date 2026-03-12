# 🛡️ CyberSentry AI

**Advanced Malware & Insider Threat Detection with Automated Response**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28.0-red)](https://streamlit.io)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-green)](https://fastapi.tiangolo.com)

## 🎯 Overview

*CyberSentry AI* is an insider threat detection platform that combines AI-powered behavioral analytics with advanced malware scanning to protect organizations from within.

## ✨ Features

### 🤖 **6 Custom AI Agents**
- **SENTRY** - Arthur-inspired coordinator (explains decisions conversationally)
- **HUNTER** - Proactive threat hunting and anomaly detection
- **ANALYST** - Deep forensic investigation with ML ensemble
- **RESPONDER** - Autonomous incident response (3-second reaction)
- **COMMUNICATOR** - Multi-channel alerts (IT, management, NC4)
- **STRATEGIST** - Continuous learning from every incident

### 🔍 **Multi-Layer Detection**
- **YARA Rules** - 1000+ malware signatures
- **Random Forest** - 94% accuracy on known threats
- **Isolation Forest** - Zero-day anomaly detection
- **XGBoost** - Ensemble voting for precision
- **12 Features** - Entropy, PE structure, suspicious strings, user context

### 👥 **User Behavior Monitoring**
- Login time anomalies (2 AM flag)
- Geographic anomalies (foreign IP detection)
- Volume anomalies (mass downloads)
- Department context (HR accessing engineering code)
- Historical baselining (learns normal patterns)

### ⚡ **Automated Response**
- Auto-block users in 3 seconds
- Isolate affected systems
- Terminate active sessions
- Generate NC4-compliant reports
- Alert IT, management, and regulators

### 📊 **Enterprise Dashboard**
- Real-time threat visualization
- Agent conversation logs
- User risk scoring
- Threat history with evidence
- System health monitoring

### 🇰🇪 **Kenya-Optimized**
- Built for Kenyan organizations
- Trained on local threat patterns
- NC4 compliance reporting
- M-PESA fraud detection


---

## 🏆 Hackathon Project

This project was developed for the **AI Hackathon Kenya** under the **Cybersecurity and Data Protection** theme.

## 🚀 Quick Start

### Prerequisites
- Python 3.11
- pip package manager

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/ronald63-coder/CS-NIRU-AI-HACKATHON.git
cd  CS-NIRU-AI-HACKATHON

2.Install dependencies

bash
pip install -r requirements.txt

3. Activate environment in each terminal
venv311_new\Scripts\Activate

4.Run the backend server( terminal 1)

bash

python app.py

5. Run the Agent (in new terminal)
bash

python run_agent.py

6.Run the dashboard (in new terminal)

bash

streamlit run dashboardapp.py

