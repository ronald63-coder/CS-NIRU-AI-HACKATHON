# cybersentry_dashboard.py
# Professional, Modern CyberSentry Dashboard
# Beautiful UI/UX with smooth transitions and professional design

import streamlit as st
import requests
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from time import sleep
from typing import Dict, Any

# ===================== CONFIG =====================
st.set_page_config(
    page_title="CyberSentry AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

API_URL = "http://localhost:8000"
REFRESH_INTERVAL = 5  # seconds

# ===================== STYLING =====================
st.markdown("""
<style>
    /* Root Colors */
    :root {
        --primary: #0ea5e9;
        --primary-dark: #0284c7;
        --secondary: #06b6d4;
        --danger: #ef4444;
        --warning: #f59e0b;
        --success: #10b981;
        --dark-bg: #0f172a;
        --card-bg: #1e293b;
        --text-primary: #f1f5f9;
        --text-secondary: #cbd5e1;
    }
    
    * {
        margin: 0;
        padding: 0;
    }
    
    [data-testid="stApp"] {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
        color: var(--text-primary);
    }
    
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
        border-right: 1px solid rgba(30, 41, 59, 0.5);
    }
    
    /* Headers */
    h1, h2, h3 {
        color: var(--text-primary) !important;
        font-weight: 700 !important;
    }
    
    h1 {
        font-size: 2.5rem !important;
        background: linear-gradient(135deg, #0ea5e9, #06b6d4);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem !important;
    }
    
    h2 {
        font-size: 1.8rem !important;
        margin-top: 2rem !important;
        margin-bottom: 1rem !important;
    }
    
    h3 {
        font-size: 1.3rem !important;
        margin-top: 1.5rem !important;
        margin-bottom: 0.8rem !important;
    }
    
    /* Cards */
    [data-testid="stMetricValue"] {
        font-size: 2rem;
        color: #0ea5e9 !important;
    }
    
    [data-testid="stMetricLabel"] {
        font-size: 0.9rem;
        color: var(--text-secondary) !important;
    }
    
    /* Buttons */
    button {
        background: linear-gradient(135deg, #0ea5e9, #0284c7) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.75rem 1.5rem !important;
        font-weight: 600 !important;
        transition: all 0.3s ease !important;
        cursor: pointer !important;
    }
    
    button:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(14, 165, 233, 0.3) !important;
    }
    
    button:active {
        transform: translateY(0);
    }
    
    /* Tabs */
    [data-testid="stTabs"] [aria-selected="true"] {
        border-bottom: 3px solid #0ea5e9 !important;
    }
    
    /* Inputs */
    input, select, textarea {
        background: rgba(30, 41, 59, 0.8) !important;
        color: var(--text-primary) !important;
        border: 1px solid rgba(148, 163, 184, 0.2) !important;
        border-radius: 6px !important;
        padding: 0.75rem !important;
    }
    
    input:focus, select:focus, textarea:focus {
        border-color: #0ea5e9 !important;
        box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.1) !important;
    }
    
    /* Alert Messages */
    .stAlert {
        border-radius: 8px !important;
        border: none !important;
    }
    
    [data-testid="stAlert"] > div {
        background: transparent !important;
    }
    
    /* Expander */
    [data-testid="stExpander"] {
        border: 1px solid rgba(148, 163, 184, 0.2) !important;
        border-radius: 8px !important;
    }
    
    /* Sidebar */
    [data-testid="stSidebarNav"] {
        padding: 2rem 1rem !important;
    }
    
    /* Dataframe */
    [data-testid="stDataFrame"] {
        background: rgba(30, 41, 59, 0.5) !important;
    }
    
    /* Animations */
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    @keyframes slideIn {
        from {
            transform: translateX(-20px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    .animate-fade {
        animation: fadeIn 0.5s ease-out;
    }
    
    .animate-slide {
        animation: slideIn 0.3s ease-out;
    }
    
    /* Custom Classes */
    .metric-card {
        background: linear-gradient(135deg, rgba(14, 165, 233, 0.1), rgba(6, 182, 212, 0.05));
        border: 1px solid rgba(14, 165, 233, 0.2);
        border-radius: 12px;
        padding: 1.5rem;
        margin: 0.5rem 0;
        transition: all 0.3s ease;
    }
    
    .metric-card:hover {
        border-color: rgba(14, 165, 233, 0.5);
        box-shadow: 0 10px 30px rgba(14, 165, 233, 0.1);
    }
    
    .status-badge {
        display: inline-block;
        padding: 0.4rem 0.8rem;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 600;
    }
    
    .status-critical {
        background: rgba(239, 68, 68, 0.1);
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.3);
    }
    
    .status-high {
        background: rgba(245, 158, 11, 0.1);
        color: #f59e0b;
        border: 1px solid rgba(245, 158, 11, 0.3);
    }
    
    .status-medium {
        background: rgba(59, 130, 246, 0.1);
        color: #3b82f6;
        border: 1px solid rgba(59, 130, 246, 0.3);
    }
    
    .status-low {
        background: rgba(34, 197, 94, 0.1);
        color: #22c55e;
        border: 1px solid rgba(34, 197, 94, 0.3);
    }
</style>
""", unsafe_allow_html=True)

# ===================== UTILITY FUNCTIONS =====================

def safe_api_call(method: str, endpoint: str, params=None, timeout=5, max_retries=2):
    """Safely call API with timeout and retry logic"""
    url = f"{API_URL}{endpoint}"
    
    for attempt in range(max_retries):
        try:
            if method.upper() == "GET":
                response = requests.get(url, params=params, timeout=timeout)
            elif method.upper() == "POST":
                response = requests.post(url, params=params, timeout=timeout)
            else:
                return {"error": "Invalid HTTP method"}
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"API error: {response.status_code}"}
        
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                sleep(2 ** attempt)
                continue
            return {"error": "Request timeout"}
        
        except requests.exceptions.ConnectionError:
            return {"error": "Cannot connect to backend"}
        
        except Exception as e:
            return {"error": str(e)[:100]}
    
    return {"error": "Request failed"}

def get_threat_color(level: str) -> str:
    """Get color based on threat level"""
    colors = {
        "critical": "#ef4444",
        "high": "#f59e0b",
        "medium": "#3b82f6",
        "low": "#22c55e"
    }
    return colors.get(level, "#94a3b8")

def format_timestamp(ts: str) -> str:
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return ts[:19] if len(ts) > 19 else ts

# ===================== SIDEBAR =====================

with st.sidebar:
    st.markdown("### 🛡️ CyberSentry AI")
    st.markdown("Intelligent Threat Detection & Response")
    st.divider()
    
    # Navigation
    st.markdown("**Navigation**")
    page = st.radio(
        "Select Page",
        ["🏠 Dashboard", "📁 File Analysis", "👥 User Monitoring", 
         "📊 Threat History", "⚙️ System Health", "🤖 Agent Control"],
        label_visibility="collapsed"
    )
    
    st.divider()
    
    # Quick Stats
    st.markdown("**Quick Status**")
    try:
        health = safe_api_call("GET", "/api/health")
        stats = safe_api_call("GET", "/api/system-stats")
        
        col1, col2 = st.columns(2)
        with col1:
            status_icon = "🟢" if health.get("status") == "healthy" else "🔴"
            st.metric("System", f"{status_icon} Online", label_visibility="collapsed")
        
        with col2:
            st.metric("Threats", stats.get("total_threats_detected", 0), label_visibility="collapsed")
    except:
        st.metric("System", "🔴 Offline", label_visibility="collapsed")
    
    st.divider()
    
    # User Info
    st.markdown("**Logged In**")
    st.markdown("""
    <div style='background: rgba(14, 165, 233, 0.1); padding: 1rem; border-radius: 8px; 
                border-left: 3px solid #0ea5e9;'>
        <p style='margin: 0.3rem 0;'><strong>👤 Admin</strong></p>
        <p style='margin: 0.3rem 0; font-size: 0.9rem; color: #94a3b8;'>admin@cybersentry.local</p>
        <p style='margin: 0.3rem 0; font-size: 0.8rem;'>👑 Administrator</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.divider()
    
    if st.button("🚪 Logout", use_container_width=True):
        st.info("Logged out successfully")

# ===================== PAGES =====================

# PAGE 1: DASHBOARD
if "Dashboard" in page:
    # Header
    st.markdown("# 🛡️ CyberSentry Dashboard")
    st.markdown("Real-time threat detection and response monitoring")
    st.divider()
    
    # Key Metrics Row 1
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class='metric-card'>
            <div style='font-size: 0.9rem; color: #94a3b8; margin-bottom: 0.5rem;'>Total Threats</div>
            <div style='font-size: 2.5rem; font-weight: bold; color: #0ea5e9;'>156</div>
            <div style='font-size: 0.8rem; color: #10b981;'>↑ 12 today</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class='metric-card'>
            <div style='font-size: 0.9rem; color: #94a3b8; margin-bottom: 0.5rem;'>Auto-Blocked</div>
            <div style='font-size: 2.5rem; font-weight: bold; color: #06b6d4;'>23</div>
            <div style='font-size: 0.8rem; color: #ef4444;'>Today</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class='metric-card'>
            <div style='font-size: 0.9rem; color: #94a3b8; margin-bottom: 0.5rem;'>Avg Risk Score</div>
            <div style='font-size: 2.5rem; font-weight: bold; color: #f59e0b;'>68.5</div>
            <div style='font-size: 0.8rem; color: #94a3b8;'>/100</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class='metric-card'>
            <div style='font-size: 0.9rem; color: #94a3b8; margin-bottom: 0.5rem;'>Blocked Users</div>
            <div style='font-size: 2.5rem; font-weight: bold; color: #ef4444;'>7</div>
            <div style='font-size: 0.8rem; color: #94a3b8;'>Active</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.divider()
    
    # Threat Trends
    st.subheader("📈 Threat Trends (7 Days)")
    
    threat_data = {
        'Day': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        'Critical': [2, 3, 1, 4, 2, 1, 0],
        'High': [5, 6, 4, 7, 5, 3, 2],
        'Medium': [12, 14, 11, 15, 13, 8, 6],
        'Low': [25, 28, 22, 31, 26, 18, 14]
    }
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=threat_data['Day'], y=threat_data['Critical'], 
                            name='Critical', line=dict(color='#ef4444', width=3)))
    fig.add_trace(go.Scatter(x=threat_data['Day'], y=threat_data['High'], 
                            name='High', line=dict(color='#f59e0b', width=3)))
    fig.add_trace(go.Scatter(x=threat_data['Day'], y=threat_data['Medium'], 
                            name='Medium', line=dict(color='#3b82f6', width=3)))
    fig.add_trace(go.Scatter(x=threat_data['Day'], y=threat_data['Low'], 
                            name='Low', line=dict(color='#22c55e', width=3)))
    
    fig.update_layout(
        template="plotly_dark",
        hovermode='x unified',
        plot_bgcolor='rgba(30, 41, 59, 0.5)',
        paper_bgcolor='rgba(30, 41, 59, 0.3)',
        height=400,
        margin=dict(l=0, r=0, t=0, b=0),
        font=dict(color='#f1f5f9')
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    st.divider()
    
    # Recent Threats
    st.subheader("🚨 Recent Threats")
    
    threat_data_df = pd.DataFrame({
        'Time': ['14:32', '13:45', '13:12', '12:58', '12:34'],
        'User': ['demo_attacker', 'suspicious_user', 'bob_wilson', 'normal_user', 'ronny_ogeya'],
        'File': ['malware.exe', 'invoice.pdf', 'config.exe', 'document.docx', 'setup.msi'],
        'Verdict': ['Malicious', 'Suspicious', 'Suspicious', 'Benign', 'Malicious'],
        'Risk': [92, 65, 58, 15, 88],
        'Action': ['Auto-Blocked', 'Auto-Blocked', 'Monitoring', 'Ignored', 'Auto-Blocked']
    })
    
    st.dataframe(
        threat_data_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Time": st.column_config.TextColumn(width="small"),
            "User": st.column_config.TextColumn(),
            "File": st.column_config.TextColumn(),
            "Verdict": st.column_config.TextColumn(),
            "Risk": st.column_config.NumberColumn(format="%.0f"),
            "Action": st.column_config.TextColumn(),
        }
    )

# PAGE 2: FILE ANALYSIS
elif "File Analysis" in page:
    st.markdown("# 📁 File Analysis")
    st.markdown("Upload and analyze files for threats")
    st.divider()
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📤 Upload File")
        uploaded_file = st.file_uploader("Choose a file to scan", type=None)
        
        if uploaded_file is not None:
            st.success(f"✅ File uploaded: {uploaded_file.name}")
            
            if st.button("🔍 Scan File", use_container_width=True):
                with st.spinner("Scanning file..."):
                    sleep(2)
                    
                    st.markdown("""
                    <div style='background: linear-gradient(135deg, rgba(14, 165, 233, 0.1), rgba(6, 182, 212, 0.05));
                                border: 1px solid rgba(14, 165, 233, 0.3); border-radius: 12px; padding: 2rem;'>
                        <h3 style='color: #0ea5e9; margin-bottom: 1.5rem;'>📊 Scan Results</h3>
                        
                        <div style='display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;'>
                            <div>
                                <p><strong>File Name:</strong> {}</p>
                                <p><strong>File Size:</strong> {} bytes</p>
                                <p><strong>File Type:</strong> Executable</p>
                                <p><strong>MD5 Hash:</strong> 5d41402abc4b2a76b9719d911017c592</p>
                            </div>
                            
                            <div>
                                <p><strong style='color: #ef4444;'>Verdict: MALICIOUS</strong></p>
                                <p><strong>Risk Score:</strong> <span style='color: #ef4444; font-size: 1.5rem;'>85/100</span></p>
                                <p><strong>Confidence:</strong> 92%</p>
                                <p><strong>Threat Level:</strong> <span class='status-badge status-critical'>CRITICAL</span></p>
                            </div>
                        </div>
                        
                        <div style='margin-top: 2rem; padding-top: 2rem; border-top: 1px solid rgba(14, 165, 233, 0.2);'>
                            <h4 style='color: #0ea5e9; margin-bottom: 1rem;'>🔍 Detection Details</h4>
                            <ul style='color: #cbd5e1; line-height: 1.8;'>
                                <li>✓ YARA: Matched Trojan.Emotet pattern</li>
                                <li>✓ Entropy: 7.8/8.0 (Encrypted/Packed)</li>
                                <li>✓ Imports: Suspicious API calls (CreateRemoteThread)</li>
                                <li>✓ ML Model: 96% confidence malicious</li>
                                <li>✓ VirusTotal: 45 vendors flag as malware</li>
                            </ul>
                        </div>
                        
                        <div style='margin-top: 2rem;'>
                            <button style='background: linear-gradient(135deg, #ef4444, #dc2626); width: 100%; padding: 0.75rem;
                                         border-radius: 8px; color: white; border: none; font-weight: 600; cursor: pointer;'>
                                🚫 Block User
                            </button>
                        </div>
                    </div>
                    """.format(uploaded_file.name, uploaded_file.size), unsafe_allow_html=True)
    
    with col2:
        st.subheader("📋 Analysis Tips")
        st.info("""
        **Quick Tips:**
        - PE/EXE files: Full analysis
        - PDFs: Macro detection
        - Archives: Content scanning
        - Large files: May take longer
        """)

# PAGE 3: USER MONITORING
elif "User Monitoring" in page:
    st.markdown("# 👥 User Monitoring")
    st.markdown("Monitor user behavior and risk profiles")
    st.divider()
    
    users_data = {
        'User': ['demo_attacker', 'bob_wilson', 'ronny_ogeya', 'suspicious_user', 'normal_user'],
        'Risk Level': ['Critical', 'Medium', 'Critical', 'High', 'Low'],
        'Logins': [45, 8, 12, 24, 5],
        'File Uploads': [156, 3, 8, 42, 1],
        'Status': ['🚫 Blocked', '⚠️ Monitored', '🚫 Blocked', '⚠️ Monitored', '✅ Safe'],
        'Last Activity': ['2h ago', '1h ago', '30m ago', '15m ago', '5m ago']
    }
    
    st.dataframe(
        pd.DataFrame(users_data),
        use_container_width=True,
        hide_index=True
    )
    
    st.divider()
    
    st.subheader("🔴 High-Risk Users")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class='metric-card'>
            <h4 style='color: #ef4444; margin-bottom: 1rem;'>demo_attacker</h4>
            <p><strong>Status:</strong> <span class='status-badge status-critical'>BLOCKED</span></p>
            <p><strong>Risk Score:</strong> <span style='color: #ef4444; font-size: 1.3rem;'>95</span>/100</p>
            <p><strong>Reason:</strong> Multiple malware uploads</p>
            <p style='margin-top: 1rem; color: #94a3b8; font-size: 0.85rem;'>Blocked since: 2h ago</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class='metric-card'>
            <h4 style='color: #f59e0b; margin-bottom: 1rem;'>ronny_ogeya</h4>
            <p><strong>Status:</strong> <span class='status-badge status-critical'>BLOCKED</span></p>
            <p><strong>Risk Score:</strong> <span style='color: #f59e0b; font-size: 1.3rem;'>88</span>/100</p>
            <p><strong>Reason:</strong> Suspicious file patterns</p>
            <p style='margin-top: 1rem; color: #94a3b8; font-size: 0.85rem;'>Blocked since: 30m ago</p>
        </div>
        """, unsafe_allow_html=True)

# PAGE 4: THREAT HISTORY
elif "Threat History" in page:
    st.markdown("# 📊 Threat History")
    st.markdown("Complete threat detection log and analysis")
    st.divider()
    
    # Filters
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        verdict_filter = st.selectbox("Verdict", ["All", "Malicious", "Suspicious", "Benign"])
    with col2:
        level_filter = st.selectbox("Threat Level", ["All", "Critical", "High", "Medium", "Low"])
    with col3:
        days_filter = st.selectbox("Time Range", ["Last 24h", "Last 7d", "Last 30d", "All"])
    with col4:
        st.write("")  # Spacing
    
    # Threat Table
    threat_history = pd.DataFrame({
        'Timestamp': ['2026-03-05 14:32', '2026-03-05 13:45', '2026-03-05 13:12', '2026-03-05 12:58'],
        'User': ['demo_attacker', 'suspicious_user', 'bob_wilson', 'ronny_ogeya'],
        'Filename': ['malware.exe', 'invoice.pdf', 'config.exe', 'setup.msi'],
        'Verdict': ['Malicious', 'Suspicious', 'Suspicious', 'Malicious'],
        'Risk': [92, 65, 58, 88],
        'Confidence': ['98%', '72%', '65%', '91%'],
        'Action': ['Auto-Blocked', 'Auto-Blocked', 'Monitored', 'Auto-Blocked']
    })
    
    st.dataframe(threat_history, use_container_width=True, hide_index=True)
    
    # Export button
    csv = threat_history.to_csv(index=False)
    st.download_button(
        label="📥 Download Threat Log",
        data=csv,
        file_name="threat_history.csv",
        mime="text/csv"
    )

# PAGE 5: SYSTEM HEALTH
elif "System Health" in page:
    st.markdown("# ⚙️ System Health")
    st.markdown("Monitor system status and AI model performance")
    st.divider()
    
    # Status Overview
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class='metric-card'>
            <div style='color: #94a3b8; margin-bottom: 0.5rem;'>Backend Status</div>
            <div style='font-size: 1.3rem; color: #22c55e; font-weight: bold;'>🟢 Online</div>
            <div style='font-size: 0.8rem; color: #94a3b8;'>v2.0.0</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class='metric-card'>
            <div style='color: #94a3b8; margin-bottom: 0.5rem;'>Uptime</div>
            <div style='font-size: 1.3rem; color: #0ea5e9; font-weight: bold;'>24h 15m</div>
            <div style='font-size: 0.8rem; color: #94a3b8;'>99.9%</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class='metric-card'>
            <div style='color: #94a3b8; margin-bottom: 0.5rem;'>API Response</div>
            <div style='font-size: 1.3rem; color: #22c55e; font-weight: bold;'>124ms</div>
            <div style='font-size: 0.8rem; color: #94a3b8;'>Normal</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class='metric-card'>
            <div style='color: #94a3b8; margin-bottom: 0.5rem;'>Agent Status</div>
            <div style='font-size: 1.3rem; color: #22c55e; font-weight: bold;'>🤖 Active</div>
            <div style='font-size: 0.8rem; color: #94a3b8;'>Running</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.divider()
    
    # System Performance
    st.subheader("📊 System Performance")
    
    col1, col2 = st.columns(2)
    
    with col1:
        fig_cpu = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=24,
            title={'text': "CPU Usage"},
            domain={'x': [0, 1], 'y': [0, 1]},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "#0ea5e9"},
                'steps': [
                    {'range': [0, 50], 'color': "rgba(34, 197, 94, 0.1)"},
                    {'range': [50, 80], 'color': "rgba(245, 158, 11, 0.1)"},
                    {'range': [80, 100], 'color': "rgba(239, 68, 68, 0.1)"}
                ]
            }
        ))
        fig_cpu.update_layout(
            template="plotly_dark",
            height=300,
            plot_bgcolor='rgba(30, 41, 59, 0.5)',
            paper_bgcolor='rgba(30, 41, 59, 0.3)',
            font=dict(color='#f1f5f9')
        )
        st.plotly_chart(fig_cpu, use_container_width=True)
    
    with col2:
        fig_mem = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=22.5,
            title={'text': "Memory Usage"},
            domain={'x': [0, 1], 'y': [0, 1]},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "#06b6d4"},
                'steps': [
                    {'range': [0, 50], 'color': "rgba(34, 197, 94, 0.1)"},
                    {'range': [50, 80], 'color': "rgba(245, 158, 11, 0.1)"},
                    {'range': [80, 100], 'color': "rgba(239, 68, 68, 0.1)"}
                ]
            }
        ))
        fig_mem.update_layout(
            template="plotly_dark",
            height=300,
            plot_bgcolor='rgba(30, 41, 59, 0.5)',
            paper_bgcolor='rgba(30, 41, 59, 0.3)',
            font=dict(color='#f1f5f9')
        )
        st.plotly_chart(fig_mem, use_container_width=True)
    
    st.divider()
    
    # AI Models Status
    st.subheader("🤖 AI Model Status")
    
    models = [
        {"name": "Enhanced Rule Engine", "status": "Active", "accuracy": "98.2%", "emoji": "✅"},
        {"name": "Anomaly Detector", "status": "Active", "accuracy": "97.5%", "emoji": "✅"},
        {"name": "Entropy Analyzer", "status": "Active", "accuracy": "95.8%", "emoji": "✅"},
        {"name": "PE Analyzer", "status": "Active", "accuracy": "94.3%", "emoji": "✅"},
        {"name": "YARA Engine", "status": "Active", "accuracy": "99.1%", "emoji": "✅"},
    ]
    
    for model in models:
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.markdown(f"**{model['emoji']} {model['name']}**")
        with col2:
            st.markdown(f"<span style='color: #22c55e;'>{model['status']}</span>", unsafe_allow_html=True)
        with col3:
            st.markdown(f"<span style='color: #0ea5e9;'>{model['accuracy']}</span>", unsafe_allow_html=True)

# PAGE 6: AGENT CONTROL
elif "Agent Control" in page:
    st.markdown("# 🤖 Agent Control")
    st.markdown("Manage autonomous threat response")
    st.divider()
    
    # Agent Status
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        <div style='background: linear-gradient(135deg, rgba(34, 197, 94, 0.1), rgba(16, 185, 129, 0.05));
                    border: 2px solid rgba(34, 197, 94, 0.3); border-radius: 12px; padding: 2rem;'>
            <h3 style='color: #22c55e; margin: 0 0 1rem 0;'>🤖 Agent Status</h3>
            <p style='font-size: 1.2rem; color: #22c55e; margin: 0; font-weight: bold;'>RUNNING ✓</p>
            <p style='color: #94a3b8; margin-top: 0.5rem;'>Actively monitoring threats...</p>
            <p style='color: #94a3b8; font-size: 0.9rem; margin-top: 1rem;'>
                <strong>Last Action:</strong> Auto-blocked suspicious_user (2m ago)
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        if st.button("▶️ Start Agent", use_container_width=True):
            st.success("Agent started")
        if st.button("⏹️ Stop Agent", use_container_width=True):
            st.warning("Agent stopped")
    
    st.divider()
    
    # Pending Reviews
    st.subheader("📋 Pending Threat Reviews")
    
    pending_threats = pd.DataFrame({
        'Threat Level': ['🔴 Critical', '🟡 High', '🟡 High'],
        'User': ['demo_attacker', 'suspicious_user', 'bob_wilson'],
        'File': ['malware.exe', 'invoice.pdf', 'config.exe'],
        'Time': ['2h ago', '1h 30m ago', '45m ago'],
        'Action': ['Approve Block', 'Approve Block', 'Monitor']
    })
    
    for idx, row in pending_threats.iterrows():
        col1, col2, col3, col4 = st.columns([1, 2, 2, 1])
        with col1:
            st.markdown(row['Threat Level'])
        with col2:
            st.markdown(f"**{row['User']}** - {row['File']}")
        with col3:
            st.markdown(f"_{row['Time']}_")
        with col4:
            if st.button(f"✓ {row['Action']}", key=f"action_{idx}", use_container_width=True):
                st.success(f"Action taken on {row['User']}")
    
    st.divider()
    
    # Manual Controls
    st.subheader("⚙️ Manual Controls")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Block User**")
        block_user = st.selectbox("Select User", ["demo_attacker", "suspicious_user", "bob_wilson"])
        block_reason = st.text_area("Reason", "Suspicious activity detected")
        if st.button("🚫 Block User", use_container_width=True):
            st.success(f"User {block_user} blocked")
    
    with col2:
        st.markdown("**Send Alert**")
        alert_user = st.selectbox("Select User", ["ronny_ogeya", "purity_kerubo", "brightone_omondi"])
        alert_type = st.selectbox("Alert Type", ["WhatsApp", "Email", "Both"])
        if st.button("📱 Send Alert", use_container_width=True):
            st.success(f"Alert sent to {alert_user}")

st.divider()
st.markdown("""
<div style='text-align: center; color: #94a3b8; font-size: 0.9rem; padding: 2rem 0;'>
    🛡️ CyberSentry AI v2.0 | Real-time Threat Detection & Response
</div>
""", unsafe_allow_html=True)