# dashboardapp.py – unified, production-ready
import streamlit as st
import requests
import json
import time
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from streamlit_lottie import st_lottie




# --------------------  AUTH GATE  --------------------
from dashboard.pages.login import show_login_page, is_logged_in, logout, get_auth_header
if not is_logged_in():
    show_login_page()
    st.stop()

# --------------------  CONFIG  --------------------
st.set_page_config(page_title="CyberSentry AI", page_icon="🛡️", layout="wide")
API_URL = "http://localhost:8000"

# --------------------  CALM-COLOURFUL CSS  --------------------
st.markdown("""
<style>
/* ----------  root palette  ---------- */
:root{
  --grad-1: linear-gradient(135deg, #a1c4fd 0%, #c2e9fb 100%);
  --grad-2: linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%);
  --grad-3: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%);
  --grad-4: linear-gradient(135deg, #f6d365 0%, #fda085 100%);
  --grad-danger:  linear-gradient(135deg, #ff4757 0%, #ff3742 100%);
  --grad-high:    linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
  --grad-warn:    linear-gradient(135deg, #ffeaa7 0%, #fab1a0 100%);
  --grad-safe:    linear-gradient(135deg, #55efc4 0%, #81ecec 100%);
  --grad-low:     linear-gradient(135deg, #74b9ff 0%, #a29bfe 100%);
  --glass: rgba(255,255,255,0.55);
  --blur:  backdrop-filter: blur(8px);
  --shadow: 0 8px 32px rgba(31,38,135,.15);
}

/* ----------  header  ---------- */
.main-header {
  background: var(--grad-1);
  padding: 2.2rem;
  border-radius: 16px;
  color: #1f2937;
  text-align: center;
  margin-bottom: 2rem;
  box-shadow: var(--shadow);
  animation: fadeIn 1s ease-out;
}

/* ----------  metric cards  ---------- */
.metric-card {
  background: var(--glass);
  var(--blur);
  border: 1px solid rgba(255,255,255,.3);
  padding: 1.5rem;
  border-radius: 16px;
  box-shadow: var(--shadow);
  transition: transform .3s ease;
}
.metric-card:hover { transform: translateY(-4px); }
.metric-card h3 { color: #6200EE; font-weight: 600; }
.metric-card h2 { color: #03DAC6; font-size: 2.2rem; margin: .2rem 0; }
.metric-card small { color: #3700B3; }

/* ----------  5-TIER VERDICT ALERTS  ---------- */
/* Critical - malicious */
.alert-critical { 
  background: var(--grad-danger); 
  color: #fff; 
  padding: 1.5rem; 
  border-radius: 12px; 
  font-weight: 700; 
  border-left: 6px solid #ff4757; 
  animation: pulse 2s infinite; 
  text-align: center;
  font-size: 1.2rem;
}
/* High - likely_malicious */
.alert-high { 
  background: var(--grad-high); 
  color: #fff; 
  padding: 1.5rem; 
  border-radius: 12px; 
  font-weight: 700; 
  border-left: 6px solid #ff6b6b; 
  text-align: center;
  font-size: 1.2rem;
}
/* Medium - suspicious */
.alert-warning  { 
  background: var(--grad-warn);   
  color: #2d3436; 
  padding: 1.5rem; 
  border-radius: 12px; 
  font-weight: 700; 
  border-left: 6px solid #fdcb6e; 
  text-align: center;
  font-size: 1.2rem;
}
/* Low - low_risk */
.alert-low { 
  background: var(--grad-low); 
  color: #fff; 
  padding: 1.5rem; 
  border-radius: 12px; 
  font-weight: 700; 
  border-left: 6px solid #74b9ff; 
  text-align: center;
  font-size: 1.2rem;
}
/* Safe - benign */
.alert-safe     { 
  background: var(--grad-safe);   
  color: #2d3436; 
  padding: 1.5rem; 
  border-radius: 12px; 
  font-weight: 700; 
  border-left: 6px solid #00cec9; 
  text-align: center;
  font-size: 1.2rem;
}

/* ----------  user cards - SOFT PROFESSIONAL COLORS  ---------- */
.user-card {
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(0, 0, 0, 0.06);
  padding: 1.2rem;
  border-radius: 12px;
  margin: 0.5rem 0;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
  transition: all 0.3s ease;
}
.user-card:hover {
  transform: translateX(4px);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
}

/* High Risk - Soft Rose */
.user-high-risk { 
  border-left: 4px solid #dc8b8b; 
  background: linear-gradient(135deg, #fdf8f8 0%, #f5e6e6 100%);
}
/* Medium Risk - Soft Amber */
.user-medium-risk { 
  border-left: 4px solid #d4b896; 
  background: linear-gradient(135deg, #fdfbf7 0%, #f5efe6 100%);
}
/* Low Risk - Soft Sage */
.user-low-risk { 
  border-left: 4px solid #8fbfa3; 
  background: linear-gradient(135deg, #f8fbf9 0%, #e6f0eb 100%);
}
/* Blocked - Soft Slate */
.user-blocked { 
  border-left: 4px solid #9a9aaa;
  background: linear-gradient(135deg, #f8f8fa 0%, #e8e8ec 100%);
}

/* ----------  blocked banner  ---------- */
.blocked-banner {
  background: var(--grad-danger);
  color: #fff;
  padding: 1.5rem;
  border-radius: 12px;
  text-align: center;
  font-weight: 700;
  font-size: 1.3rem;
  margin: 1rem 0;
  box-shadow: var(--shadow);
  animation: shake 0.5s ease-in-out;
}

/* ----------  buttons  ---------- */
.stButton > button {
  background: var(--grad-1);
  color: #1f2937;
  border: none;
  padding: .6rem 1.4rem;
  border-radius: 12px;
  font-weight: 600;
  box-shadow: var(--shadow);
  transition: .3s ease;
}
.stButton > button:hover {
  transform: scale(1.05);
  box-shadow: 0 12px 40px rgba(31,38,135,.25);
}

/* ----------  animations  ---------- */
@keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
@keyframes pulse { 50% { transform: scale(1.02); } }
@keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); } }
</style>
""", unsafe_allow_html=True)

# --------------------  TOP USER BAR --------------------
with st.sidebar:
    st.markdown(f"""
    <div style='padding: 1rem; background: var(--glass); border-radius: 12px; margin-bottom: 1rem;'>
        <p><strong>👤 {st.session_state['user']['full_name']}</strong></p>
        <p><small>{st.session_state['user']['email']}</small></p>
        <p><small>Role: {'👑 Admin' if st.session_state['user']['is_admin'] else '👤 User'}</small></p>
    </div>
    """, unsafe_allow_html=True)
    if st.button("🚪 Logout", use_container_width=True):
        logout()
        st.rerun()

# --------------------  NAV  --------------------
with st.sidebar:
    page = st.radio("Navigate", ["Dashboard", "File Analysis", "User Monitoring", "Threat History", "System Health"])
    st.markdown("---")
    if st.button("🔄 Refresh All", use_container_width=True):
        st.rerun()

# --------------------  HELPERS  --------------------
def metric_card(label, value, delta, emoji):
    st.markdown(f"""
    <div class="metric-card">
        <h3>{emoji} {label}</h3>
        <h2 style='color:#111827;font-size:2.2rem;margin:.2rem 0;'>{value}</h2>
        <small style='color:#6b7280;'>{delta}</small>
    </div>
    """, unsafe_allow_html=True)

def display_verdict_card(verdict, risk_score, confidence, reasons):
    """Display 5-tier verdict with appropriate styling"""
    
    verdict_config = {
        "malicious": {
            "class": "alert-critical",
            "emoji": "🚨",
            "title": "CRITICAL THREAT",
            "subtitle": "Malicious file detected - immediate action taken",
        },
        "likely_malicious": {
            "class": "alert-high",
            "emoji": "🔴",
            "title": "HIGH RISK",
            "subtitle": "Likely malicious - strong indicators present",
        },
        "suspicious": {
            "class": "alert-warning",
            "emoji": "⚠️",
            "title": "SUSPICIOUS",
            "subtitle": "Mixed signals - manual review recommended",
        },
        "low_risk": {
            "class": "alert-low",
            "emoji": "🟡",
            "title": "LOW RISK",
            "subtitle": "Minor indicators but likely safe",
        },
        "benign": {
            "class": "alert-safe",
            "emoji": "✅",
            "title": "SAFE",
            "subtitle": "No threats detected - file is clean",
        }
    }
    
    config = verdict_config.get(verdict, verdict_config["benign"])
    
    st.markdown(f"""
    <div class="{config['class']}">
        {config['emoji']} <strong>{config['title']}</strong><br>
        <small>{config['subtitle']}</small>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Risk Score", f"{risk_score}/100", delta=None)
    with col2:
        st.metric("Confidence", f"{confidence*100:.1f}%", delta=None)
    with col3:
        threat_level = "Critical" if risk_score >= 80 else "High" if risk_score >= 60 else "Medium" if risk_score >= 40 else "Low" if risk_score >= 15 else "Safe"
        st.metric("Threat Level", threat_level, delta=None)
    
    if reasons:
        with st.expander("🔍 Detection Reasons", expanded=True):
            for reason in reasons:
                st.write(f"• {reason}")

def render_user_card(u):
    """Render a single user card with soft professional styling"""
    if u["status"] == "blocked":
        card_class = "user-card user-blocked"
        status_color = "#7a7a8a"
        risk_label = "Blocked"
    else:
        card_class = f'user-card user-{u["risk"]}-risk'
        status_color = {"high": "#b07070", "medium": "#b8956a", "low": "#6a9b7d"}.get(u["risk"], "#666")
        risk_label = u["risk"].title()
    
    st.markdown(f"""
    <div class="{card_class}">
        <div style="display: flex; align-items: flex-start; gap: 12px;">
            <div style="margin-top: 2px;">
                <div style="width: 10px; height: 10px; border-radius: 50%; background: {status_color};"></div>
            </div>
            <div style="flex: 1;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="color: #2d3748; font-size: 1.05rem;">{u['name']}</strong>
                    <span style="color: {status_color}; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">{risk_label}</span>
                </div>
                <div style="color: #4a5568; font-size: 0.85rem; margin-top: 6px;">
                    {u["last_action"]}
                </div>
                <div style="color: #718096; font-size: 0.8rem; margin-top: 4px;">
                    {u["login_time"]} • {u["department"]}
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# --------------------  PAGES  --------------------
if page == "Dashboard":
    st.markdown('<div class="main-header"><h1>🛡️ CyberSentry AI Dashboard</h1><p>Real-time Threat Intelligence Platform</p></div>', unsafe_allow_html=True)
    try:
        activity = requests.get(f"{API_URL}/user-activity").json()
        stats = requests.get(f"{API_URL}/system-stats").json()
        blocked = requests.get(f"{API_URL}/blocked-users").json()
        total, threats = activity["total_users"], activity["active_threats"]
        
        c1, c2, c3, c4 = st.columns(4)
        with c1: metric_card("Total Users", total, "+2%", "👥")
        with c2: metric_card("Active Threats", threats, "+5%", "🚨")
        with c3: metric_card("Auto-Blocks", stats['auto_blocks_performed'], "+8%", "🛑")
        with c4: metric_card("Protected", total - threats, "+12%", "✅")

        if blocked["blocked_users"]:
            st.markdown(f'<div class="blocked-banner">🚫 {len(blocked["blocked_users"])} USERS CURRENTLY BLOCKED</div>', unsafe_allow_html=True)
            for u in blocked["blocked_users"]:
                col1, col2 = st.columns([3, 1])
                with col1: 
                    st.error(f"**{u}** – Account automatically suspended due to critical threat")
                with col2:
                    if st.button(f"Unblock {u}", key=f"unblock_{u}"):
                        res = requests.post(f"{API_URL}/unblock-user", params={"username": u})
                        if res.json().get("action") == "UNBLOCKED":
                            st.success(f"✅ {u} unblocked!")
                            time.sleep(1)
                            st.rerun()

        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🚨 Live Threat Alerts")
            for a in activity["alerts"]:
                emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(a["severity"], "⚪")
                cls = {"high": "alert-critical", "medium": "alert-warning", "low": "alert-safe"}.get(a["severity"], "alert-safe")
                st.markdown(f'<div class="{cls}">{emoji} <strong>{a["type"].replace("_"," ").title()}</strong><br>User: {a["user"]} | Time: {a["time"]}</div>', unsafe_allow_html=True)
        
        with col2:
            st.subheader("👥 Real-time User Monitor")
            for u in activity["users"]:
                render_user_card(u)
                
    except Exception as e:
        st.error(f"🚨 Backend error: {e}")
        st.info("Ensure backend runs on :8000")

# --------------------  FILE ANALYSIS  --------------------
elif page == "File Analysis":
    st.markdown('<div class="main-header"><h1>📁 File Threat Analysis</h1><p>Upload suspicious files for AI-powered scanning</p></div>', unsafe_allow_html=True)
    uploaded = st.file_uploader("Drag and drop file here", type=['exe', 'dll', 'pdf', 'doc', 'docx', 'zip', 'rar', 'js'])
    
    if uploaded:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <h3>📄 File Information</h3>
                <p><strong>Name:</strong> {uploaded.name}</p>
                <p><strong>Size:</strong> {uploaded.size:,} bytes</p>
                <p><strong>Type:</strong> {uploaded.type or 'Unknown'}</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            if st.button("🚀 Scan with AI", type="primary", use_container_width=True):
                with st.spinner("🔬 Deep scanning file for advanced threats..."):
                    try:
                        files = {"file": (uploaded.name, uploaded.getvalue())}
                        r = requests.post(f"{API_URL}/api/v1/scan", files=files)
                        res = r.json()

                        st.success("✅ Analysis Complete!")
                        
                        display_verdict_card(
                            verdict=res["verdict"],
                            risk_score=res["risk_score"],
                            confidence=res["confidence"],
                            reasons=res.get("detection_reasons", [])
                        )
                        
                        if res["auto_blocked"]:
                            st.balloons()
                            st.markdown("""
                            <div class="blocked-banner">
                                🛑 USER AUTO-BLOCKED!<br>
                                <small>Critical threat automatically neutralized</small>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        with st.expander("🔬 Technical Analysis Details"):
                            tech_col1, tech_col2 = st.columns(2)
                            with tech_col1:
                                st.subheader("File Features")
                                st.json(res.get("features", {}))
                            with tech_col2:
                                st.subheader("Indicators")
                                st.json(res.get("indicators", {}))
                            
                            st.subheader("AI Model Info")
                            st.write(f"**Models Used:** {', '.join(res.get('ai_models_used', []))}")
                            st.write(f"**ML Confidence:** {res.get('ai_confidence', 0)*100:.1f}%")
                            st.write(f"**Anomaly Detected:** {'Yes' if res.get('anomaly_detected') else 'No'}")
                        
                        with st.expander("📄 Raw API Response"):
                            st.json(res)
                            
                    except Exception as e:
                        st.error(f"❌ Scan failed: {e}")
                        st.info("Ensure the backend is running on http://localhost:8000")

# --------------------  USER MONITORING  --------------------
elif page == "User Monitoring":
    st.markdown('<div class="main-header"><h1>👥 User Behavior Monitoring</h1><p>Real-time user activity and risk analysis</p></div>', unsafe_allow_html=True)
    try:
        activity = requests.get(f"{API_URL}/user-activity").json()
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            risk_counts = {"High": 0, "Medium": 0, "Low": 0}
            for u in activity["users"]:
                risk_counts[u["risk"].title()] += 1
            
            fig = go.Figure(data=[go.Pie(
                labels=list(risk_counts.keys()), 
                values=list(risk_counts.values()),
                hole=.3, 
                marker_colors=['#dc8b8b', '#d4b896', '#8fbfa3']
            )])
            fig.update_layout(title_text="User Risk Distribution")
            st.plotly_chart(fig, use_container_width=True)

            st.subheader("👤 Detailed User Activity")
            for u in activity["users"]:
                render_user_card(u)
        
        with col2:
            high = len([u for u in activity["users"] if u["risk"] == "high"])
            med = len([u for u in activity["users"] if u["risk"] == "medium"])
            low = len([u for u in activity["users"] if u["risk"] == "low"])
            
            st.metric("🔴 High Risk", high)
            st.metric("🟡 Medium Risk", med)
            st.metric("🟢 Low Risk", low)
            
            st.markdown("---")
            protected = len([u for u in activity["users"] if u["status"] != "blocked"])
            blocked = len(activity.get("blocked_users", []))
            
            st.metric("✅ Protected Users", protected)
            st.metric("🚫 Blocked Users", blocked)
            
    except Exception as e:
        st.error(f"Could not load user data: {e}")

# --------------------  THREAT HISTORY  --------------------
elif page == "Threat History":
    st.markdown('<div class="main-header"><h1>📈 Threat Intelligence</h1><p>Historical threat data and patterns</p></div>', unsafe_allow_html=True)
    try:
        rows = requests.get(f"{API_URL}/threat-history").json()["threat_history"]
        
        if rows:
            df = pd.DataFrame(rows)
            df["datetime"] = pd.to_datetime(df["timestamp"])
            
            threat_colors = {
                "critical": "#c0392b",
                "high": "#e74c3c", 
                "medium": "#f39c12",
                "low": "#3498db",
                "safe": "#27ae60"
            }
            
            col1, col2 = st.columns(2)
            
            with col1:
                fig = px.pie(
                    df, 
                    names="threat_level", 
                    title="Threat Level Distribution",
                    color="threat_level",
                    color_discrete_map=threat_colors
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                hourly = df.groupby(df["datetime"].dt.hour).size()
                fig2 = px.line(hourly, title="Threats by Hour of Day", markers=True)
                fig2.update_traces(line_color='#dc8b8b')
                st.plotly_chart(fig2, use_container_width=True)
            
            st.markdown("### 📋 Detailed Threat History")
            
            display_cols = ['datetime', 'username', 'threat_level', 'action_taken', 'confidence']
            
            if 'verdict' in df.columns:
                df['verdict_display'] = df['verdict'].str.replace('_', ' ').str.title()
                threat_idx = display_cols.index('threat_level')
                display_cols.insert(threat_idx + 1, 'verdict_display')
            
            available_cols = [c for c in display_cols if c in df.columns]
            st.dataframe(df[available_cols].sort_values('datetime', ascending=False), use_container_width=True)
        else:
            st.info("No threats detected yet. Upload a file to see history.")
            
    except Exception as e:
        st.error(f"Could not load threat history: {e}")

# --------------------  SYSTEM HEALTH  --------------------
elif page == "System Health":
    st.markdown('<div class="main-header"><h1>⚙️ System Health</h1><p>Monitor system status and AI models</p></div>', unsafe_allow_html=True)
    try:
        health = requests.get(f"{API_URL}/health").json()
        stats = requests.get(f"{API_URL}/system-stats").json()
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Overall Status", health["status"].title())
            st.metric("Version", health["version"])
            st.metric("Uptime", stats["system_uptime"])
        
        with col2:
            for f, s in health["features"].items():
                st.write(f"{'✅' if s == 'active' else '❌'} {f.replace('_', ' ').title()}: {s}")
        
        with col3:
            st.metric("Total Threats", stats["total_threats_detected"])
            st.metric("Auto-Blocks", stats["auto_blocks_performed"])
            st.metric("Blocked Users", stats["current_blocked_users"])
            
    except Exception as e:
        st.error(f"Health check failed: {e}")

# --------------------  FOOTER  --------------------
st.sidebar.markdown("---")
if st.sidebar.checkbox("🔄 Auto-refresh (10 s)"):
    time.sleep(10)
    st.rerun()