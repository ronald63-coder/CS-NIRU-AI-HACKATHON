import streamlit as st

def display_metrics_card(title: str, value: str, change: str = "", icon: str = "📊"):
    """Display a metric card"""
    col1, col2 = st.columns([1, 3])
    
    with col1:
        st.markdown(f"<h1 style='font-size: 2.5rem;'>{icon}</h1>", unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"<h3 style='margin: 0;'>{title}</h3>", unsafe_allow_html=True)
        st.markdown(f"<h2 style='margin: 0; color: #667eea;'>{value}</h2>", unsafe_allow_html=True)
        if change:
            st.markdown(f"<p style='margin: 0; font-size: 0.8rem;'>{change}</p>", unsafe_allow_html=True)

def display_alert_card(severity: str, title: str, message: str, time: str):
    """Display an alert card"""
    colors = {
        "high": "#ff6b6b",
        "medium": "#ffd93d",
        "low": "#00d2d3"
    }
    
    icon = "🔴" if severity == "high" else "🟡" if severity == "medium" else "🟢"
    
    st.markdown(f"""
    <div style='
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid {colors.get(severity, "#666")};
        background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
        margin: 0.5rem 0;
        box-shadow: 0 3px 10px rgba(0,0,0,0.1);
    '>
        <div style='display: flex; align-items: center;'>
            <span style='font-size: 1.5rem; margin-right: 0.5rem;'>{icon}</span>
            <div>
                <strong>{title}</strong><br>
                <small>{message}</small><br>
                <small style='color: #666;'>{time}</small>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)