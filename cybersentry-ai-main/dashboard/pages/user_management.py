import streamlit as st
import requests
import pandas as pd
from datetime import datetime

def show_user_management():
    """User management page for admins"""
    
    st.title("👥 User Management")
    
    if not st.session_state.get('user', {}).get('is_admin', False):
        st.error("⛔ Admin access required")
        return
    
    # Get auth header
    headers = {"Authorization": f"Bearer {st.session_state.get('access_token')}"}
    
    # Tabs for different management functions
    tab1, tab2, tab3, tab4 = st.tabs(["View Users", "Add User", "User Activity", "Security Logs"])
    
    with tab1:
        st.subheader("System Users")
        
        try:
            # In production, call your API
            # For demo, show sample data
            users_data = [
                {"username": "admin", "email": "admin@company.com", "role": "Administrator", "status": "active", "last_login": "2026-01-15 09:30"},
                {"username": "jane doe", "email": "jane@company.com", "role": "HR Manager", "status": "active", "last_login": "2026-01-15 08:15"},
                {"username": "john smith", "email": "john@company.com", "role": "Developer", "status": "active", "last_login": "2026-01-14 14:20"},
                {"username": "bob wilson", "email": "bob@company.com", "role": "Finance", "status": "blocked", "last_login": "2026-01-13 02:30"},
                {"username": "sarah connor", "email": "sarah@company.com", "role": "Marketing", "status": "active", "last_login": "2026-01-15 10:45"},
            ]
            
            df = pd.DataFrame(users_data)
            
            # Add color coding for status
            def color_status(val):
                if val == "active":
                    return "color: green; font-weight: bold;"
                elif val == "blocked":
                    return "color: red; font-weight: bold;"
                else:
                    return ""
            
            st.dataframe(
                df.style.applymap(color_status, subset=['status']),
                use_container_width=True
            )
            
        except Exception as e:
            st.error(f"Error loading users: {str(e)}")
    
    with tab2:
        st.subheader("Add New User")
        
        with st.form("add_user_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                new_username = st.text_input("Username")
                new_email = st.text_input("Email")
                new_password = st.text_input("Password", type="password")
            
            with col2:
                new_fullname = st.text_input("Full Name")
                new_department = st.selectbox("Department", ["IT", "HR", "Finance", "Marketing", "Engineering", "Operations"])
                new_role = st.text_input("Role")
            
            is_admin = st.checkbox("Administrator privileges")
            
            if st.form_submit_button("➕ Add User"):
                if all([new_username, new_email, new_password]):
                    st.success(f"User {new_username} added successfully!")
                else:
                    st.error("Please fill all required fields")
    
    with tab3:
        st.subheader("User Activity Monitor")
        
        # Show recent logins
        st.info("Recent login activity (last 24 hours)")
        
        activity_data = [
            {"user": "jane doe", "time": "08:15 AM", "ip": "192.168.1.101", "status": "✅", "risk": "low"},
            {"user": "bob wilson", "time": "02:30 AM", "ip": "45.67.89.123", "status": "🚫", "risk": "high"},
            {"user": "john smith", "time": "02:15 PM", "ip": "192.168.1.105", "status": "✅", "risk": "low"},
            {"user": "admin", "time": "09:30 AM", "ip": "192.168.1.100", "status": "✅", "risk": "low"},
        ]
        
        for activity in activity_data:
            col1, col2, col3, col4, col5 = st.columns([2, 2, 2, 1, 1])
            with col1:
                st.write(f"**{activity['user']}**")
            with col2:
                st.write(activity['time'])
            with col3:
                st.write(activity['ip'])
            with col4:
                st.write(activity['status'])
            with col5:
                st.write(f"**{activity['risk']}**")
            st.divider()
    
    with tab4:
        st.subheader("Security Events")
        
        # Show security alerts
        events = [
            {"time": "02:30 AM", "event": "Failed login attempts", "user": "bob wilson", "severity": "🔴 High"},
            {"time": "09:15 AM", "event": "Password changed", "user": "jane doe", "severity": "🟢 Low"},
            {"time": "11:45 AM", "event": "New user registered", "user": "sarah connor", "severity": "🟡 Medium"},
            {"time": "03:20 PM", "event": "File upload blocked", "user": "john smith", "severity": "🟡 Medium"},
        ]
        
        for event in events:
            st.write(f"**{event['time']}** - {event['event']}")
            st.write(f"User: {event['user']} | Severity: {event['severity']}")
            st.divider()