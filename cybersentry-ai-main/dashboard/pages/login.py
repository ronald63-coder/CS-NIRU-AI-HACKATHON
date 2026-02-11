# login.py  –  tabs (login + register) + full logic + demo
import streamlit as st
import requests
from datetime import datetime

API_URL = "http://localhost:8000"

# ------------------------------------------------------------------
#  UTILS  (missing in newest file)
for k in ("show_register", "prefill_username", "prefill_password"):
    if k not in st.session_state:
        st.session_state[k] = None          # or "" / False as appropriate
# ------------------------------------------------------------------
def is_logged_in():
    return st.session_state.get("logged_in", False)

def logout():
    tok = st.session_state.get("access_token")
    if tok:
        try:
            requests.post(f"{API_URL}/auth/logout", headers={"Authorization": f"Bearer {tok}"})
        except:
            pass
    for k in ["access_token", "user", "logged_in", "login_time", "prefill_username", "prefill_password", "show_register"]:
        if k in st.session_state:
            del st.session_state[k]
    st.rerun()

def get_auth_header():
    tok = st.session_state.get("access_token")
    return {"Authorization": f"Bearer {tok}"} if tok else {}

# ------------------------------------------------------------------
#  REGISTER  (kept inside tab)
# ------------------------------------------------------------------
def register_user():
    """POST /auth/register and auto-fill login on success"""
    reg_user = st.session_state["reg_user"]
    reg_mail = st.session_state["reg_email"]
    reg_pass = st.session_state["reg_pass"]
    reg_conf = st.session_state["reg_confirm"]
    reg_name = st.session_state.get("reg_name", reg_user)
    reg_dept = st.session_state.get("reg_dept", "General")
    reg_role = st.session_state.get("reg_role", "User")
    agree    = st.session_state.get("reg_terms", False)

    if not all([reg_user, reg_mail, reg_pass, reg_conf]):
        st.error("Please fill all required fields (*)"); return
    if reg_pass != reg_conf:
        st.error("Passwords do not match"); return
    if not agree:
        st.error("You must agree to the terms"); return

    with st.spinner("Creating account..."):
        try:
            res = requests.post(
                f"{API_URL}/auth/register",
                json={
                    "username": reg_user,
                    "email": reg_mail,
                    "full_name": reg_name,
                    "password": reg_pass,
                    "department": reg_dept,
                    "role": reg_role,
                    "is_admin": False
                }
            )
            if res.status_code == 201:
                st.success("✅ Account created! You can now log in.")
                # auto-fill login tab
                st.session_state["prefill_username"] = reg_user
                st.session_state["prefill_password"] = reg_pass
                # switch to login tab
                del st.session_state["show_register"]
                st.rerun()
            else:
                st.error(res.json().get("detail", "Registration failed"))
        except requests.exceptions.ConnectionError:
            st.error("🔌 Cannot connect to server. Make sure backend is running!")

# ------------------------------------------------------------------
#  LOGIN PAGE  (tabs: login | register)
# ------------------------------------------------------------------
def show_login_page():
    st.markdown("""
    <div style='text-align: center; padding: 3rem;'>
        <h1>🔐 CyberSentry AI</h1>
        <p>AI-Powered Cybersecurity Platform</p>
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🚀 Login", "📝 Register"])

    # --------------------  LOGIN TAB  --------------------
    with tab1:
        with st.form("login_form"):
            username = st.text_input("Username", value=st.session_state.get("prefill_username", ""))
            password = st.text_input("Password", type="password", value=st.session_state.get("prefill_password", ""))
            login_btn = st.form_submit_button("Login", use_container_width=True)

        if login_btn:
            if not username or not password:
                st.error("Please enter username and password")
            else:
                with st.spinner("Authenticating..."):
                    try:
                        res = requests.post(
                            f"{API_URL}/auth/login",
                            data={"username": username, "password": password},
                            headers={"Content-Type": "application/x-www-form-urlencoded"}
                        )
                        if res.status_code == 200:
                            data = res.json()
                            st.session_state["access_token"] = data["access_token"]
                            st.session_state["user"]         = data["user"]
                            st.session_state["logged_in"]    = True
                            st.session_state["login_time"]   = datetime.now()
                            st.success("✅ Login successful!")
                            st.rerun()
                        else:
                            st.error(res.json().get("detail", "Login failed"))
                    except Exception as e:
                        st.error(f"Connection error: {e}")

        # Demo quick-login
        if st.button("👁️ Demo Login"):
            st.session_state["access_token"] = "demo_token_123"
            st.session_state["user"] = {
                "username": "demo_user", "email": "demo@cybersentry.ai",
                "full_name": "Demo User", "is_admin": True
            }
            st.session_state["logged_in"] = True
            st.session_state["login_time"] = datetime.now()
            st.success("✅ Demo login successful!")
            st.rerun()

    # --------------------  REGISTER TAB  --------------------
    with tab2:
        st.subheader("Create New Account")
        with st.form("register_form"):
            col_a, col_b = st.columns(2)
            with col_a:
                st.text_input("Username *", key="reg_user")
                st.text_input("Email *", key="reg_email")
            with col_b:
                st.text_input("Full Name", key="reg_name")
                st.selectbox("Department", ["IT", "HR", "Finance", "Marketing", "Engineering", "Operations", "General"], key="reg_dept")
            st.selectbox("Role", ["User", "Analyst", "Manager", "Administrator"], key="reg_role")
            st.text_input("Password *", type="password", key="reg_pass", help="≥ 8 chars, number + uppercase")
            st.text_input("Confirm Password *", type="password", key="reg_confirm")
            st.checkbox("I agree to the Terms of Service", key="reg_terms")
            reg_btn = st.form_submit_button("Create Account", use_container_width=True)

        if reg_btn:
            register_user()

    

# ------------------------------------------------------------------
#  EXPORTS  (same interface as before)
# ------------------------------------------------------------------
def logout():
    tok = st.session_state.get("access_token")
    if tok:
        try:
            requests.post(f"{API_URL}/auth/logout", headers={"Authorization": f"Bearer {tok}"})
        except:
            pass
    for k in ["access_token", "user", "logged_in", "login_time", "prefill_username", "prefill_password", "show_register"]:
        if k in st.session_state:
            del st.session_state[k]
    st.rerun()

def is_logged_in():
    return st.session_state.get("logged_in", False)

def get_auth_header():
    tok = st.session_state.get("access_token")
    return {"Authorization": f"Bearer {tok}"} if tok else {}