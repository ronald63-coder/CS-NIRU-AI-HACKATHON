# login.py — unified authentication (login | register | forgot password)
import streamlit as st
import requests
import re
from datetime import datetime
import base64

API_URL = "http://localhost:8000"

# ==================== SESSION STATE INITIALIZATION ====================
# Initialize ALL session state keys properly (MOVE THIS OUTSIDE THE FUNCTION)
if "auth_view" not in st.session_state:
    st.session_state["auth_view"] = "login"  # login, register, forgot

if 'login_attempts' not in st.session_state:
    st.session_state['login_attempts'] = 0

# Initialize other session state keys
if "show_register" not in st.session_state:
    st.session_state["show_register"] = False
if "prefill_username" not in st.session_state:
    st.session_state["prefill_username"] = ""
if "prefill_password" not in st.session_state:
    st.session_state["prefill_password"] = ""
if "reset_email" not in st.session_state:
    st.session_state["reset_email"] = ""
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "access_token" not in st.session_state:
    st.session_state["access_token"] = None
if "user" not in st.session_state:
    st.session_state["user"] = None
if "login_time" not in st.session_state:
    st.session_state["login_time"] = None

# Initialize form field keys
form_keys = [
    "reg_user", "reg_email", "reg_name", "reg_pass", "reg_confirm", "reg_terms",
    "login_user", "login_pass", "reset_email_input"
]
for k in form_keys:
    if k not in st.session_state:
        if k == "reg_terms":
            st.session_state[k] = False
        else:
            st.session_state[k] = ""


# ==================== UTILS ====================

def is_logged_in():
    return st.session_state.get("logged_in", False)


def logout():
    tok = st.session_state.get("access_token")
    if tok:
        try:
            requests.post(f"{API_URL}/auth/logout", headers={"Authorization": f"Bearer {tok}"})
        except:
            pass
    
    # Clear session state
    keys = ["access_token", "user", "logged_in", "login_time", 
            "prefill_username", "prefill_password", "show_register", "reset_email"]
    for k in keys:
        if k in st.session_state:
            del st.session_state[k]
    
    # Reset auth_view
    st.session_state["auth_view"] = "login"
    st.rerun()


def get_auth_header():
    tok = st.session_state.get("access_token")
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def validate_password(pwd: str) -> list:
    """Return list of password errors"""
    errors = []
    if len(pwd) < 8:
        errors.append("At least 8 characters")
    if not re.search(r"[A-Z]", pwd):
        errors.append("One uppercase letter")
    if not re.search(r"\d", pwd):
        errors.append("One number")
    return errors


def get_base64_of_bin_file(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()


def set_png_as_page_bg(png_file):
    """Set background image with proper overlay"""
    bin_str = get_base64_of_bin_file(png_file)
    page_bg_img = '''
    <style>
    /* Main app background */
    .stApp {
        background-image: url("data:image/png;base64,%s");
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        background-attachment: fixed;
        position: relative;
    }
    
    /* Semi-transparent overlay */
    .stApp::before {
        content: "";
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: linear-gradient(135deg, rgba(0,20,40,0.92) 0%, rgba(0,40,70,0.95) 100%);
        z-index: 0;
        pointer-events: none;
    }
    
    /* Ensure main content is above overlay */
    .main {
        position: relative;
        z-index: 2;
        background: transparent;
    }
    
    /* Style the main content container */
    .main .block-container {
        background: rgba(255, 255, 255, 0.98);
        border-radius: 20px;
        padding: 2.5rem;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        border: 1px solid rgba(255, 255, 255, 0.1);
        margin: 2rem auto;
        max-width: 500px;
        animation: slideUp 0.5s ease-out;
        position: relative;
        z-index: 3;
    }
    
    /* Ensure all Streamlit elements are above overlay */
    .stApp > div {
        position: relative;
        z-index: 2;
    }
    
    /* Fix for Streamlit's default z-index issues */
    .element-container, .stTextInput, .stButton, .stAlert, .stMarkdown {
        position: relative;
        z-index: 3;
    }
    
    /* Form field styling */
    .stTextInput > div > div > input {
        border-radius: 10px;
        border: 1.5px solid #e2e8f0;
        padding: 0.75rem 1rem;
        font-size: 0.95rem;
        transition: all 0.2s ease;
        background: #ffffff;
        z-index: 4;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #2563eb;
        box-shadow: 0 0 0 3px rgba(37,99,235,0.2);
        background: white;
    }
    
    /* Button styling */
    .stButton > button {
        border-radius: 10px;
        padding: 0.75rem 1.5rem;
        font-weight: 500;
        font-size: 0.95rem;
        transition: all 0.2s ease;
        border: none;
        background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
        color: white;
        width: 100%;
        box-shadow: 0 4px 6px -1px rgba(37,99,235,0.3);
        z-index: 4;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #1d4ed8 0%, #1e3a8a 100%);
        transform: translateY(-1px);
        box-shadow: 0 10px 15px -3px rgba(37,99,235,0.4);
    }
    
    /* Logo/Header styling */
    .logo-container {
        text-align: center;
        margin-bottom: 2rem;
        position: relative;
        z-index: 3;
    }
    
    .logo-container h1 {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #2563eb, #1e40af);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
        letter-spacing: -0.5px;
    }
    
    .logo-container p {
        color: #64748b;
        font-size: 0.95rem;
        font-weight: 400;
    }
    
    /* Link styling */
    .auth-links {
        text-align: center;
        margin-top: 2rem;
        padding-top: 1.5rem;
        border-top: 1px solid #e2e8f0;
        position: relative;
        z-index: 3;
    }
    
    .auth-links button {
        background: none;
        border: none;
        color: #2563eb;
        font-size: 0.95rem;
        font-weight: 500;
        cursor: pointer;
        padding: 0.5rem 1rem;
        width: auto;
        box-shadow: none;
    }
    
    .auth-links button:hover {
        color: #1d4ed8;
        text-decoration: underline;
        background: none;
        transform: none;
        box-shadow: none;
    }
    
    /* Form title */
    .form-title {
        text-align: center;
        margin-bottom: 2rem;
    }
    
    .form-title h3 {
        color: #0f172a;
        font-size: 1.8rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }
    
    .form-title p {
        color: #64748b;
        font-size: 0.95rem;
    }
    
    /* Animation */
    @keyframes slideUp {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    /* Footer styling */
    .footer {
        text-align: center;
        margin-top: 2rem;
        padding-top: 1.5rem;
        border-top: 1px solid #e2e8f0;
        color: #64748b;
        font-size: 0.85rem;
        position: relative;
        z-index: 3;
    }
    
    /* Responsive adjustments */
    @media (max-width: 640px) {
        .main .block-container {
            padding: 1.5rem;
            margin: 1rem;
        }
    }
    </style>
    ''' % bin_str
    
    st.markdown(page_bg_img, unsafe_allow_html=True)


# ==================== FORGOT PASSWORD ====================

def show_forgot_password():
    """Password reset flow"""
    st.markdown("""
    <div class='form-title'>
        <h3>Reset Password</h3>
        <p>Enter your email to receive reset instructions</p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("forgot_form"):
        email = st.text_input("Email Address", key="reset_email_input", 
                            placeholder="name@organization.ke")
        submit = st.form_submit_button("Send Reset Link", use_container_width=True)
    
    if submit:
        if not email or "@" not in email:
            st.error("Please enter a valid email address")
            return
        
        with st.spinner("Sending reset link..."):
            try:
                # Mock API call — replace with real endpoint
                st.success("✅ Reset link sent successfully!")
                st.info("📧 Please check your email for instructions")
                
            except Exception as e:
                st.error(f"Error: {e}")
    
    # Back to login button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("← Back to Login", key="back_to_login_from_forgot"):
            st.session_state["auth_view"] = "login"
            st.rerun()


# ==================== REGISTER ====================

def show_register():
    """Registration form"""
    st.markdown("""
    <div class='form-title'>
        <h3>Create Account</h3>
        <p>Register as a security operator</p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("register_form"):
        col1, col2 = st.columns(2)
        with col1:
            st.text_input("Username *", key="reg_user", placeholder="johndoe")
            st.text_input("Email *", key="reg_email", placeholder="john@agency.ke")
        
        with col2:
            st.text_input("Full Name", key="reg_name", placeholder="John Doe")
            st.selectbox("Role", ["SOC Analyst", "Security Manager", "IT Admin", "Executive"], key="reg_role")
        
        st.text_input("Password *", type="password", key="reg_pass", placeholder="••••••••")
        st.text_input("Confirm Password *", type="password", key="reg_confirm", placeholder="••••••••")
        
        st.checkbox("I agree to the Terms of Service", key="reg_terms")
        
        submitted = st.form_submit_button("Create Account", use_container_width=True)
    
    if submitted:
        handle_register()
    
    # Back to login button (outside form)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("← Back to Login", key="back_to_login_from_register"):
            st.session_state["auth_view"] = "login"
            st.rerun()


def handle_register():
    """Process registration form submission"""
    # Get values from session state
    username = st.session_state.get("reg_user", "").strip()
    email = st.session_state.get("reg_email", "").strip()
    full_name = st.session_state.get("reg_name", "").strip()
    password = st.session_state.get("reg_pass", "")
    confirm = st.session_state.get("reg_confirm", "")
    role = st.session_state.get("reg_role", "SOC Analyst")
    agree = st.session_state.get("reg_terms", False)
    
    # Validation
    errors = []
    
    if not username or len(username) < 3:
        errors.append("Username must be at least 3 characters")
    
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        errors.append("Valid email required")
    
    pwd_errors = validate_password(password)
    if pwd_errors:
        errors.append(f"Password needs: {', '.join(pwd_errors)}")
    
    if password != confirm:
        errors.append("Passwords do not match")
    
    if not agree:
        errors.append("You must agree to the terms")
    
    if errors:
        for e in errors:
            st.error(f"❌ {e}")
        return
    
    # API call
    with st.spinner("Creating account..."):
        try:
            user_data = {
                "username": username,
                "email": email,
                "full_name": full_name if full_name else username,
                "password": password,
                "role": role,
                "is_admin": False
            }
            
            res = requests.post(
                f"{API_URL}/auth/register",
                json=user_data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if res.status_code == 201:
                st.success("✅ Account created successfully!")
                
                # Auto-fill login
                st.session_state["prefill_username"] = username
                st.session_state["prefill_password"] = password
                st.session_state["auth_view"] = "login"
                
                # Clear register fields
                for k in ["reg_user", "reg_email", "reg_name", "reg_pass", "reg_confirm", "reg_terms"]:
                    if k in st.session_state:
                        st.session_state[k] = "" if k != "reg_terms" else False
                
                st.rerun()
                
            elif res.status_code == 400:
                detail = res.json().get("detail", "Registration failed")
                st.error(f"❌ {detail}")
                    
            else:
                st.error(f"❌ Server error: {res.status_code}")
                
        except requests.exceptions.ConnectionError:
            st.error("🔌 Cannot connect to backend")
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")


# ==================== LOGIN ====================

def show_login():
    """Login form"""
    with st.form("login_form"):
        st.markdown("""
        <div class='form-title'>
            <h3>Sign In</h3>
            <p>Access your security dashboard</p>
        </div>
        """, unsafe_allow_html=True)
        
        default_user = st.session_state.get("prefill_username", "")
        default_pass = st.session_state.get("prefill_password", "")
        
        st.text_input("Username", key="login_user", value=default_user, placeholder="Enter your username")
        st.text_input("Password", type="password", key="login_pass", value=default_pass, placeholder="••••••••")
        
        col1, col2 = st.columns(2)
        with col1:
            login_btn = st.form_submit_button("Sign In", use_container_width=True)
        with col2:
            demo_btn = st.form_submit_button("Demo Access", use_container_width=True)
    
    if login_btn:
        handle_login()
    
    if demo_btn:
        demo_login()
    
    # Links below using columns with buttons
    st.markdown("<div class='auth-links'>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1, 1])
    
    with col1:
        if st.button("Create Account", key="goto_register", use_container_width=True):
            st.session_state["auth_view"] = "register"
            st.rerun()
    
    with col2:
        st.markdown("<p style='text-align: center; color: #cbd5e1;'>•</p>", unsafe_allow_html=True)
    
    with col3:
        if st.button("Forgot Password?", key="goto_forgot", use_container_width=True):
            st.session_state["auth_view"] = "forgot"
            st.rerun()
    
    st.markdown("</div>", unsafe_allow_html=True)


def handle_login():
    """Process login form"""
    username = st.session_state.get("login_user", "").strip()
    password = st.session_state.get("login_pass", "")
    
    if not username or not password:
        st.error("Please enter your credentials")
        return
    
    with st.spinner("Authenticating..."):
        try:
            res = requests.post(
                f"{API_URL}/auth/login",
                data={"username": username, "password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            
            if res.status_code == 200:
                data = res.json()
                st.session_state["access_token"] = data["access_token"]
                st.session_state["user"] = data["user"]
                st.session_state["logged_in"] = True
                st.session_state["login_time"] = datetime.now()
                
                st.rerun()
                
            else:
                detail = res.json().get("detail", "Login failed")
                st.error(f"❌ {detail}")
                
        except requests.exceptions.ConnectionError:
            st.error("🔌 Cannot connect to backend")
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")


def demo_login():
    """One-click demo access"""
    st.session_state["access_token"] = "demo_token"
    st.session_state["user"] = {
        "username": "demo_user",
        "email": "demo@cybersentry.ai",
        "full_name": "Demo User",
        "role": "Administrator",
        "is_admin": True
    }
    st.session_state["logged_in"] = True
    st.session_state["login_time"] = datetime.now()
    
    st.rerun()


# ==================== MAIN LOGIN PAGE ====================

def show_login_page(bg_image_path=None):
    """Unified login page with clean enterprise styling"""
    
    # Set background image if provided
    if bg_image_path:
        try:
            set_png_as_page_bg(bg_image_path)
        except Exception as e:
            st.warning(f"Could not load background image: {e}")
    
    # Header
    st.markdown("""
    <div class='logo-container'>
        <h1>🛡️ CybeSentry AI</h1>
        <p>National Cyber Defense Infrastructure</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Show the appropriate view based on session state
    if st.session_state.get("auth_view", "login") == "register":
        show_register()
    elif st.session_state.get("auth_view", "login") == "forgot":
        show_forgot_password()
    else:  # default to login
        show_login()
    
    # Footer
    st.markdown("""
    <div class='footer'>
        <p>© 2026 CyberSentry AI</p> </div>

    """, unsafe_allow_html=True)


# ==================== EXPORTS ====================

__all__ = ['show_login_page', 'is_logged_in', 'logout', 'get_auth_header']