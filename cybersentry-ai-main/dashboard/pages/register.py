import streamlit as st
import requests
import re
from datetime import datetime

def show_register_page():
    """User registration page"""
    
    st.markdown("""
    <div style='text-align: center; padding: 2rem;'>
        <h1>📝 Create New Account</h1>
        <p>Join CyberSentry AI Security Platform</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("register_form"):
            st.subheader("Account Information")
            
            col_a, col_b = st.columns(2)
            with col_a:
                username = st.text_input("Username*", 
                    help="Choose a unique username")
                email = st.text_input("Email*", 
                    help="Your email address")
            
            with col_b:
                full_name = st.text_input("Full Name", 
                    help="Your full name (optional)")
                department = st.selectbox("Department", 
                    ["IT", "HR", "Finance", "Marketing", "Engineering", "Operations", "General"])
            
            st.subheader("Security")
            
            col_c, col_d = st.columns(2)
            with col_c:
                password = st.text_input("Password*", type="password",
                    help="At least 8 characters with number and uppercase")
            with col_d:
                confirm_password = st.text_input("Confirm Password*", type="password")
            
            role = st.selectbox("Role", ["User", "Analyst", "Manager", "Administrator"])
            
            # Terms agreement
            agree_terms = st.checkbox("I agree to the Terms of Service and Privacy Policy")
            
            col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
            with col_btn2:
                register_button = st.form_submit_button("🚀 Create Account", use_container_width=True)
        
        if register_button:
            # Validate inputs
            errors = []
            
            if not username:
                errors.append("Username is required")
            elif len(username) < 3:
                errors.append("Username must be at least 3 characters")
            
            if not email or "@" not in email:
                errors.append("Valid email is required")
            
            if not password:
                errors.append("Password is required")
            elif len(password) < 8:
                errors.append("Password must be at least 8 characters")
            elif not re.search(r"[A-Z]", password):
                errors.append("Password must contain an uppercase letter")
            elif not re.search(r"\d", password):
                errors.append("Password must contain a number")
            
            if password != confirm_password:
                errors.append("Passwords do not match")
            
            if not agree_terms:
                errors.append("You must agree to the terms")
            
            if errors:
                for error in errors:
                    st.error(f"❌ {error}")
            else:
                with st.spinner("Creating your account..."):
                    try:
                        # Prepare registration data
                        user_data = {
                            "username": username,
                            "email": email,
                            "full_name": full_name if full_name else username,
                            "password": password,
                            "department": department,
                            "role": role
                        }
                        
                        # Call registration API
                        response = requests.post(
                            "http://localhost:8000/auth/register",
                            json=user_data,
                            headers={"Content-Type": "application/json"}
                        )
                        
                        if response.status_code == 201:
                            st.success("✅ Account created successfully!")
                            st.balloons()
                            
                            # Show next steps
                            st.info("""
                            **Next Steps:**
                            1. You can now login with your new account
                            2. Check your email for verification (in production)
                            3. Complete your security profile
                            """)
                            
                            # Auto-fill login
                            st.session_state['prefill_username'] = username
                            st.session_state['prefill_password'] = password
                            
                            # Offer to go to login
                            if st.button("🔐 Go to Login", use_container_width=True):
                                st.switch_page("streamlit_app.py")  # Redirect to login
                            
                        elif response.status_code == 400:
                            error_detail = response.json().get("detail", "Unknown error")
                            st.error(f"❌ Registration failed: {error_detail}")
                            
                            # Suggest fixes
                            if "already registered" in error_detail.lower():
                                st.info("💡 Try a different username or email")
                            elif "password" in error_detail.lower():
                                st.info("💡 Password must be at least 8 characters with uppercase and number")
                                
                        else:
                            st.error(f"❌ Registration failed: {response.status_code}")
                            
                    except requests.exceptions.ConnectionError:
                        st.error("🔌 Cannot connect to server. Make sure backend is running!")
                        st.code("python app.py")
                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")
        
        # Demo credentials info
        st.markdown("---")
        with st.expander("🔐 Need demo access?"):
            st.markdown("""
            **Default Demo Accounts:**
            
            | Username | Password | Role |
            |----------|----------|------|
            | `admin` | `Admin@123` | 👑 Administrator |
            | `analyst` | `Analyst@123` | 🔍 Security Analyst |
            | `user` | `User@123` | 👤 Regular User |
            
            **Or create your own account above!**
            """)
        
        # Back to login link
        st.markdown("---")
        if st.button("← Back to Login", use_container_width=True):
            # Clear any prefill data
            if 'prefill_username' in st.session_state:
                del st.session_state['prefill_username']
            if 'prefill_password' in st.session_state:
                del st.session_state['prefill_password']
            
            # In actual app, you'd redirect to login page
            st.info("Redirecting to login...")
            st.rerun()  # This will show login page if you modify main app