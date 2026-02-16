import streamlit as st
import streamlit_authenticator as stauth
import yaml
from yaml.loader import SafeLoader
import joblib
import pandas as pd
import re
import requests
from bs4 import BeautifulSoup

# ── Page config (modern look) ──
st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="wide")

# ── Custom CSS for dashboard style ──
st.markdown("""
    <style>
    .main { background-color: #0e1117; color: white; }
    .stButton>button { background-color: #00b8d9; color: white; border: none; }
    .stButton>button:hover { background-color: #00a0c0; }
    .card { background-color: #1e293b; border-radius: 10px; padding: 20px; margin: 10px 0; text-align: center; }
    .stat-number { font-size: 36px; font-weight: bold; color: #00b8d9; }
    .stat-label { font-size: 16px; color: #94a3b8; }
    .feature-box { background-color: #1e293b; border-radius: 10px; padding: 20px; margin: 10px; }
    </style>
""", unsafe_allow_html=True)

# ── Website content scanner ──
def scan_website_content(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            return "⚠️ Cannot reach this website – likely fake or blocked", "warning"
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else "No title"
        meta = soup.find("meta", attrs={"name": "description"})
        desc = meta["content"] if meta else "No description"
        suspicious_keywords = ["login", "signin", "verify", "bank", "account", "password", "update", "secure"]
        suspicious_count = sum(word in (title + desc).lower() for word in suspicious_keywords)
        has_login_form = bool(soup.find("input", {"type": "password"}))
        if suspicious_count >= 2 or has_login_form:
            return f"⚠️ Suspicious content detected (score: {suspicious_count})", "error"
        return "✅ Website content looks normal", "success"
    except Exception as e:
        return "⚠️ Cannot reach this website – domain may not exist", "warning"

# ── Load credentials ──
try:
    with open("credentials.yaml", "r", encoding="utf-8") as file:
        config = yaml.load(file, Loader=SafeLoader)
except Exception as e:
    st.error(f"Credentials error: {e}")
    st.stop()

authenticator = stauth.Authenticate(
    config["credentials"],
    config["cookie"]["name"],
    config["cookie"]["key"],
    config["cookie"]["expiry_days"],
)

# ── Login ──
name, authentication_status, username = authenticator.login(
    location="sidebar",
    form_name="Login to PhishGuard AI"
)

# ── Cache clear ──
if st.button("🧹 Clear Cache", help="Click if app feels slow"):
    st.cache_data.clear()
    st.cache_resource.clear()
    st.session_state.clear()
    st.success("Cache cleared!")
    st.rerun()

# ── App ──
if authentication_status:
    st.sidebar.success(f"Welcome {name}!")

    is_premium = (username == "premium_user")
    st.session_state["is_premium"] = is_premium

    # Lazy load model
    if "model" not in st.session_state:
        with st.spinner("Loading AI model..."):
            st.session_state.model = joblib.load("phishing_model.pkl")
    model = st.session_state.model

    # ── Hero / Stats section ──
    st.markdown("<h1 style='text-align: center; color: #00b8d9;'>🛡️ PhishGuard AI</h1>", unsafe_allow_html=True)
    st.markdown("<h3 style='text-align: center; color: #94a3b8;'>Real-Time Phishing Protection</h3>", unsafe_allow_html=True)

    cols = st.columns(3)
    with cols[0]:
        st.markdown('<div class="card"><div class="stat-number">1,247</div><div class="stat-label">Threats Blocked</div></div>', unsafe_allow_html=True)
    with cols[1]:
        st.markdown('<div class="card"><div class="stat-number">15,632</div><div class="stat-label">Sites Scanned</div></div>', unsafe_allow_html=True)
    with cols[2]:
        st.markdown('<div class="card"><div class="stat-number">50K+</div><div class="stat-label">Protected Users</div></div>', unsafe_allow_html=True)

    # ── Input section ──
    st.markdown("---")
    url = st.text_input("Enter suspicious URL", placeholder="https://example.com or http://fake-login.com")

    if url.strip():
        if url.lower().startswith("https"):
            st.info("🔒 HTTPS detected – encrypted connection")
        else:
            st.warning("⚠️ HTTP detected – unencrypted, higher risk")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("🔍 Scan URL", type="primary"):
            if not url.strip():
                st.warning("Enter a URL first")
            else:
                with st.spinner("Analyzing URL..."):
                    try:
                        features = {
                            "url_length": len(url),
                            "has_https": 1 if url.lower().startswith("https") else 0,
                            "num_special": len(re.findall(r"[^a-zA-Z0-9]", url)),
                            "num_digits": sum(c.isdigit() for c in url),
                            "has_ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", url) else 0,
                            "suspicious_count": sum(w in url.lower() for w in ["login", "verify", "bank", "free", "update", "secure", "account"]),
                        }
                        df = pd.DataFrame([features])
                        prob = model.predict_proba(df)[0][1]
                        prediction = "Phishing ⚠️" if prob > 0.5 else "Safe ✅"
                        conf = prob if prob > 0.5 else (1 - prob)

                        if prob > 0.5:
                            st.error(f"{prediction} ({conf:.2%})")
                        else:
                            st.success(f"{prediction} ({conf:.2%})")

                        if is_premium:
                            st.subheader("Detailed Analysis")
                            for k, v in features.items():
                                st.write(f"• {k.replace('_', ' ').title()}: {v}")
                            report = f"URL: {url}\nResult: {prediction}\nConfidence: {conf:.2%}"
                            st.download_button("Download Report", report, "scan_report.txt")
                    except Exception as e:
                        st.error(f"Scan error: {e}")

    with col2:
        if st.button("🌐 Scan Website Content"):
            if not url.strip():
                st.warning("Enter a URL first")
            else:
                with st.spinner("Checking website..."):
                    result, alert = scan_website_content(url)
                    if alert == "success":
                        st.success(result)
                    elif alert == "warning":
                        st.warning(result)
                    else:
                        st.error(result)

    authenticator.logout("Logout", "sidebar")

else:
    st.warning("Please login to use the detector.")