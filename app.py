import streamlit as st
import streamlit_authenticator as stauth
import yaml
from yaml.loader import SafeLoader
import joblib
import pandas as pd
import re
import requests
from bs4 import BeautifulSoup
from datetime import datetime

# ---------------- PAGE CONFIG (UNCHANGED) ----------------
st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="centered")

# ---------------- CUSTOM CSS (UNCHANGED) ----------------
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .login-card {
        background-color: #1e2937;
        padding: 40px;
        border-radius: 16px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        max-width: 420px;
        margin: 60px auto;
        text-align: center;
    }
    .title { font-size: 32px; font-weight: bold; color: #00d4ff; margin-bottom: 30px; }
    .stTextInput > div > div > input { background-color: #334155; color: white; border: 2px solid #475569; }
    .stButton>button { background-color: #00d4ff; color: black; font-weight: bold; height: 50px; border-radius: 10px; }
    .stButton>button:hover { background-color: #00b8d9; }
    </style>
""", unsafe_allow_html=True)

# ---------------- TRUSTED DOMAINS ----------------
trusted_domains = [
    "hdfc.bank", "sbi.co.in", "icicibank.com", "axisbank.com",
    "bankofbaroda.in", "pnbindia.in", "canarabank.com",
    "unionbankofindia.co.in", "indianbank.in",
    "centralbankofindia.co.in", "idbibank.in",
    "kotak.com", "yesbank.in", "rblbank.com",
    "federalbank.co.in", "bandhanbank.com", "indusind.com",
    "paytm.com", "phonepe.com", "google.com", "amazonpay.in", "bhimupi.org",
    "gov.in", "nic.in", "india.gov.in", "uidai.gov.in", "incometax.gov.in",
]

# ---------------- WEBSITE CONTENT SCAN ----------------
def scan_website_content(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            return "⚠️ Cannot reach this website", "warning"

        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else ""
        meta = soup.find("meta", attrs={"name": "description"})
        desc = meta["content"] if meta else ""

        suspicious_words = [
            "login", "signin", "verify", "bank",
            "account", "password", "secure", "update"
        ]

        suspicious_count = sum(word in (title + desc).lower() for word in suspicious_words)
        has_password_field = bool(soup.find("input", {"type": "password"}))

        if suspicious_count >= 2 or has_password_field:
            return "⚠️ Suspicious website content detected", "error"

        return "✅ Website content looks normal", "success"

    except:
        return "⚠️ Cannot scan website", "warning"

# ---------------- LOAD CREDENTIALS ----------------
with open("credentials.yaml", "r", encoding="utf-8") as file:
    config = yaml.load(file, Loader=SafeLoader)

authenticator = stauth.Authenticate(
    config["credentials"],
    config["cookie"]["name"],
    config["cookie"]["key"],
    config["cookie"]["expiry_days"],
)

# ---------------- LOGIN ----------------
name, authentication_status, username = authenticator.login("Login", "main")

# ---------------- MAIN APP ----------------
if authentication_status:

    st.sidebar.success(f"Welcome {name}")
    authenticator.logout("Logout", "sidebar")

    is_premium = (username == "premium_user")

    @st.cache_resource
    def load_model():
        return joblib.load("phishing_model.pkl")

    model = load_model()

    st.title("🛡️ PhishGuard AI")
    st.subheader("Real-Time Phishing URL Detector")

    url = st.text_input("Enter suspicious URL", placeholder="https://example.com")

    col1, col2 = st.columns(2)

    # ---------------- SCAN URL ----------------
    with col1:
        if st.button("🔍 Scan URL", type="primary", use_container_width=True):
            if url:
                with st.spinner("Analyzing URL..."):

                    is_trusted = any(domain in url.lower() for domain in trusted_domains)

                    features = {
                        "url_length": len(url),
                        "has_https": 1 if url.startswith("https") else 0,
                        "num_special": len(re.findall(r"[^a-zA-Z0-9]", url)),
                        "num_digits": sum(c.isdigit() for c in url),
                        "has_ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", url) else 0,
                        "suspicious_count": sum(
                            w in url.lower()
                            for w in ["login", "verify", "bank", "free", "update", "secure", "account"]
                        ),
                    }

                    df = pd.DataFrame([features])
                    prob = model.predict_proba(df)[0][1]

                    # ---------- RESULT ----------
                    if is_trusted:
                        st.success("✅ Trusted official website (domain-based check)")
                    elif prob > 0.5:
                        st.error(f"⚠️ Phishing detected ({prob:.2%})")
                    else:
                        st.success(f"✅ Safe URL ({1 - prob:.2%})")

                    # ---------- PREMIUM FEATURES (ALWAYS SHOWN FOR PREMIUM) ----------
                    if is_premium:
                        st.markdown("### 🔐 Premium Analysis")

                        if prob > 0.8:
                            risk = "🔴 High Risk"
                        elif prob > 0.5:
                            risk = "🟡 Medium Risk"
                        else:
                            risk = "🟢 Low Risk"

                        st.write(f"**Risk Level:** {risk}")
                        st.write(f"**Phishing Probability:** {prob:.2%}")

                        st.markdown("#### 📊 Feature Breakdown")
                        for k, v in features.items():
                            st.write(f"- {k.replace('_',' ').title()}: {v}")

                        st.markdown("#### 🛡️ Recommended Action")
                        if prob > 0.5:
                            st.warning(
                                "Do NOT click or enter personal details. "
                                "Verify through the official website or mobile app."
                            )
                        else:
                            st.success("URL looks safe, but always stay cautious.")

                        report = f"""
PhishGuard AI – Scan Report
--------------------------
URL: {url}
Trusted Domain: {is_trusted}
Risk Level: {risk}
Probability: {prob:.2%}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

                        st.download_button(
                            "⬇️ Download Scan Report",
                            report,
                            file_name="phishguard_report.txt"
                        )
                    else:
                        st.info("🔒 Upgrade to Premium for detailed analysis & report download")

            else:
                st.warning("Please enter a URL")

    # ---------------- WEBSITE CONTENT SCAN ----------------
    with col2:
        if st.button("🌐 Scan Website Content", use_container_width=True):
            if url:
                with st.spinner("Checking website content..."):
                    result, alert = scan_website_content(url)
                    if alert == "success":
                        st.success(result)
                    elif alert == "warning":
                        st.warning(result)
                    else:
                        st.error(result)
            else:
                st.warning("Please enter a URL")

elif authentication_status is False:
    st.error("Username or password is incorrect")

else:
    st.warning("Please enter your credentials")
