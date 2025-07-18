import streamlit as st
import json
import os
from gmail_client import GmailClient
from phishing_detector import PhishingDetector
from auth import login_block

st.set_page_config(page_title="Phishing Email Detector", layout="wide")

# 🔒 Login Gate (returns email if logged in)
user_email = login_block()
if not user_email:
    st.stop()

# 🔐 Sidebar: Logout option
with st.sidebar:
    st.title("Session")
    st.markdown(f"**Logged in as:** {user_email}")
    if st.button("🔓 Logout"):
        token_path = f"token_{user_email}.pkl"
        if os.path.exists(token_path):
            os.remove(token_path)
        st.session_state.clear()
        st.rerun()

# 🎯 Main App Logic
st.title("📬 Gmail Inbox - Phishing Detection")

gmail = GmailClient(user_email)
detector = PhishingDetector()

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = gmail.authenticate()

if not st.session_state.authenticated:
    st.error("❌ Authentication failed. Please check credentials.")
    st.stop()

emails = gmail.get_recent_emails(limit=20)
st.subheader("📥 Recent Emails")

phishing_count = 0

for email in emails:
    score = detector.calculate_risk_score(email)
    level = detector.get_risk_level(score)
    threats = detector.detect_threats(email)

    if level == "High":
        phishing_count += 1

    with st.expander(f"📧 {email['subject']}"):
        st.markdown(f"**From:** {email['sender']}")
        st.markdown(f"**Date:** {email['date']}")
        st.markdown(f"**Labels:** {', '.join(email.get('labels', []))}")
        st.markdown("---")
        st.write(email['content'])
        st.markdown("---")
        st.metric("Phishing Risk Score", f"{score:.2f}", level)

        if threats:
            st.warning("⚠️ Threat Indicators:")
            for t in threats:
                st.write(f"- {t}")
        else:
            st.success("✅ No significant phishing indicators detected.")

        if level == "High" and st.button(f"🚫 Mark email `{email['id']}` as spam", key=email['id']):
            success = gmail.mark_as_spam(email['id'])
            if success:
                st.success("Marked as spam.")
            else:
                st.error("Failed to mark as spam.")

# 📊 Summary
st.markdown("---")
st.metric("🚨 Total Phishing Emails Detected", f"{phishing_count} of {len(emails)}")