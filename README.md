# 📧 Phishing Email Detection App

A full-stack Streamlit application that connects to a user's Gmail account using OAuth2, scans recent emails, and detects phishing threats using a custom-built phishing detection engine.

---

## 🔍 Features

- 🔐 **User Authentication** (Sign Up & Login)
- 📬 **Gmail Integration** via OAuth 2.0
- 🛡️ **Phishing Detection Engine**
- 🗂️ Threat score, indicators, and spam marking
- 👥 Multi-user support with session handling
- 🚪 Logout functionality (clears session + Gmail token)

---

## 📁 Project Structure

.
├── app.py # Main Streamlit application
├── auth.py # Handles login and signup
├── gmail_client.py # Gmail API integration and email fetching
├── phishing_detector.py # Email phishing detection engine
├── users.json # Stores registered users
├── credentials.json # OAuth 2.0 credentials (Google Cloud)
├── token_<email>.pkl # Token generated for each authenticated user
├── requirements.txt # Project dependencies
└── README.md # Project documentation

yaml
Copy
Edit

---

## 🔧 Tech Stack

- [Python 3.9+](https://www.python.org/)
- [Streamlit](https://streamlit.io/)
- [Google OAuth2 API](https://developers.google.com/identity)
- [Gmail API](https://developers.google.com/gmail/api)
- Custom NLP-based phishing detection logic

---

## 🚀 Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/your-username/phishing-email-detector.git
cd phishing-email-detector
2. Install dependencies
bash
Copy
Edit
pip install -r requirements.txt
3. Setup OAuth2
Go to Google Cloud Console (https://console.cloud.google.com/)

Enable Gmail API

Create OAuth 2.0 Client ID (Desktop)

Download the credentials.json file into your project root

Add your own email addresses to the OAuth 2.0 test users list

4. Run the app
bash
Copy
Edit
streamlit run app.py
👨‍💻 Usage Flow
Sign Up or Log In via the app interface.

Authenticate Gmail access using OAuth.

Emails will be fetched and scanned using PhishingDetector.

View results:

Threat level (Low/Medium/High)

Risk score

Threat indicators (URLs, keywords, etc.)

Mark phishing emails as spam directly from the interface.

Use the Logout button to end the session and clear token.

🔐 Security Notes
All tokens are stored per-user as token_<email>.pkl

Passwords are stored in users.json (plaintext — ⚠️ for production use, hash securely)

Users must be pre-approved in the OAuth 2.0 test users list

Token and session data is deleted upon logout

📌 Requirements
nginx
Copy
Edit
streamlit
google-auth
google-auth-oauthlib
google-api-python-client
beautifulsoup4
lxml
Or install with:

bash
Copy
Edit
pip install -r requirements.txt
📄 License
This project is licensed under the MIT License. See LICENSE for more details.

✨ Acknowledgments
Streamlit Docs : (https://docs.streamlit.io/)

Google Gmail API : (https://developers.google.com/gmail/api)

You, the awesome developer! 🚀

📬 Contact
For questions, feedback, or contributions, reach out at:
your-email@example.com

yaml
Copy
Edit

---

✅ Let me know if you want:
- A DOCX version of this `README`
- Deployed link instructions (Streamlit Cloud / Heroku / Vercel)
- Screenshots or badges added to the README

Ready to paste! ✅
