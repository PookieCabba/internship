# 🛡️ PhishGuard AI — Chrome Extension (Manifest V3)

A real-time cybersecurity browser extension powered by a neural machine-learning model that detects phishing websites and protects users from malicious links.

---

## 🚀 How to Install in Chrome / Brave / Edge

1. Open your browser and navigate to:
   - **Chrome**: `chrome://extensions`
   - **Brave**: `brave://extensions`
   - **Edge**: `edge://extensions`
2. Toggle **Developer mode** on (top-right corner).
3. Click the **Load unpacked** button.
4. Select the `extension/` directory inside this repository:
   ```
   /Users/ujjwalsingh/Desktop/internship/extension
   ```
5. Click **Select Folder**. PhishGuard AI is now installed!
6. Click the extension puzzle icon in your browser toolbar and click the **Pin** icon next to PhishGuard AI.

---

## ⚡ Features

- **Real-Time Active Page Scanning**: Detects phishing when you navigate to any webpage.
- **Dynamic Action Badging**:
  - 🟢 **✓ Green**: Safe site
  - 🟡 **⚠ Amber**: Medium risk
  - 🔴 **! Red**: Phishing detected / High risk
- **In-Page Security Banner**: Injects an unmissable security warning modal if a user lands on a verified phishing domain.
- **Manual URL Inspector**: Paste links from emails, SMS, or chats before opening them.
- **27 Feature Telemetry**: Domain entropy, raw IP presence, suspicious keywords, subdomain depth, and character frequency.
- **Configurable Backend**: Switch between local development (`http://localhost:8000`) or any deployed cloud API endpoint with the built-in latency tester.
- **Recent Scan History**: Access results from your last 5 threat assessments with one click.

---

## 🌐 Connecting to the Backend API

By default, the extension connects to `http://localhost:8000`.

To point to a deployed cloud server:
1. Click the PhishGuard icon in your browser toolbar.
2. Click the ⚙️ (Settings) icon in the top right.
3. Paste your public API URL (e.g., `https://phishguard-api.onrender.com`).
4. Click **Test** to verify latency.
5. Click **Save Preferences**.
