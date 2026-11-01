# 🛡️ PhishGuard AI — Chrome Extension (Manifest V3)

A real-time cybersecurity browser extension powered by a neural machine-learning model that detects phishing websites and protects users from malicious links.

> **Important:** This extension does NOT contain any API keys.
> It communicates exclusively with your PhishGuard FastAPI backend server.

---

## 🚀 How to Install (Chrome / Brave / Edge)

1. Open your browser and navigate to:
   - **Chrome**: `chrome://extensions`
   - **Brave**: `brave://extensions`
   - **Edge**: `edge://extensions`
2. Toggle **Developer mode** on (top-right corner).
3. Click the **Load unpacked** button.
4. Select the `extension/` directory inside this repository.
5. Click **Select Folder**. PhishGuard AI is now installed!
6. Click the extensions puzzle icon (🧩) in your browser toolbar and click the **Pin** icon next to PhishGuard AI.

---

## 🌐 Setting the Backend URL

By default, the extension connects to `http://localhost:8000` (your local FastAPI dev server).

To point to a deployed cloud backend:

1. Click the **PhishGuard shield icon** in your browser toolbar.
2. Click the **⚙️ Settings gear** icon (top-right of the popup).
3. In the **API Endpoint URL** field, enter your backend URL, e.g.:
   ```
   https://phishguard-api.onrender.com
   ```
4. Click **Test** — you should see a green **✓ Connected successfully** with latency.
5. Click **Save Preferences**.

The URL is stored in `chrome.storage.local` (private to the extension). It is never sent anywhere except to the backend you configure.

---

## ⚡ Features

- **Real-Time Active Page Scanning**: Detects phishing when you navigate to any webpage.
- **Dynamic Action Badging**:
  - 🟢 **✓ Green**: Safe site
  - 🟡 **⚠ Amber**: Medium risk
  - 🔴 **! Red**: Phishing detected / High risk
- **In-Page Security Banner**: Injects an unmissable security warning modal if a user lands on a verified phishing domain. Users can click *"I understand the risks — proceed anyway"* to dismiss.
- **Manual URL Inspector**: Paste links from emails, SMS, or chats before opening them.
- **27 Feature Telemetry**: Domain entropy, raw IP presence, suspicious keywords, subdomain depth, and character frequency.
- **Configurable Backend**: Switch between local development and any deployed cloud API endpoint.
- **Connection Tester**: Built-in latency test button to verify backend connectivity.
- **Recent Scan History**: Access results from your last 5 threat assessments with one click.

---

## 📁 Extension File Structure

```
extension/
├── manifest.json    # Chrome Manifest V3 configuration
├── background.js    # Service worker: auto-scan, badges, API calls
├── popup.html       # Extension popup UI markup
├── popup.js         # Popup logic: scan, settings, history
├── popup.css        # Popup styling
├── content.js       # In-page phishing warning banner injection
├── content.css      # Warning banner styles
├── icons/           # Extension icons (16/32/48/128px)
└── README.md        # This file
```

---

## 🔒 Security Notes

- **No API keys** are stored in the extension. It only sends URLs to your self-hosted backend.
- **Permissions are minimal**: `activeTab`, `tabs`, `storage`, `notifications`, `alarms`.
- **`host_permissions`** are scoped to `localhost` and `127.0.0.1` only. For production backends, Chrome will prompt the user for permission on first use.
- The phishing warning modal is **non-blocking** — users can dismiss it to continue navigating.
