# 🛡️ PhishGuard AI — Complete Free Deployment Guide

This guide walks you through deploying the complete PhishGuard AI system for **100% free** using:
1. **Render.com** (Free Web Service Tier) → FastAPI Machine Learning Backend
2. **Streamlit Community Cloud** (Free Tier) → Interactive Web Dashboard
3. **Google Chrome** (Developer Mode) → Real-Time Protection Browser Extension

---

## 📋 Table of Contents
- [Prerequisites](#-prerequisites)
- [Step 1: Commit & Push to GitHub](#-step-1-commit--push-to-github)
- [Step 2: Deploy FastAPI Backend to Render](#-step-2-deploy-fastapi-backend-to-render)
- [Step 3: Deploy Streamlit Dashboard to Streamlit Cloud](#-step-3-deploy-streamlit-dashboard-to-streamlit-cloud)
- [Step 4: Configure the Chrome Extension](#-step-4-configure-the-chrome-extension)
- [Step 5: End-to-End Verification Checklist](#-step-5-end-to-end-verification-checklist)
- [Troubleshooting & Free Tier Notes](#-troubleshooting--free-tier-notes)

---

## 🧰 Prerequisites

Before starting, ensure you have:
- A [GitHub](https://github.com) account.
- A [Render](https://render.com) account (free tier, no credit card required).
- A [Streamlit Community Cloud](https://streamlit.io/cloud) account (free, connects to GitHub).
- Google Chrome browser installed locally.
- (Optional) API keys for live threat intelligence:
  - [Google Safe Browsing API Key](https://console.cloud.google.com/)
  - [PhishTank API Key](https://phishtank.org/developer_info.php)

---

## 🚀 Step 1: Commit & Push to GitHub

Ensure all secret files (`.env`, `.streamlit/secrets.toml`) are gitignored and push the latest codebase to your GitHub repository.

1. **Verify git status:**
   ```bash
   git status
   ```
   *Make sure `.env` or `.streamlit/secrets.toml` are NOT staged or tracked.*

2. **Stage your files:**
   ```bash
   git add .
   ```

3. **Commit changes:**
   ```bash
   git commit -m "Prepare production deployment configs for Render and Streamlit Cloud"
   ```

4. **Push to GitHub:**
   ```bash
   git push origin main
   ```

---

## ⚡ Step 2: Deploy FastAPI Backend to Render

Render will host the FastAPI REST API and run the Scikit-Learn/XGBoost ML inference pipeline.

### Method A: Deploy via Blueprint (Fastest)
1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** (top right) and select **Blueprint**.
3. Connect your GitHub repository.
4. Render will automatically detect [`render.yaml`](render.yaml) and configure:
   - **Service Name:** `phishguard-api`
   - **Environment:** `Python`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn api:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path:** `/health`
5. Render will prompt you for the environment variables listed with `sync: false`. Fill them in (see table below).
6. Click **Apply**.

---

### Method B: Deploy as a Web Service Manually
If you prefer manual setup:
1. On [Render Dashboard](https://dashboard.render.com), click **New +** → **Web Service**.
2. Select **Build and deploy from a Git repository** and connect your repository.
3. Configure the service settings:
   - **Name:** `phishguard-api`
   - **Region:** Choose the region closest to you (e.g., Oregon, Frankfurt)
   - **Branch:** `main`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn api:app --host 0.0.0.0 --port $PORT`
   - **Instance Type:** `Free`
4. Expand **Advanced**:
   - **Health Check Path:** `/health`
   - **Auto-Deploy:** `Yes`
5. Under **Environment Variables**, click **Add Environment Variable** for each:

| Key | Example Value | Description |
| :--- | :--- | :--- |
| `PYTHON_VERSION` | `3.11.0` | Python runtime version |
| `ENVIRONMENT` | `production` | App environment |
| `ALLOWED_ORIGINS` | `*` *(or your Streamlit Cloud URL)* | Allowed CORS origins for browser/dashboard access |
| `GOOGLE_SAFE_BROWSING_API_KEY` | *(your-key-or-leave-blank)* | Optional live Google Safe Browsing lookups |
| `PHISHTANK_API_KEY` | *(your-key-or-leave-blank)* | Optional live PhishTank verified database lookups |

6. Click **Create Web Service**.
7. Wait 2–4 minutes for dependencies to install and the build to complete.
8. Once the status shows **Live**, copy your public URL:
   ```
   https://phishguard-api.onrender.com
   ```

---

## 🎨 Step 3: Deploy Streamlit Dashboard to Streamlit Cloud

Streamlit Community Cloud provides free hosting for data apps with direct GitHub integration.

1. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
2. Click **Create app** (or **New app**).
3. Select your repository details:
   - **Repository:** `<your-github-username>/<repo-name>`
   - **Branch:** `main`
   - **Main file path:** `app.py`
   - **App URL (optional):** Customize your subdomain (e.g. `phishguard-ai.streamlit.app`)
4. Click **Advanced settings...** (bottom of the form).
5. In the **Secrets** text area, paste your Render backend URL:
   ```toml
   BACKEND_URL = "https://phishguard-api.onrender.com"
   ```
   *(Replace with your actual Render URL from Step 2)*
6. Click **Save** and then click **Deploy!**
7. Once deployed, test the dashboard:
   - Check the top right of the dashboard: the Backend Status badge should read **Online** (green).
8. **Optional Security Tightening:**
   - Copy your Streamlit app URL (e.g. `https://phishguard-ai.streamlit.app`).
   - Go back to Render Dashboard → `phishguard-api` → **Environment**.
   - Update `ALLOWED_ORIGINS` from `*` to:
     ```
     https://phishguard-ai.streamlit.app
     ```
   - Click **Save Changes** (Render will redeploy with tightened CORS).

---

## 🧩 Step 4: Configure the Chrome Extension

The Chrome extension monitors browser tabs and scans URLs against your deployed backend.

### Option A: Configure via Extension Settings (No Code Edit)
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle on **Developer mode** in the top-right corner.
3. Click **Load unpacked** (top-left).
4. Select the `extension/` folder inside your cloned repository.
5. Click the PhishGuard extension icon in your Chrome toolbar (pin it for convenience).
6. Click the **⚙️ Settings** tab/icon at the top right of the popup.
7. In the **API Base URL** input field, enter your Render API URL:
   ```
   https://phishguard-api.onrender.com
   ```
8. Click **Test Connection**:
   - ✅ A green checkmark confirms the extension reached the `/health` endpoint on Render.
9. Click **Save Preferences**.

---

### Option B: Bake Render URL as Permanent Default in Code
If you want the extension to use your cloud backend by default for anyone who installs it:

1. In `extension/background.js` (line 6), update:
   ```javascript
   const DEFAULT_API_BASE = "https://phishguard-api.onrender.com";
   ```
2. In `extension/popup.js` (line 5), update:
   ```javascript
   const DEFAULT_API = "https://phishguard-api.onrender.com";
   ```
3. In `chrome://extensions/`, click the **Reload (↺)** icon on the PhishGuard extension card.

---

## ✅ Step 5: End-to-End Verification Checklist

Run these tests to confirm each component is working:

### 1. Test Backend Health Endpoint
Open in your browser or run in terminal:
```bash
curl -s https://phishguard-api.onrender.com/health | jq .
```
Expected response:
```json
{
  "status": "healthy",
  "model_loaded": true,
  "scaler_loaded": true,
  "features_count": 16,
  "environment": "production"
}
```

### 2. Test Interactive Swagger API Docs
Open in your browser:
```
https://phishguard-api.onrender.com/docs
```
- Expand `POST /predict`
- Click **Try it out**
- Enter payload:
  ```json
  {"url": "https://secure-login-paypal.com.account-update.xyz/signin"}
  ```
- Click **Execute** and verify `risk_score`, `verdict: "phishing"`, and `threat_intel` fields.

### 3. Test Streamlit Web Dashboard
- Navigate to your Streamlit app URL (`https://<your-app>.streamlit.app`).
- In the **Single URL Scan** tab, test:
  - Legitimate URL: `https://www.wikipedia.org` → Verdict: **SAFE** (Green gauge)
  - Phishing URL: `http://login.apple.id.security-verify.com/login.php` → Verdict: **PHISHING** (Red gauge)
- Verify the **Feature Radar Chart** renders properly.
- Switch to the **Batch URL Scanner** tab and test multiple URLs at once.

### 4. Test Chrome Extension
- Open a safe website (e.g. `https://news.ycombinator.com`).
- Click the PhishGuard extension icon:
  - Active Tab URL should display with **SAFE** badge.
- Open a simulated suspicious URL in manual scan or browser tab.
- If a phishing threat is detected:
  - The extension badge turns **RED** with `WARN`.
  - The in-page warning banner displays with the bypass link: *"I understand the risks — proceed anyway"*.

---

## 💡 Troubleshooting & Free Tier Notes

### Render Free Tier "Cold Starts"
- **Spin-down Behavior:** Render's free tier spins down web services after 15 minutes of inactivity.
- **Waking Up:** The first request after sleep may take **30–50 seconds** to wake up the server.
- **What to Expect:** In Streamlit or the Chrome extension, if the backend was sleeping, the first request might briefly show a timeout or connecting status while the container boots. Subsequent requests will be fast (< 200ms).
- **Tip (Keep-Alive):** You can set up a free uptime monitor like [UptimeRobot](https://uptimerobot.com) to ping `https://phishguard-api.onrender.com/health` every 10 minutes to keep the service warm.

### Streamlit Community Cloud Limits
- Free tier apps get 1GB of RAM, which is more than enough since the heavy ML inference runs on your Render backend.
- If secrets are modified, Streamlit Cloud reboots the app automatically.

### CORS Errors
- If the Streamlit dashboard or extension reports `CORS error` or `Network Error`, verify the `ALLOWED_ORIGINS` environment variable in your Render dashboard:
  - Set to `*` for testing, or include your exact Streamlit URL: `https://<your-app>.streamlit.app`.
