# 🚀 Deployment Guide: PhishGuard AI Backend API

This guide provides step-by-step instructions for deploying the FastAPI machine-learning backend so that your Chrome extension and web clients can access it globally over HTTPS.

---

## ⚡ Option 1: Instant Free Cloud Deploy on Render.com (Recommended)

Render offers free hosting with automated SSL certificates (`https://...`):

1. **Push your code to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Deploy PhishGuard AI Pipeline & Extension"
   git branch -M main
   git remote add origin https://github.com/<your-username>/phishguard-ai.git
   git push -u origin main
   ```

2. **Deploy on Render**:
   - Go to [dashboard.render.com](https://dashboard.render.com) and log in.
   - Click **New +** → **Blueprint**.
   - Connect your GitHub repository.
   - Render will automatically detect the [`render.yaml`](file:///Users/ujjwalsingh/Desktop/internship/render.yaml) file and provision your service.
   - Click **Apply**.

3. **Get your live URL**:
   - Once the build succeeds, Render assigns a public URL like:
     `https://phishguard-api.onrender.com`
   - Test it in your browser: `https://phishguard-api.onrender.com/health`
   - Paste this URL into your Chrome extension settings!

---

## ⚡ Option 2: 1-Click Deploy on Railway.app

1. Go to [railway.app](https://railway.app) and sign in with GitHub.
2. Click **New Project** → **Deploy from GitHub repo**.
3. Select your repository. Railway uses the included [`Procfile`](file:///Users/ujjwalsingh/Desktop/internship/Procfile) and [`Dockerfile`](file:///Users/ujjwalsingh/Desktop/internship/Dockerfile).
4. In Settings → **Networking**, click **Generate Domain**.
5. Your service is now live on `https://...up.railway.app`.

---

## ⚡ Option 3: Instant Public HTTPS Tunnel (Zero Signup / Zero Setup)

If you want to test the extension with a public HTTPS link **immediately** without waiting for cloud builds:

### Using Cloudflare Tunnels (Free & No Account Needed):
```bash
# In your terminal, run:
npx untun@latest tunnel http://localhost:8000
```
This gives you an instant public HTTPS URL (e.g. `https://random-words.localtunnel.me` or `https://...trycloudflare.com`) that routes directly to your local FastAPI server.

---

## ⚡ Option 4: Docker & Docker Compose (Self-Hosted VPS / Cloud VM)

To deploy both the API and Streamlit Dashboard on an AWS EC2, DigitalOcean Droplet, or local server:

```bash
docker compose up -d --build
```

- **API**: `http://<your-server-ip>:8000`
- **Dashboard**: `http://<your-server-ip>:8501`
- **Swagger Docs**: `http://<your-server-ip>:8000/docs`

---

## 🔒 Chrome Extension Integration

Once your backend is deployed:
1. Open the **PhishGuard AI** extension popup in your browser.
2. Click the **⚙️ Settings** icon.
3. In **API Endpoint URL**, enter your public HTTPS URL:
   ```
   https://phishguard-api.onrender.com
   ```
4. Click **Test** to ensure connection and low latency.
5. Click **Save Preferences**.
