# 🛡️ PhishGuard AI — Intelligent Phishing URL Detection & Browser Shield

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.3%2B-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Chrome Extension](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)

An end-to-end Machine Learning cybersecurity pipeline that inspects, extracts lexical features, classifies malicious URLs, and actively defends users in real time via a **Chrome Extension (Manifest V3)**, an **interactive Streamlit Dashboard**, and a **high-throughput FastAPI REST service**.

---

## 📌 Table of Contents

- [About the Project](#-about-the-project)
- [System Architecture](#-system-architecture)
- [Key Features](#-key-features)
- [Lexical Features & Detection Signals](#-lexical-features--detection-signals)
- [Project Directory Structure](#-project-directory-structure)
- [Installation & Quickstart](#-installation--quickstart)
- [How to Use](#-how-to-use)
  - [1. Running the FastAPI Backend](#1-running-the-fastapi-backend)
  - [2. Running the Streamlit Security Dashboard](#2-running-the-streamlit-security-dashboard)
  - [3. Loading the Chrome Extension](#3-loading-the-chrome-extension)
  - [4. Docker & Docker Compose](#4-docker--docker-compose)
- [API Documentation & Usage](#-api-documentation--usage)
- [Model Training & Retraining](#-model-training--retraining)
- [Cloud Deployment](#-cloud-deployment)
- [License](#-license)

---

## 📖 About the Project

Phishing remains the #1 initial access vector in cyber attacks, accounting for over **3.4 billion malicious emails sent daily** and billions of dollars in enterprise losses. Threat actors routinely evade traditional signature-based blocklists by generating dynamic, short-lived URLs, typosquatting domains, and weaponizing URL-shorteners.

**PhishGuard AI** addresses this problem using **lexical and structural heuristic analysis coupled with Machine Learning**. Rather than relying purely on static domain blocklists:
1. It analyzes **27 lexical, entropy, and structural signals** directly from the URL string in under 20 milliseconds.
2. An ensemble **Random Forest / XGBoost classifier** computes the mathematical probability of malicious intent.
3. The results are served via a **real-time REST API**, an **interactive SOC analyst dashboard**, and a **Chrome Extension** that protects end-users as they browse.

---

## 🏛️ System Architecture

```
                          ┌────────────────────────┐
                          │   Incoming Web URL     │
                          └───────────┬────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │   Feature Extraction      │
                        │   (features.py - 27 feats)│
                        │   • Shannon Entropy       │
                        │   • Raw IP Detection      │
                        │   • Subdomain / TLD checks│
                        │   • Token & Lexical Ratios│
                        └─────────────┬─────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Trained AI Model (Random  │
                        │ Forest / XGBoost + Scaler)│
                        └─────────────┬─────────────┘
                                      │
                  ┌───────────────────┴───────────────────┐
                  ▼                                       ▼
       ┌─────────────────────┐                 ┌─────────────────────┐
       │   FastAPI Service   │                 │ Streamlit Dashboard │
       │   (Port 8000)       │                 │ (Port 8501)         │
       │   • /predict        │                 │ • Real-time Scanner │
       │   • /predict/batch  │                 │ • Batch CSV Upload  │
       │   • /health         │                 │ • Feature Analytics │
       └──────────┬──────────┘                 └─────────────────────┘
                  │
                  ▼
       ┌─────────────────────────────────────┐
       │     Chrome Extension (Manifest V3)  │
       │     • Real-time tab auto-scan       │
       │     • Threat badge indicator        │
       │     • In-page phishing alert banner │
       │     • Manual email link inspector   │
       └─────────────────────────────────────┘
```

---

## ✨ Key Features

- **⚡ 27 Lexical Real-Time Features**: Shannon domain entropy, path entropy, IP detection, suspicious TLD flagging, token length distributions, and special character ratios.
- **🎯 Calibrated Risk Engine**: Probabilities are categorized into standard SOC risk tiers:
  - 🟢 **Safe** (`0.0% – 19.9%`)
  - 🔵 **Low Risk** (`20.0% – 39.9%`)
  - 🟡 **Medium Risk** (`40.0% – 59.9%`)
  - 🟠 **High Risk** (`60.0% – 79.9%`)
  - 🔴 **Critical Threat** (`80.0% – 100.0%`)
- **🚀 High-Speed FastAPI Backend**: Asynchronous endpoints supporting single and batch inference with sub-30ms latency.
- **🖥️ SOC Analyst Streamlit Dashboard**: Interactive UI featuring gauge meters, radar telemetry, batch CSV scanner with exportable reports, confusion matrix, ROC-AUC curve, and feature importance explorer.
- **🛡️ Chrome Extension (Manifest V3)**:
  - Automatically assesses active tabs upon navigation.
  - Updates browser action badges in real time (🟢 **✓**, 🟡 **⚠**, 🔴 **!**).
  - Injects a high-visibility warning modal on verified malicious domains with a *"Take Me to Safety"* escape button.
  - Includes a manual link inspector to test suspicious links before opening them.
  - Allows switching between local (`http://localhost:8000`) and cloud-hosted backends with a built-in latency tester.
- **🐳 Cloud & Container Ready**: Includes `Dockerfile`, `docker-compose.yml`, `render.yaml`, and `Procfile`.

---

## 🔬 Lexical Features & Detection Signals

The feature extraction engine ([`features.py`](features.py)) extracts 27 features without making external network calls:

| Feature Category | Features Extracted | Threat Significance |
| :--- | :--- | :--- |
| **Entropy** | `domain_entropy`, `path_entropy` | Phishing kits use randomized strings, resulting in abnormally high Shannon entropy. |
| **Host Characteristics** | `has_ip_address`, `num_subdomains`, `domain_length` | Using raw IP addresses (e.g. `http://192.168.1.1/login`) or deep subdomain nesting (`login.paypal.com.account-verify.xyz`) indicates deceptive cloaking. |
| **Structural Lexicals** | `num_dots`, `num_hyphens`, `num_slashes`, `num_question_marks`, `num_equals`, `num_at_signs` | Excess delimiters indicate disguised query parameters and credential harvest tokens. |
| **Character Ratios** | `digit_ratio`, `num_digits`, `num_percent` | Malicious URLs often contain hex-encoded strings and ID parameters. |
| **Protocol & TLD** | `uses_https`, `has_suspicious_tld`, `has_double_slash_redir` | Free or high-abuse TLDs (`.xyz`, `.top`, `.tk`, `.buzz`, `.club`, etc.) and protocol spoofing. |
| **Token Statistics** | `longest_token_length`, `avg_token_length` | Identifies machine-generated or DGA (Domain Generation Algorithm) paths. |

---

## 📁 Project Directory Structure

```text
├── api.py                    # FastAPI REST API (Endpoints: /predict, /predict/batch, /health)
├── app.py                    # Streamlit SOC Analyst Web Application
├── features.py               # Shared feature extraction engine (27 features)
├── train_model.py            # Model training, scaling, evaluation, and serialization
├── generate_dataset.py       # Realistic synthetic dataset generator
├── requirements.txt          # Python project dependencies
├── Dockerfile                # Production container definition
├── docker-compose.yml        # Multi-container orchestration (API + Dashboard)
├── render.yaml               # Render.com 1-click cloud deployment blueprint
├── Procfile                  # Railway / Heroku deployment specification
├── DEPLOYMENT.md             # Comprehensive cloud deployment guide
├── models/
│   ├── phishing_model.joblib # Serialized Random Forest classifier
│   ├── feature_scaler.joblib # Serialized StandardScaler
│   └── model_metadata.json   # Model performance metrics & feature names
└── extension/                # Manifest V3 Chrome Extension
    ├── manifest.json         # Extension configuration & permissions
    ├── popup.html            # Extension popup user interface
    ├── popup.css             # Cyber dark-theme styling
    ├── popup.js              # Popup controller & API integration
    ├── background.js         # Service worker for active tab monitoring
    ├── content.js            # In-page security warning modal
    ├── content.css           # In-page alert styling
    ├── README.md             # Extension installation manual
    └── icons/                # High-res extension icons (16, 32, 48, 128px)
```

---

## 💻 Installation & Quickstart

### Prerequisites
- Python 3.10, 3.11, or 3.12
- Google Chrome, Brave, or Microsoft Edge (for the browser extension)

### Setup Virtual Environment & Install Dependencies

```bash
# 1. Clone repository
git clone https://github.com/PookieCabba/internship.git
cd internship

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 How to Use

### 1. Running the FastAPI Backend

Start the API server on `http://localhost:8000`:

```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

### 2. Running the Streamlit Security Dashboard

In a separate terminal (with the virtual environment activated), run:

```bash
streamlit run app.py --server.port 8501
```

Open your browser at **[http://localhost:8501](http://localhost:8501)**. You can:
1. Paste any URL to view real-time risk gauges and feature telemetry.
2. Upload a CSV file of URLs to perform batch triage.
3. Inspect model evaluation metrics (Confusion Matrix, ROC Curve, Feature Importance).

---

### 3. Loading the Chrome Extension

To protect your daily browsing in real time:

1. Open your browser and navigate to its extensions page:
  - Chrome: `chrome://extensions`
  - Brave: `brave://extensions`
  - Edge: `edge://extensions`
2. Turn on **Developer mode** using the toggle in the top-right corner.
3. Click **Load unpacked** in the top-left corner.
4. Select the project's `extension/` folder:
   ```text
  /Users/ujjwalsingh/Desktop/internship/extension
   ```
5. Click **Select Folder**. PhishGuard AI will be added to your browser.
6. Click the extensions puzzle icon in the browser toolbar, then pin **PhishGuard AI**.
  The extension will evaluate websites as you browse.

*(Optional)* You can also view the standalone extension popup in your browser by running:
```bash
python3 -m http.server 8080 --directory extension
```
And opening **[http://localhost:8080/popup.html](http://localhost:8080/popup.html)**.

---

### 4. Docker & Docker Compose

To spin up both the FastAPI backend and Streamlit dashboard with a single command:

```bash
docker compose up -d --build
```

- FastAPI API: `http://localhost:8000`
- Streamlit Dashboard: `http://localhost:8501`

To stop the containers:
```bash
docker compose down
```

---

## 📡 API Documentation & Usage

### 1. Classify a Single URL

**Endpoint:** `POST /predict`

```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.1/paypal/login/verify-account.php?token=123"}'
```

**Response:**
```json
{
  "url": "http://192.168.1.1/paypal/login/verify-account.php?token=123",
  "is_phishing": true,
  "phishing_probability": 0.644,
  "risk_level": "High Risk",
  "confidence": 0.644,
  "features": {
    "url_length": 60.0,
    "has_ip_address": 1.0,
    "domain_entropy": 2.2999,
    "path_entropy": 4.0778,
    "uses_https": 0.0,
    "num_dots": 4.0
  },
  "warnings": [
    "🔴 IP Address Detected — The URL contains a raw IP address instead of a domain name.",
    "🟠 No HTTPS — The URL does not use HTTPS encryption."
  ],
  "inference_time_ms": 34.2
}
```

---

### 2. Batch Classification

**Endpoint:** `POST /predict/batch`

```bash
curl -X POST http://localhost:8000/predict/batch \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://google.com",
      "http://verify-bank-security-login.xyz/update"
    ]
  }'
```

---

## 🧠 Model Training & Retraining

To generate a new dataset and retrain the classifier:

```bash
# 1. (Optional) Generate a fresh balanced synthetic dataset
python generate_dataset.py

# 2. Train the Random Forest model and export artifacts
python train_model.py
```

The training script automatically:
1. Extracts all 27 lexical features across the dataset.
2. Performs train-test splitting (80/20) with stratification.
3. Scales features with `StandardScaler`.
4. Trains the classifier and prints classification metrics (Accuracy, Precision, Recall, F1).
5. Exports serializations to `models/phishing_model.joblib` and `models/feature_scaler.joblib`.

---

## ☁️ Cloud Deployment

For detailed guides on deploying the API to **Render.com**, **Railway.app**, or cloud VMs with automated SSL certificates, refer to [**DEPLOYMENT.md**](DEPLOYMENT.md).

---

## 📄 License

This project is open-source and available under the **MIT License**.