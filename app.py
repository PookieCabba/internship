"""
============================================================
app.py — Streamlit Frontend Dashboard
============================================================
A sleek, cybersecurity-themed dashboard for interacting with
the Phishing URL Detection API.

Features:
  • Single URL analysis with detailed risk breakdown
  • Batch URL scanning (paste multiple URLs)
  • Feature radar chart visualization
  • Real-time risk scoring with animated gauges
  • Warning breakdown with severity indicators
  • Model information panel

Usage:
    streamlit run app.py

Make sure the FastAPI backend is running:
    uvicorn api:app --host 0.0.0.0 --port 8000

Author:  Senior AI & Cybersecurity Engineer
Version: 1.0.0
============================================================
"""

# pyrefly: ignore[missing-import]
import streamlit as st
import requests
import json
import time
# pyrefly: ignore[missing-import]
import plotly.graph_objects as go
from typing import Dict, Optional

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────
API_BASE_URL = "http://localhost:8000"
PREDICT_URL = f"{API_BASE_URL}/predict"
BATCH_URL = f"{API_BASE_URL}/predict/batch"
HEALTH_URL = f"{API_BASE_URL}/health"
MODEL_INFO_URL = f"{API_BASE_URL}/model/info"


# ──────────────────────────────────────────────────────────────
# Page configuration & custom styling
# ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard AI — URL Threat Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject custom CSS for a premium dark cybersecurity theme
st.markdown("""
<style>
    /* ── Import Google Fonts ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* ── Global Styles ── */
    .stApp {
        font-family: 'Inter', sans-serif;
    }

    /* ── Hero Header ── */
    .hero-header {
        text-align: center;
        padding: 2rem 0 1rem;
        margin-bottom: 1rem;
    }
    .hero-header h1 {
        font-family: 'Inter', sans-serif;
        font-weight: 800;
        font-size: 2.8rem;
        background: linear-gradient(135deg, #00F0FF, #7B61FF, #FF3CAC);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.3rem;
        letter-spacing: -0.03em;
    }
    .hero-subtitle {
        font-size: 1.1rem;
        color: #8892B0;
        font-weight: 300;
        letter-spacing: 0.02em;
    }

    /* ── Risk Cards ── */
    .risk-card {
        border-radius: 16px;
        padding: 1.8rem;
        margin: 1rem 0;
        text-align: center;
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255,255,255,0.08);
        transition: transform 0.2s ease;
    }
    .risk-card:hover {
        transform: translateY(-2px);
    }
    .risk-safe {
        background: linear-gradient(135deg, rgba(0,200,120,0.15), rgba(0,200,120,0.05));
        border-color: rgba(0,200,120,0.3);
    }
    .risk-low {
        background: linear-gradient(135deg, rgba(255,200,0,0.15), rgba(255,200,0,0.05));
        border-color: rgba(255,200,0,0.3);
    }
    .risk-medium {
        background: linear-gradient(135deg, rgba(255,150,0,0.15), rgba(255,150,0,0.05));
        border-color: rgba(255,150,0,0.3);
    }
    .risk-high {
        background: linear-gradient(135deg, rgba(255,60,60,0.15), rgba(255,60,60,0.05));
        border-color: rgba(255,60,60,0.3);
    }
    .risk-critical {
        background: linear-gradient(135deg, rgba(200,0,50,0.2), rgba(200,0,50,0.05));
        border-color: rgba(200,0,50,0.4);
        animation: pulse-border 2s ease-in-out infinite;
    }

    @keyframes pulse-border {
        0%, 100% { border-color: rgba(200,0,50,0.4); }
        50% { border-color: rgba(255,0,60,0.8); }
    }

    .risk-label {
        font-size: 1.1rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-bottom: 0.5rem;
    }
    .risk-score {
        font-family: 'JetBrains Mono', monospace;
        font-size: 3.2rem;
        font-weight: 700;
        line-height: 1;
        margin: 0.5rem 0;
    }
    .risk-description {
        font-size: 0.9rem;
        color: #8892B0;
        margin-top: 0.5rem;
    }

    /* ── Stat Boxes ── */
    .stat-box {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 1.2rem;
        text-align: center;
    }
    .stat-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.6rem;
        font-weight: 700;
        color: #E6F1FF;
    }
    .stat-label {
        font-size: 0.8rem;
        color: #8892B0;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 0.3rem;
    }

    /* ── Warning Cards ── */
    .warning-card {
        background: rgba(255,255,255,0.03);
        border-left: 4px solid;
        border-radius: 0 12px 12px 0;
        padding: 1rem 1.2rem;
        margin: 0.5rem 0;
    }
    .warning-red { border-left-color: #FF3333; }
    .warning-orange { border-left-color: #FF9500; }
    .warning-yellow { border-left-color: #FFCC00; }

    /* ── URL Input ── */
    .stTextInput > div > div > input {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.95rem;
    }

    /* ── Footer ── */
    .footer {
        text-align: center;
        color: #4A5568;
        font-size: 0.8rem;
        padding: 2rem 0 1rem;
        border-top: 1px solid rgba(255,255,255,0.05);
        margin-top: 3rem;
    }

    /* ── Sidebar styling ── */
    [data-testid="stSidebar"] {
        background: rgba(10,15,30,0.95);
    }
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────

def check_api_health() -> Optional[Dict]:
    """Check if the FastAPI backend is running and healthy."""
    try:
        response = requests.get(HEALTH_URL, timeout=5)
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.ConnectionError:
        return None
    except Exception:
        return None
    return None


def predict_url(url: str) -> Optional[Dict]:
    """Send a URL to the prediction API and return the result."""
    try:
        response = requests.post(
            PREDICT_URL,
            json={"url": url},
            timeout=30,
        )
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"API returned status {response.status_code}: {response.text}")
            return None
    except requests.exceptions.ConnectionError:
        st.error(
            "❌ Cannot connect to the API server. "
            "Make sure it's running: `uvicorn api:app --port 8000`"
        )
        return None
    except Exception as e:
        st.error(f"❌ Request failed: {e}")
        return None


def get_risk_color(risk_level: str) -> str:
    """Map risk level to its theme color."""
    colors = {
        "Safe": "#00C878",
        "Low Risk": "#FFCC00",
        "Medium Risk": "#FF9500",
        "High Risk": "#FF3333",
        "Critical": "#CC0033",
    }
    return colors.get(risk_level, "#8892B0")


def get_risk_emoji(risk_level: str) -> str:
    """Map risk level to an emoji."""
    emojis = {
        "Safe": "✅",
        "Low Risk": "⚠️",
        "Medium Risk": "🟠",
        "High Risk": "🔴",
        "Critical": "🚨",
    }
    return emojis.get(risk_level, "❓")


def get_risk_css_class(risk_level: str) -> str:
    """Map risk level to its CSS class."""
    classes = {
        "Safe": "risk-safe",
        "Low Risk": "risk-low",
        "Medium Risk": "risk-medium",
        "High Risk": "risk-high",
        "Critical": "risk-critical",
    }
    return classes.get(risk_level, "risk-safe")


def create_gauge_chart(probability: float, risk_level: str) -> go.Figure:
    """Create an animated semicircular gauge chart for the risk score."""
    color = get_risk_color(risk_level)

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=probability * 100,
        number={
            "suffix": "%",
            "font": {"size": 42, "family": "JetBrains Mono", "color": "#E6F1FF"},
        },
        gauge={
            "axis": {
                "range": [0, 100],
                "tickwidth": 1,
                "tickcolor": "#2D3748",
                "dtick": 20,
                "tickfont": {"color": "#8892B0", "size": 10},
            },
            "bar": {"color": color, "thickness": 0.3},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 20], "color": "rgba(0,200,120,0.1)"},
                {"range": [20, 40], "color": "rgba(255,200,0,0.1)"},
                {"range": [40, 60], "color": "rgba(255,150,0,0.1)"},
                {"range": [60, 80], "color": "rgba(255,60,60,0.1)"},
                {"range": [80, 100], "color": "rgba(200,0,50,0.15)"},
            ],
            "threshold": {
                "line": {"color": "#FF3CAC", "width": 3},
                "thickness": 0.8,
                "value": probability * 100,
            },
        },
    ))

    fig.update_layout(
        height=280,
        margin=dict(l=30, r=30, t=40, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#E6F1FF"},
    )

    return fig


def create_feature_radar(features: Dict) -> go.Figure:
    """Create a radar chart showing key feature values."""
    # Select the most interpretable features for the radar
    radar_features = {
        "URL Length": min(features.get("url_length", 0) / 200, 1.0),
        "Digits": min(features.get("digit_ratio", 0) * 3, 1.0),
        "Special Chars": min(
            (features.get("num_at_signs", 0) + features.get("num_percent", 0) +
             features.get("num_exclamation", 0)) / 5, 1.0
        ),
        "Domain Entropy": min(features.get("domain_entropy", 0) / 5, 1.0),
        "Subdomains": min(features.get("num_subdomains", 0) / 5, 1.0),
        "Params": min(features.get("num_params", 0) / 8, 1.0),
        "Path Length": min(features.get("path_length", 0) / 100, 1.0),
        "Dots": min(features.get("num_dots", 0) / 8, 1.0),
    }

    categories = list(radar_features.keys())
    values = list(radar_features.values())
    # Close the polygon
    values.append(values[0])
    categories.append(categories[0])

    fig = go.Figure()

    # Fill area
    fig.add_trace(go.Scatterpolar(
        r=values,
        theta=categories,
        fill="toself",
        fillcolor="rgba(123, 97, 255, 0.15)",
        line=dict(color="#7B61FF", width=2),
        name="Feature Profile",
    ))

    fig.update_layout(
        polar=dict(
            bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(
                visible=True,
                range=[0, 1],
                gridcolor="rgba(255,255,255,0.08)",
                tickfont=dict(size=9, color="#8892B0"),
            ),
            angularaxis=dict(
                gridcolor="rgba(255,255,255,0.08)",
                tickfont=dict(size=11, color="#CCD6F6"),
            ),
        ),
        showlegend=False,
        height=350,
        margin=dict(l=60, r=60, t=40, b=40),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )

    return fig


# ──────────────────────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ PhishGuard AI")
    st.markdown("---")

    # API connection status
    health = check_api_health()
    if health and health.get("status") == "healthy":
        st.success("🟢 API Connected")
        st.caption(f"Model v{health.get('model_version', '?')}")
        st.caption(f"Predictions: {health.get('total_predictions', 0)}")
    else:
        st.error("🔴 API Offline")
        st.caption(
            "Start the API server:\n"
            "```\nuvicorn api:app --port 8000\n```"
        )

    st.markdown("---")

    # Scan mode selector
    scan_mode = st.radio(
        "Scan Mode",
        ["🔍 Single URL", "📋 Batch Scan"],
        help="Choose between scanning a single URL or multiple URLs at once.",
    )

    st.markdown("---")

    # Quick test URLs
    st.markdown("### 🧪 Test URLs")
    st.caption("Click to auto-fill:")

    test_urls = {
        "✅ Google": "https://www.google.com/search?q=test",
        "✅ GitHub": "https://github.com/features",
        "🔴 IP Phish": "http://192.168.1.100/login/verify",
        "🔴 Fake Bank": "http://secure-login-verify.xyz/account",
        "🔴 @ Redirect": "http://google.com@evil-site.tk/phish",
    }

    for label, url in test_urls.items():
        if st.button(label, key=f"test_{label}", use_container_width=True):
            st.session_state["test_url"] = url

    st.markdown("---")

    # Model info expander
    with st.expander("📊 Model Details"):
        try:
            info_resp = requests.get(MODEL_INFO_URL, timeout=5)
            if info_resp.status_code == 200:
                info = info_resp.json()
                st.json(info.get("metrics", {}))
                st.caption(f"Algorithm: {info.get('algorithm', 'N/A')}")
                st.caption(f"Features: {info.get('num_features', 'N/A')}")
            else:
                st.caption("Could not load model info.")
        except Exception:
            st.caption("API not available.")


# ──────────────────────────────────────────────────────────────
# Main content
# ──────────────────────────────────────────────────────────────

# Hero header
st.markdown("""
<div class="hero-header">
    <h1>🛡️ PhishGuard AI</h1>
    <p class="hero-subtitle">
        Advanced URL Threat Detection powered by Machine Learning
    </p>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Single URL Scan Mode
# ─────────────────────────────────────────────
if scan_mode == "🔍 Single URL":

    # URL input
    default_url = st.session_state.get("test_url", "")
    url_input = st.text_input(
        "🔗 Enter a URL to scan",
        value=default_url,
        placeholder="https://suspicious-website.xyz/login?id=12345",
        help="Paste any URL to analyze it for phishing indicators.",
    )

    # Clear the test URL from session state after use
    if "test_url" in st.session_state:
        del st.session_state["test_url"]

    # Scan button
    col_btn, col_spacer = st.columns([1, 3])
    with col_btn:
        scan_clicked = st.button(
            "🔬 Scan URL",
            type="primary",
            use_container_width=True,
        )

    if scan_clicked and url_input:
        with st.spinner("Analyzing URL..."):
            result = predict_url(url_input)

        if result:
            risk_level = result["risk_level"]
            probability = result["phishing_probability"]
            confidence = result["confidence"]
            risk_color = get_risk_color(risk_level)
            risk_emoji = get_risk_emoji(risk_level)
            risk_class = get_risk_css_class(risk_level)

            # ── Results Header ──
            st.markdown("---")

            # ── Top row: Gauge + Risk Card + Stats ──
            col1, col2, col3 = st.columns([1.2, 1, 1])

            with col1:
                st.markdown("##### 🎯 Threat Score")
                gauge = create_gauge_chart(probability, risk_level)
                st.plotly_chart(gauge, use_container_width=True)

            with col2:
                st.markdown("##### 📊 Verdict")
                risk_description = {
                    "Safe": "This URL appears to be legitimate.",
                    "Low Risk": "Minor suspicious signals detected.",
                    "Medium Risk": "Several risk indicators found. Proceed with caution.",
                    "High Risk": "Strong phishing indicators detected. Likely malicious.",
                    "Critical": "Extremely high threat level. Almost certainly a phishing URL.",
                }
                st.markdown(f"""
                <div class="risk-card {risk_class}">
                    <div class="risk-label" style="color: {risk_color};">
                        {risk_emoji} {risk_level}
                    </div>
                    <div class="risk-score" style="color: {risk_color};">
                        {probability*100:.1f}%
                    </div>
                    <div class="risk-description">
                        {risk_description.get(risk_level, '')}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with col3:
                st.markdown("##### ⚡ Stats")
                st.markdown(f"""
                <div class="stat-box" style="margin-bottom: 0.8rem;">
                    <div class="stat-value">{confidence*100:.1f}%</div>
                    <div class="stat-label">Model Confidence</div>
                </div>
                """, unsafe_allow_html=True)
                st.markdown(f"""
                <div class="stat-box" style="margin-bottom: 0.8rem;">
                    <div class="stat-value">{result['inference_time_ms']:.0f}ms</div>
                    <div class="stat-label">Inference Time</div>
                </div>
                """, unsafe_allow_html=True)
                st.markdown(f"""
                <div class="stat-box">
                    <div class="stat-value">{len(result.get('warnings', []))}</div>
                    <div class="stat-label">Warnings</div>
                </div>
                """, unsafe_allow_html=True)

            # ── Warnings Section ──
            warnings = result.get("warnings", [])
            if warnings:
                st.markdown("---")
                st.markdown("### ⚠️ Risk Indicators")
                for warning in warnings:
                    # Determine severity color from emoji
                    if "🔴" in warning:
                        css_class = "warning-red"
                    elif "🟠" in warning:
                        css_class = "warning-orange"
                    else:
                        css_class = "warning-yellow"

                    st.markdown(
                        f'<div class="warning-card {css_class}">{warning}</div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown("---")
                st.success("✅ No specific risk indicators were flagged.")

            # ── Feature Analysis ──
            st.markdown("---")
            col_radar, col_features = st.columns([1, 1])

            with col_radar:
                st.markdown("### 📡 Feature Profile")
                features = result.get("features", {})
                radar = create_feature_radar(features)
                st.plotly_chart(radar, use_container_width=True)

            with col_features:
                st.markdown("### 🔢 Extracted Features")
                features = result.get("features", {})
                # Format features into a nice table
                feature_data = []
                for name, value in features.items():
                    # Format display
                    display_name = name.replace("_", " ").title()
                    if isinstance(value, float):
                        display_value = f"{value:.4f}" if value < 1 else f"{value:.2f}"
                    else:
                        display_value = str(value)
                    feature_data.append({
                        "Feature": display_name,
                        "Value": display_value,
                    })
                st.dataframe(
                    feature_data,
                    use_container_width=True,
                    height=400,
                    hide_index=True,
                )

    elif scan_clicked and not url_input:
        st.warning("Please enter a URL to scan.")


# ─────────────────────────────────────────────
# Batch Scan Mode
# ─────────────────────────────────────────────
elif scan_mode == "📋 Batch Scan":

    st.markdown("### 📋 Batch URL Scanner")
    st.caption("Paste one URL per line (max 100 URLs).")

    urls_text = st.text_area(
        "URLs to scan",
        height=200,
        placeholder=(
            "https://google.com\n"
            "http://192.168.1.1/login\n"
            "http://secure-verify-account.xyz/auth"
        ),
    )

    if st.button("🔬 Scan All URLs", type="primary"):
        if urls_text.strip():
            urls = [u.strip() for u in urls_text.strip().split("\n") if u.strip()]

            if len(urls) > 100:
                st.warning("Maximum 100 URLs allowed. Truncating to 100.")
                urls = urls[:100]

            with st.spinner(f"Scanning {len(urls)} URLs..."):
                try:
                    response = requests.post(
                        BATCH_URL,
                        json={"urls": urls},
                        timeout=120,
                    )
                    if response.status_code == 200:
                        batch_result = response.json()
                    else:
                        st.error(f"API error: {response.status_code}")
                        batch_result = None
                except requests.exceptions.ConnectionError:
                    st.error("Cannot connect to API. Is it running?")
                    batch_result = None
                except Exception as e:
                    st.error(f"Error: {e}")
                    batch_result = None

            if batch_result:
                predictions = batch_result["predictions"]

                # Summary stats
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total URLs", batch_result["total_urls"])
                with col2:
                    st.metric(
                        "🟢 Legitimate",
                        batch_result["total_legitimate"],
                    )
                with col3:
                    st.metric(
                        "🔴 Phishing",
                        batch_result["total_phishing"],
                    )
                with col4:
                    if batch_result["total_urls"] > 0:
                        threat_pct = (
                            batch_result["total_phishing"]
                            / batch_result["total_urls"] * 100
                        )
                    else:
                        threat_pct = 0
                    st.metric("Threat Rate", f"{threat_pct:.1f}%")

                st.markdown("---")

                # Results table
                table_data = []
                for pred in predictions:
                    emoji = get_risk_emoji(pred["risk_level"])
                    table_data.append({
                        "Status": emoji,
                        "URL": pred["url"][:80] + ("..." if len(pred["url"]) > 80 else ""),
                        "Risk": pred["risk_level"],
                        "Probability": f"{pred['phishing_probability']*100:.1f}%",
                        "Warnings": len(pred.get("warnings", [])),
                    })

                st.dataframe(
                    table_data,
                    use_container_width=True,
                    hide_index=True,
                )

                # Distribution chart
                risk_counts = {}
                for pred in predictions:
                    rl = pred["risk_level"]
                    risk_counts[rl] = risk_counts.get(rl, 0) + 1

                if risk_counts:
                    fig = go.Figure(go.Bar(
                        x=list(risk_counts.keys()),
                        y=list(risk_counts.values()),
                        marker_color=[
                            get_risk_color(r) for r in risk_counts.keys()
                        ],
                        text=list(risk_counts.values()),
                        textposition="auto",
                    ))
                    fig.update_layout(
                        title="Risk Level Distribution",
                        xaxis_title="Risk Level",
                        yaxis_title="Count",
                        height=350,
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#CCD6F6"),
                        xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                        yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                    )
                    st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("Please paste at least one URL.")


# ──────────────────────────────────────────────────────────────
# Footer
# ──────────────────────────────────────────────────────────────
st.markdown("""
<div class="footer">
    <p>
        🛡️ <strong>PhishGuard AI</strong> v1.0.0 —
        Built with XGBoost, FastAPI, and Streamlit<br>
        <em>This tool is for educational and research purposes.
        Always verify results with additional security tools.</em>
    </p>
</div>
""", unsafe_allow_html=True)
