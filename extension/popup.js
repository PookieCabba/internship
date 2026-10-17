/**
 * popup.js — Logic & Controller for PhishGuard AI Popup
 */

const DEFAULT_API = "http://localhost:8000";

// DOM Elements
const statusDot = document.querySelector(".status-dot");
const statusContainer = document.getElementById("api-status-indicator");
const currentUrlDisplay = document.getElementById("current-url-display");
const btnScanCurrent = document.getElementById("btn-scan-current");

const tabBtnCurrent = document.getElementById("tab-btn-current");
const tabBtnManual = document.getElementById("tab-btn-manual");
const manualContainer = document.getElementById("manual-input-container");
const manualInput = document.getElementById("manual-url-input");
const btnScanManual = document.getElementById("btn-scan-manual");

const loadingState = document.getElementById("loading-state");
const errorState = document.getElementById("error-state");
const errorMessage = document.getElementById("error-message");
const btnRetry = document.getElementById("btn-retry");

const resultsPanel = document.getElementById("results-panel");
const verdictIcon = document.getElementById("verdict-icon");
const verdictTitle = document.getElementById("verdict-title");
const verdictRisk = document.getElementById("verdict-risk");
const probPercentage = document.getElementById("prob-percentage");
const probBarFill = document.getElementById("prob-bar-fill");
const metricConfidence = document.getElementById("metric-confidence");
const metricLatency = document.getElementById("metric-latency");

const warningsBox = document.getElementById("warnings-box");
const warningsList = document.getElementById("warnings-list");

const btnToggleTelemetry = document.getElementById("btn-toggle-telemetry");
const telemetryContent = document.getElementById("telemetry-content");
const telemetryArrow = document.getElementById("telemetry-arrow");
const featuresGrid = document.getElementById("features-grid");

const historyPills = document.getElementById("history-pills");

// Settings Elements
const btnSettingsToggle = document.getElementById("btn-settings-toggle");
const btnCloseSettings = document.getElementById("btn-close-settings");
const settingsPanel = document.getElementById("settings-panel");
const inputApiUrl = document.getElementById("input-api-url");
const btnTestApi = document.getElementById("btn-test-api");
const apiTestResult = document.getElementById("api-test-result");
const toggleAutoscan = document.getElementById("toggle-autoscan");
const toggleBanner = document.getElementById("toggle-banner");
const btnSaveSettings = document.getElementById("btn-save-settings");

let activeTabUrl = "";

// ─────────────────────────────────────────────────────────────
// Initialization
// ─────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  await loadSettings();
  await checkApiHealth();
  await detectActiveTab();
  loadScanHistory();
  attachEvents();
});

// Load preferences from chrome.storage
async function loadSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["apiUrl", "autoScan", "showBannerOnPhish"], (res) => {
      inputApiUrl.value = res.apiUrl || DEFAULT_API;
      toggleAutoscan.checked = res.autoScan !== false;
      toggleBanner.checked = res.showBannerOnPhish !== false;
      resolve();
    });
  });
}

// Get API base URL
function getApiUrl() {
  return (inputApiUrl.value.trim() || DEFAULT_API).replace(/\/+$/, "");
}

// Check Backend Health
async function checkApiHealth() {
  statusDot.className = "status-dot";
  statusContainer.title = "Checking backend API...";

  try {
    const res = await fetch(`${getApiUrl()}/health`, { method: "GET" });
    if (res.ok) {
      statusDot.className = "status-dot online";
      statusContainer.title = "Backend API: Online & Operational";
      return true;
    } else {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch (err) {
    statusDot.className = "status-dot offline";
    statusContainer.title = `Backend API: Offline (${err.message})`;
    return false;
  }
}

// Detect Active Tab URL
async function detectActiveTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      activeTabUrl = tab.url;
      currentUrlDisplay.textContent = tab.url;
      currentUrlDisplay.title = tab.url;

      // Auto scan if valid http/https URL
      if (tab.url.startsWith("http")) {
        scanUrl(tab.url);
      } else {
        currentUrlDisplay.textContent = `${tab.url} (Internal Browser Page)`;
      }
    } else {
      currentUrlDisplay.textContent = "No active web page detected";
    }
  } catch (e) {
    currentUrlDisplay.textContent = "Unable to read active tab";
  }
}

// ─────────────────────────────────────────────────────────────
// URL Scanning & Inference
// ─────────────────────────────────────────────────────────────
async function scanUrl(url) {
  if (!url || !url.startsWith("http")) {
    showError("Please enter a valid web URL starting with http:// or https://");
    return;
  }

  showLoading();

  try {
    const response = await fetch(`${getApiUrl()}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Server returned HTTP ${response.status}`);
    }

    const data = await response.json();
    renderResults(data);
    saveToHistory(data);
  } catch (err) {
    showError(`Scan failed: ${err.message}. Ensure backend API is running at ${getApiUrl()}`);
  }
}

// ─────────────────────────────────────────────────────────────
// Render Prediction Results
// ─────────────────────────────────────────────────────────────
function renderResults(data) {
  hideLoading();
  hideError();
  resultsPanel.classList.remove("hidden");

  const probPct = (data.phishing_probability * 100).toFixed(1);
  probPercentage.textContent = `${probPct}%`;
  probBarFill.style.width = `${Math.min(100, Math.max(2, probPct))}%`;

  metricConfidence.textContent = `${(data.confidence * 100).toFixed(1)}%`;
  metricLatency.textContent = `${data.inference_time_ms ? data.inference_time_ms.toFixed(0) : "12"}ms`;

  // Risk Level styling
  const risk = data.risk_level;
  verdictRisk.textContent = risk.toUpperCase();
  verdictRisk.className = "verdict-risk-badge";

  if (data.is_phishing || risk === "Critical") {
    verdictIcon.textContent = "🚨";
    verdictTitle.textContent = "MALICIOUS PHISHING DETECTED";
    verdictRisk.classList.add("badge-critical");
    probBarFill.style.backgroundColor = "var(--accent-crimson)";
  } else if (risk === "High Risk") {
    verdictIcon.textContent = "⚠️";
    verdictTitle.textContent = "HIGH RISK URL DETECTED";
    verdictRisk.classList.add("badge-high");
    probBarFill.style.backgroundColor = "var(--accent-rose)";
  } else if (risk === "Medium Risk") {
    verdictIcon.textContent = "⚡";
    verdictTitle.textContent = "SUSPICIOUS CHARACTERISTICS";
    verdictRisk.classList.add("badge-medium");
    probBarFill.style.backgroundColor = "var(--accent-amber)";
  } else if (risk === "Low Risk") {
    verdictIcon.textContent = "🛡️";
    verdictTitle.textContent = "LOW RISK WEBSITE";
    verdictRisk.classList.add("badge-low");
    probBarFill.style.backgroundColor = "var(--accent-blue)";
  } else {
    verdictIcon.textContent = "✅";
    verdictTitle.textContent = "LEGITIMATE / SAFE WEBSITE";
    verdictRisk.classList.add("badge-safe");
    probBarFill.style.backgroundColor = "var(--accent-emerald)";
  }

  // Warnings
  if (data.warnings && data.warnings.length > 0) {
    warningsBox.classList.remove("hidden");
    warningsList.innerHTML = data.warnings
      .map((w) => `<li>${escapeHtml(w)}</li>`)
      .join("");
  } else {
    warningsBox.classList.add("hidden");
  }

  // Features Telemetry
  if (data.features) {
    featuresGrid.innerHTML = "";
    Object.entries(data.features).forEach(([key, val]) => {
      const pill = document.createElement("div");
      pill.className = "feature-pill";
      const displayVal = typeof val === "number" ? (Number.isInteger(val) ? val : val.toFixed(3)) : val;
      pill.innerHTML = `
        <span class="name" title="${key}">${formatFeatureName(key)}</span>
        <span class="val">${displayVal}</span>
      `;
      featuresGrid.appendChild(pill);
    });
  }
}

function formatFeatureName(name) {
  return name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// ─────────────────────────────────────────────────────────────
// History Management
// ─────────────────────────────────────────────────────────────
function saveToHistory(data) {
  chrome.storage.local.get(["scanHistory"], (res) => {
    let history = res.scanHistory || [];
    // remove existing entry with same url
    history = history.filter((h) => h.url !== data.url);
    history.unshift({
      url: data.url,
      risk_level: data.risk_level,
      is_phishing: data.is_phishing,
      probability: data.phishing_probability,
      timestamp: Date.now(),
    });
    // keep only top 5
    history = history.slice(0, 5);
    chrome.storage.local.set({ scanHistory: history });
    renderHistory(history);
  });
}

function loadScanHistory() {
  chrome.storage.local.get(["scanHistory"], (res) => {
    renderHistory(res.scanHistory || []);
  });
}

function renderHistory(items) {
  if (!items || items.length === 0) {
    historyPills.innerHTML = '<span class="no-history">No recent scans recorded</span>';
    return;
  }

  historyPills.innerHTML = "";
  items.forEach((item) => {
    const el = document.createElement("div");
    el.className = "history-item";

    const badgeClass = item.is_phishing ? "badge-critical" : (item.risk_level === "Safe" ? "badge-safe" : "badge-medium");

    el.innerHTML = `
      <span class="history-url" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</span>
      <span class="history-badge ${badgeClass}">${escapeHtml(item.risk_level)}</span>
    `;

    el.addEventListener("click", () => {
      manualInput.value = item.url;
      switchToManualMode();
      scanUrl(item.url);
    });

    historyPills.appendChild(el);
  });
}

// ─────────────────────────────────────────────────────────────
// UI State Helpers
// ─────────────────────────────────────────────────────────────
function showLoading() {
  loadingState.classList.remove("hidden");
  errorState.classList.add("hidden");
  resultsPanel.classList.add("hidden");
}

function hideLoading() {
  loadingState.classList.add("hidden");
}

function showError(msg) {
  hideLoading();
  resultsPanel.classList.add("hidden");
  errorState.classList.remove("hidden");
  errorMessage.textContent = msg;
}

function hideError() {
  errorState.classList.add("hidden");
}

function switchToManualMode() {
  tabBtnManual.classList.add("active");
  tabBtnCurrent.classList.remove("active");
  manualContainer.classList.remove("hidden");
  btnScanCurrent.classList.add("hidden");
}

function switchToCurrentMode() {
  tabBtnCurrent.classList.add("active");
  tabBtnManual.classList.remove("active");
  manualContainer.classList.add("hidden");
  btnScanCurrent.classList.remove("hidden");
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ─────────────────────────────────────────────────────────────
// Event Listeners
// ─────────────────────────────────────────────────────────────
function attachEvents() {
  // Mode Tabs
  tabBtnCurrent.addEventListener("click", () => {
    switchToCurrentMode();
    if (activeTabUrl) scanUrl(activeTabUrl);
  });

  tabBtnManual.addEventListener("click", () => {
    switchToManualMode();
    manualInput.focus();
  });

  // Buttons
  btnScanCurrent.addEventListener("click", () => {
    if (activeTabUrl) scanUrl(activeTabUrl);
    else detectActiveTab();
  });

  btnScanManual.addEventListener("click", () => {
    const url = manualInput.value.trim();
    if (url) scanUrl(url);
  });

  manualInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      const url = manualInput.value.trim();
      if (url) scanUrl(url);
    }
  });

  btnRetry.addEventListener("click", () => {
    checkApiHealth();
    if (activeTabUrl) scanUrl(activeTabUrl);
  });

  // Telemetry Accordion
  btnToggleTelemetry.addEventListener("click", () => {
    const isHidden = telemetryContent.classList.contains("hidden");
    if (isHidden) {
      telemetryContent.classList.remove("hidden");
      telemetryArrow.textContent = "▲";
    } else {
      telemetryContent.classList.add("hidden");
      telemetryArrow.textContent = "▼";
    }
  });

  // Settings Panel
  btnSettingsToggle.addEventListener("click", () => {
    settingsPanel.classList.toggle("hidden");
  });

  btnCloseSettings.addEventListener("click", () => {
    settingsPanel.classList.add("hidden");
  });

  btnTestApi.addEventListener("click", async () => {
    apiTestResult.textContent = "Pinging API...";
    apiTestResult.style.color = "var(--text-muted)";
    const start = performance.now();
    try {
      const res = await fetch(`${getApiUrl()}/health`);
      const latency = Math.round(performance.now() - start);
      if (res.ok) {
        apiTestResult.textContent = `✓ Connected successfully (${latency}ms)`;
        apiTestResult.style.color = "var(--accent-emerald)";
        statusDot.className = "status-dot online";
      } else {
        throw new Error(`HTTP ${res.status}`);
      }
    } catch (e) {
      apiTestResult.textContent = `✕ Connection failed: ${e.message}`;
      apiTestResult.style.color = "var(--accent-crimson)";
      statusDot.className = "status-dot offline";
    }
  });

  btnSaveSettings.addEventListener("click", () => {
    const apiUrl = inputApiUrl.value.trim();
    const autoScan = toggleAutoscan.checked;
    const showBannerOnPhish = toggleBanner.checked;

    chrome.storage.local.set({ apiUrl, autoScan, showBannerOnPhish }, () => {
      settingsPanel.classList.add("hidden");
      checkApiHealth();
    });
  });
}
