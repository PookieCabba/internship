/**
 * background.js — Service Worker for PhishGuard AI
 * Manages background URL monitoring, caching, badge status, and API communication.
 */

const DEFAULT_API_BASE = "http://localhost:8000";
const CACHE_TTL_MS = 1000 * 60 * 15; // 15 minutes cache
const urlCache = new Map();

// Initialize default settings on installation
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["apiUrl", "autoScan", "showBannerOnPhish"], (result) => {
    const defaults = {};
    if (!result.apiUrl) defaults.apiUrl = DEFAULT_API_BASE;
    if (result.autoScan === undefined) defaults.autoScan = true;
    if (result.showBannerOnPhish === undefined) defaults.showBannerOnPhish = true;

    if (Object.keys(defaults).length > 0) {
      chrome.storage.local.set(defaults);
    }
  });

  console.log("PhishGuard AI background service worker initialized.");
});

// Helper: Get configured API URL
async function getApiBaseUrl() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["apiUrl"], (res) => {
      resolve(res.apiUrl || DEFAULT_API_BASE);
    });
  });
}

// Call API to analyze URL
async function analyzeUrl(url) {
  if (!url || !url.startsWith("http")) {
    return null;
  }

  // Check cache
  const cached = urlCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return cached.data;
  }

  const apiBase = await getApiBaseUrl();
  const endpoint = `${apiBase.replace(/\/+$/, "")}/predict`;

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      throw new Error(`API returned HTTP ${response.status}`);
    }

    const data = await response.json();
    urlCache.set(url, { timestamp: Date.now(), data });
    return data;
  } catch (error) {
    console.error("PhishGuard API Scan error:", error);
    return { error: error.message };
  }
}

// Update Chrome extension action badge based on result
function updateBadge(tabId, result) {
  if (!tabId || !result) return;

  if (result.error) {
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#64748B" });
    return;
  }

  const isPhish = result.is_phishing;
  const risk = result.risk_level || "Unknown";

  if (isPhish || risk === "High Risk" || risk === "Critical") {
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" }); // Red
    chrome.action.setTitle({
      tabId,
      title: `⚠️ PHISHING DETECTED (${risk})\nPhishing Probability: ${(result.phishing_probability * 100).toFixed(1)}%`,
    });
  } else if (risk === "Medium Risk") {
    chrome.action.setBadgeText({ tabId, text: "⚠" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" }); // Amber
    chrome.action.setTitle({
      tabId,
      title: `⚠️ Medium Risk URL\nPhishing Probability: ${(result.phishing_probability * 100).toFixed(1)}%`,
    });
  } else {
    chrome.action.setBadgeText({ tabId, text: "✓" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" }); // Emerald Green
    chrome.action.setTitle({
      tabId,
      title: `🛡️ Safe Website\nPhishing Probability: ${(result.phishing_probability * 100).toFixed(1)}%`,
    });
  }
}

// Background auto-scan on tab update (navigation)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    chrome.storage.local.get(["autoScan", "showBannerOnPhish"], async (settings) => {
      if (settings.autoScan === false) return;

      const result = await analyzeUrl(tab.url);
      if (!result) return;

      updateBadge(tabId, result);

      if (result.is_phishing || result.risk_level === "Critical" || result.risk_level === "High Risk") {
        // Send notification
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon128.png",
          title: "🚨 PhishGuard AI Alert: Dangerous URL Detected!",
          message: `The page at ${new URL(tab.url).hostname} appears to be a phishing threat (${result.risk_level}). Proceed with caution!`,
          priority: 2,
        });

        // Instruct content script to show on-page warning if enabled
        if (settings.showBannerOnPhish !== false) {
          try {
            chrome.tabs.sendMessage(tabId, {
              type: "SHOW_PHISHING_BANNER",
              payload: result,
            });
          } catch (e) {
            // Content script may not be loaded yet on some protected pages
          }
        }
      }
    });
  }
});

// Handle incoming messages from popup or content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "CHECK_URL") {
    analyzeUrl(request.url).then((result) => {
      if (sender.tab && sender.tab.id) {
        updateBadge(sender.tab.id, result);
      }
      sendResponse({ success: true, result });
    });
    return true; // Keep message channel open for async response
  }

  if (request.type === "GET_ACTIVE_TAB_URL") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        sendResponse({ tab: tabs[0] });
      } else {
        sendResponse({ tab: null });
      }
    });
    return true;
  }

  if (request.type === "TEST_CONNECTION") {
    getApiBaseUrl().then((apiBase) => {
      fetch(`${apiBase.replace(/\/+$/, "")}/health`)
        .then((res) => res.json())
        .then((data) => sendResponse({ success: true, data }))
        .catch((err) => sendResponse({ success: false, error: err.message }));
    });
    return true;
  }
});
