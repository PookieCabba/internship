/**
 * content.js — PhishGuard in-page security shield
 * Injects a security alert banner when a user lands on a verified phishing or high-risk domain.
 */

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SHOW_PHISHING_BANNER") {
    displaySecurityBanner(message.payload);
  }
});

function displaySecurityBanner(data) {
  // Prevent duplicate banners
  if (document.getElementById("phishguard-alert-container")) {
    return;
  }

  const container = document.createElement("div");
  container.id = "phishguard-alert-container";

  const probabilityPct = (data.phishing_probability * 100).toFixed(1);
  const warningsList = (data.warnings && data.warnings.length > 0)
    ? data.warnings.map(w => `<li>⚠️ ${escapeHtml(w)}</li>`).join("")
    : "<li>⚠️ Heuristic anomaly detected in URL structure</li>";

  container.innerHTML = `
    <div class="phishguard-backdrop"></div>
    <div class="phishguard-modal">
      <div class="phishguard-header">
        <div class="phishguard-icon-box">🛡️</div>
        <div>
          <h2 class="phishguard-title">PhishGuard Security Warning</h2>
          <div class="phishguard-badge phishguard-badge-danger">
            ${escapeHtml(data.risk_level.toUpperCase())} (${probabilityPct}% Phishing Probability)
          </div>
        </div>
      </div>

      <div class="phishguard-body">
        <p class="phishguard-lead">
          Our AI security model detected that <strong>${escapeHtml(window.location.hostname)}</strong> exhibits classic characteristics of a malicious phishing attack.
        </p>

        <div class="phishguard-warnings-box">
          <div class="phishguard-box-title">Detected Threat Signals:</div>
          <ul class="phishguard-warnings-list">
            ${warningsList}
          </ul>
        </div>

        <p class="phishguard-advice">
          <strong>Recommendation:</strong> Do NOT enter passwords, financial credentials, credit cards, or personal data on this page.
        </p>
      </div>

      <div class="phishguard-actions">
        <button id="phishguard-btn-safe" class="phishguard-btn phishguard-btn-primary">
          ← Take Me to Safety
        </button>
        <a id="phishguard-btn-dismiss" href="#" class="phishguard-proceed-link">
          I understand the risks — proceed anyway
        </a>
      </div>
    </div>
  `;

  document.documentElement.appendChild(container);

  // "Take Me to Safety" navigates away from the page
  document.getElementById("phishguard-btn-safe").addEventListener("click", () => {
    window.location.href = "https://www.google.com";
  });

  // "Proceed anyway" — remove the overlay so the user can interact with
  // the underlying page.  The banner does NOT block navigation; the user
  // explicitly acknowledges the risk by clicking this link.
  document.getElementById("phishguard-btn-dismiss").addEventListener("click", (e) => {
    e.preventDefault();
    container.style.transition = "opacity 0.3s ease";
    container.style.opacity = "0";
    setTimeout(() => {
      container.remove();
    }, 300);
  });

  // Allow clicking the backdrop itself to dismiss (non-blocking navigation)
  const backdrop = container.querySelector(".phishguard-backdrop");
  if (backdrop) {
    backdrop.addEventListener("click", () => {
      container.style.transition = "opacity 0.3s ease";
      container.style.opacity = "0";
      setTimeout(() => {
        container.remove();
      }, 300);
    });
  }
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
