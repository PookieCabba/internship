"""
============================================================
threat_intel.py — Live Threat Intelligence Integrations
============================================================
Provides async wrappers around external threat-reputation APIs:

    1. Google Safe Browsing Lookup API v4
    2. PhishTank URL Check API

Each function is fully fault-tolerant: if the API key is missing,
the request times out, or the remote service returns an error,
the function returns a graceful "unavailable" response so that the
core ML prediction pipeline is never disrupted.

Usage (from api.py):
    from threat_intel import run_threat_intel
    intel = await run_threat_intel("https://suspicious-url.xyz")

Author:  Senior AI & Cybersecurity Engineer
Version: 1.0.0
============================================================
"""

import os
import asyncio
import logging
from typing import Dict, Any, Optional
from urllib.parse import quote_plus

# pyrefly: ignore[missing-import]
import requests

logger = logging.getLogger(__name__)

# Timeout for each individual external API call (seconds)
THREAT_INTEL_TIMEOUT = 3


# ──────────────────────────────────────────────────────────────
# 1. Google Safe Browsing Lookup API v4
# ──────────────────────────────────────────────────────────────

def check_google_safe_browsing(url: str, api_key: str) -> Dict[str, Any]:
    """
    Query Google Safe Browsing v4 for known threats.

    Checks the URL against three threat categories:
        - MALWARE
        - SOCIAL_ENGINEERING (phishing)
        - UNWANTED_SOFTWARE

    Args:
        url:     The URL to check.
        api_key: Google Safe Browsing API key.

    Returns:
        dict with keys:
            is_threat    (bool | None) — True if threat found, None if unavailable.
            threat_types (list[str])   — Matched threat type strings.
            source       (str)        — Always "google_safe_browsing" or "unavailable".
    """
    placeholder_values = {"", "your_key_here", "your_google_key_here"}

    if not api_key or api_key in placeholder_values:
        logger.debug("Google Safe Browsing: No API key configured — skipping.")
        return {"is_threat": None, "threat_types": [], "source": "unavailable"}

    endpoint = (
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={api_key}"
    )

    payload = {
        "client": {
            "clientId": "phishguard-ai",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=THREAT_INTEL_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        matches = data.get("matches", [])
        if matches:
            threat_types = list({m.get("threatType", "UNKNOWN") for m in matches})
            logger.info(
                f"Google Safe Browsing: THREAT DETECTED for {url} — {threat_types}"
            )
            return {
                "is_threat": True,
                "threat_types": threat_types,
                "source": "google_safe_browsing",
            }

        return {
            "is_threat": False,
            "threat_types": [],
            "source": "google_safe_browsing",
        }

    except requests.exceptions.Timeout:
        logger.warning(f"Google Safe Browsing: Timeout after {THREAT_INTEL_TIMEOUT}s for {url}")
        return {"is_threat": None, "threat_types": [], "source": "unavailable"}
    except requests.exceptions.RequestException as e:
        logger.warning(f"Google Safe Browsing: Request error for {url}: {e}")
        return {"is_threat": None, "threat_types": [], "source": "unavailable"}
    except Exception as e:
        logger.error(f"Google Safe Browsing: Unexpected error for {url}: {e}")
        return {"is_threat": None, "threat_types": [], "source": "unavailable"}


# ──────────────────────────────────────────────────────────────
# 2. PhishTank URL Check API
# ──────────────────────────────────────────────────────────────

def check_phishtank(url: str, api_key: str) -> Dict[str, Any]:
    """
    Query PhishTank to determine if a URL is a known phishing page.

    Args:
        url:     The URL to check.
        api_key: PhishTank application key.

    Returns:
        dict with keys:
            is_phishing (bool | None) — True if confirmed phish, None if unavailable.
            verified    (bool)        — Whether PhishTank has verified the entry.
            source      (str)        — Always "phishtank" or "unavailable".
    """
    placeholder_values = {"", "your_key_here", "your_phishtank_key_here"}

    if not api_key or api_key in placeholder_values:
        logger.debug("PhishTank: No API key configured — skipping.")
        return {"is_phishing": None, "verified": False, "source": "unavailable"}

    endpoint = "https://checkurl.phishtank.com/checkurl/"

    form_data = {
        "url": quote_plus(url),
        "format": "json",
        "app_key": api_key,
    }

    try:
        response = requests.post(
            endpoint,
            data=form_data,
            timeout=THREAT_INTEL_TIMEOUT,
            headers={"User-Agent": "phishguard-ai/1.0"},
        )
        response.raise_for_status()
        data = response.json()

        results = data.get("results", {})
        in_database = results.get("in_database", False)
        is_phish = results.get("valid", False)  # "valid" = confirmed phish
        verified = results.get("verified", False)

        if in_database and is_phish:
            logger.info(f"PhishTank: PHISHING CONFIRMED for {url} (verified={verified})")
            return {
                "is_phishing": True,
                "verified": bool(verified),
                "source": "phishtank",
            }

        return {
            "is_phishing": False,
            "verified": False,
            "source": "phishtank",
        }

    except requests.exceptions.Timeout:
        logger.warning(f"PhishTank: Timeout after {THREAT_INTEL_TIMEOUT}s for {url}")
        return {"is_phishing": None, "verified": False, "source": "unavailable"}
    except requests.exceptions.RequestException as e:
        logger.warning(f"PhishTank: Request error for {url}: {e}")
        return {"is_phishing": None, "verified": False, "source": "unavailable"}
    except Exception as e:
        logger.error(f"PhishTank: Unexpected error for {url}: {e}")
        return {"is_phishing": None, "verified": False, "source": "unavailable"}


# ──────────────────────────────────────────────────────────────
# 3. Combined Threat Intelligence Runner
# ──────────────────────────────────────────────────────────────

async def run_threat_intel(url: str) -> Dict[str, Any]:
    """
    Run all threat intelligence checks concurrently with individual
    3-second timeouts.  Returns a merged dict of all results.

    If both APIs are unavailable (no keys or network errors), this
    still returns a valid dict — the ML model is never blocked.

    Args:
        url: The URL to check across all threat feeds.

    Returns:
        dict with keys:
            google_safe_browsing  — Result from Google Safe Browsing
            phishtank             — Result from PhishTank
            any_threat_detected   — True if ANY feed flagged the URL
    """
    google_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    phishtank_key = os.getenv("PHISHTANK_API_KEY", "")

    loop = asyncio.get_event_loop()

    # Run the blocking HTTP calls in the thread pool with timeout
    try:
        google_future = asyncio.wait_for(
            loop.run_in_executor(None, check_google_safe_browsing, url, google_key),
            timeout=THREAT_INTEL_TIMEOUT + 1,  # Slightly longer than request timeout
        )
        phishtank_future = asyncio.wait_for(
            loop.run_in_executor(None, check_phishtank, url, phishtank_key),
            timeout=THREAT_INTEL_TIMEOUT + 1,
        )

        results = await asyncio.gather(
            google_future, phishtank_future,
            return_exceptions=True,
        )
    except Exception as e:
        logger.error(f"Threat intel gather failed: {e}")
        results = [
            {"is_threat": None, "threat_types": [], "source": "unavailable"},
            {"is_phishing": None, "verified": False, "source": "unavailable"},
        ]

    # Unpack results, replacing exceptions with safe defaults
    google_result = results[0] if isinstance(results[0], dict) else {
        "is_threat": None, "threat_types": [], "source": "unavailable",
    }
    phishtank_result = results[1] if isinstance(results[1], dict) else {
        "is_phishing": None, "verified": False, "source": "unavailable",
    }

    # Determine if ANY source flagged the URL
    any_threat = False
    if google_result.get("is_threat") is True:
        any_threat = True
    if phishtank_result.get("is_phishing") is True:
        any_threat = True

    return {
        "google_safe_browsing": google_result,
        "phishtank": phishtank_result,
        "any_threat_detected": any_threat,
    }
