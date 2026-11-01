"""
============================================================
threat_intel.py — Live Threat Intelligence Integrations
============================================================
Provides async wrappers around external threat-reputation APIs:

    1. Google Safe Browsing Lookup API v4
    2. URLhaus API (abuse.ch)

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
# 2. URLhaus API (abuse.ch)
# ──────────────────────────────────────────────────────────────

def check_urlhaus(url: str) -> Dict[str, Any]:
    """
    Query URLhaus (abuse.ch) to determine if a URL is a known malicious or phishing page.

    Endpoint: POST https://urlhaus-api.abuse.ch/v1/url/
    Body: url=<the_url> (form encoded, not JSON)
    No API key required.

    Args:
        url: The URL to check.

    Returns:
        dict with keys:
            is_phishing  (bool | None) — True if known threat, False if clean, None if unavailable.
            query_status (str | None)  — "is_phishing", "no_results", "not_in_database", etc.
            source       (str)        — "urlhaus" or "unavailable".
    """
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    form_data = {"url": url}
    headers = {"User-Agent": "phishguard-ai/1.0"}

    # Optional Auth-Key if provided in environment
    auth_key = os.getenv("URLHAUS_AUTH_KEY") or os.getenv("URLHAUS_API_KEY")
    if auth_key:
        headers["Auth-Key"] = auth_key

    try:
        response = requests.post(
            endpoint,
            data=form_data,
            headers=headers,
            timeout=THREAT_INTEL_TIMEOUT,
        )
        if response.status_code != 200:
            logger.warning(f"URLhaus: HTTP {response.status_code} for {url}")
            return {"is_phishing": None, "query_status": None, "source": "unavailable"}

        data = response.json()
        query_status = data.get("query_status", "")

        if query_status in ("is_phishing", "ok"):
            logger.info(f"URLhaus: THREAT CONFIRMED for {url} (query_status={query_status})")
            return {
                "is_phishing": True,
                "query_status": query_status,
                "source": "urlhaus",
            }
        elif query_status in ("no_results", "not_in_database"):
            return {
                "is_phishing": False,
                "query_status": query_status,
                "source": "urlhaus",
            }

        return {
            "is_phishing": False,
            "query_status": query_status,
            "source": "urlhaus",
        }

    except requests.exceptions.Timeout:
        logger.warning(f"URLhaus: Timeout after {THREAT_INTEL_TIMEOUT}s for {url}")
        return {"is_phishing": None, "query_status": None, "source": "unavailable"}
    except requests.exceptions.RequestException as e:
        logger.warning(f"URLhaus: Request error for {url}: {e}")
        return {"is_phishing": None, "query_status": None, "source": "unavailable"}
    except Exception as e:
        logger.error(f"URLhaus: Unexpected error for {url}: {e}")
        return {"is_phishing": None, "query_status": None, "source": "unavailable"}


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
            urlhaus               — Result from URLhaus (abuse.ch)
            any_threat_detected   — True if ANY feed flagged the URL
    """
    google_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

    loop = asyncio.get_event_loop()

    # Run the blocking HTTP calls in the thread pool with timeout
    try:
        google_future = asyncio.wait_for(
            loop.run_in_executor(None, check_google_safe_browsing, url, google_key),
            timeout=THREAT_INTEL_TIMEOUT + 1,  # Slightly longer than request timeout
        )
        urlhaus_future = asyncio.wait_for(
            loop.run_in_executor(None, check_urlhaus, url),
            timeout=THREAT_INTEL_TIMEOUT + 1,
        )

        results = await asyncio.gather(
            google_future, urlhaus_future,
            return_exceptions=True,
        )
    except Exception as e:
        logger.error(f"Threat intel gather failed: {e}")
        results = [
            {"is_threat": None, "threat_types": [], "source": "unavailable"},
            {"is_phishing": None, "query_status": None, "source": "unavailable"},
        ]

    # Unpack results, replacing exceptions with safe defaults
    google_result = results[0] if isinstance(results[0], dict) else {
        "is_threat": None, "threat_types": [], "source": "unavailable",
    }
    urlhaus_result = results[1] if isinstance(results[1], dict) else {
        "is_phishing": None, "query_status": None, "source": "unavailable",
    }

    # Determine if ANY source flagged the URL
    any_threat = False
    if google_result.get("is_threat") is True:
        any_threat = True
    if urlhaus_result.get("is_phishing") is True:
        any_threat = True

    return {
        "google_safe_browsing": google_result,
        "urlhaus": urlhaus_result,
        "any_threat_detected": any_threat,
    }
