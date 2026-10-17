"""
============================================================
features.py — Shared Feature Extraction Module
============================================================
This module is the single source of truth for all URL feature
engineering. It is imported by both `train_model.py` (batch
extraction during training) and `api.py` (real-time extraction
during inference), ensuring perfect feature parity between
training and serving.

Features extracted:
  1.  url_length            — Total character count of the URL
  2.  domain_length         — Character count of the registered domain
  3.  path_length           — Character count of the URL path
  4.  num_dots              — Number of '.' characters
  5.  num_hyphens           — Number of '-' characters
  6.  num_underscores       — Number of '_' characters
  7.  num_slashes           — Number of '/' characters
  8.  num_question_marks    — Number of '?' characters
  9.  num_equals            — Number of '=' characters
  10. num_at_signs          — Number of '@' characters (credential injection)
  11. num_ampersands        — Number of '&' characters
  12. num_exclamation       — Number of '!' characters
  13. num_tildes            — Number of '~' characters
  14. num_percent           — Number of '%' characters (URL encoding)
  15. num_digits            — Count of digit characters
  16. digit_ratio           — Ratio of digits to total length
  17. has_ip_address        — Binary: URL contains a raw IPv4 address
  18. has_at_sign           — Binary: URL contains '@'
  19. has_double_slash_redir — Binary: URL contains '//' beyond the protocol
  20. uses_https            — Binary: URL uses HTTPS
  21. num_subdomains        — Number of subdomain levels
  22. domain_entropy        — Shannon entropy of the domain string
  23. path_entropy          — Shannon entropy of the path string
  24. has_suspicious_tld    — Binary: TLD is in a known-suspicious list
  25. num_params            — Number of query parameters
  26. longest_token_length  — Length of the longest token (split on delimiters)
  27. avg_token_length      — Average token length

Author:  Senior AI & Cybersecurity Engineer
Version: 1.0.0
============================================================
"""

import re
import math
import logging
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
# pyrefly: ignore[missing-import]
import tldextract

# ──────────────────────────────────────────────────────────────
# Module-level configuration
# ──────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# Ordered list of feature names — used to guarantee column order
# during both training and inference.
FEATURE_NAMES: List[str] = [
    "url_length",
    "domain_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_equals",
    "num_at_signs",
    "num_ampersands",
    "num_exclamation",
    "num_tildes",
    "num_percent",
    "num_digits",
    "digit_ratio",
    "has_ip_address",
    "has_at_sign",
    "has_double_slash_redir",
    "uses_https",
    "num_subdomains",
    "domain_entropy",
    "path_entropy",
    "has_suspicious_tld",
    "num_params",
    "longest_token_length",
    "avg_token_length",
]

# TLDs commonly abused by phishing campaigns (sourced from
# multiple threat-intelligence feeds and research papers).
SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "top", "xyz", "club", "work", "gq", "ml",
    "cf", "ga", "tk", "buzz", "surf", "rest", "fit", "cam",
    "icu", "click", "link", "info", "online", "site", "pw",
})

# Compiled regex for detecting raw IPv4 addresses in URLs
_IPV4_PATTERN = re.compile(
    r"(?:^|[/@])(\d{1,3}\.){3}\d{1,3}(?:[:/]|$)"
)


# ──────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Shannon entropy measures the randomness/unpredictability of a
    string. Phishing domains often have high entropy because they
    use random character sequences to evade blocklists.

    Formula: H = -Σ p(x) * log2(p(x))

    Args:
        text: Input string to measure.

    Returns:
        Entropy value (float). Returns 0.0 for empty strings.
    """
    if not text:
        return 0.0

    # Count character frequencies
    freq = Counter(text)
    length = len(text)

    # Compute entropy
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return round(entropy, 4)


def _count_char(text: str, char: str) -> int:
    """Count occurrences of a specific character in text."""
    return text.count(char)


def _has_ip_address(url: str) -> int:
    """
    Check if the URL contains a raw IPv4 address.

    Legitimate sites almost never use raw IP addresses in URLs.
    Presence of an IP is a strong phishing indicator.

    Returns:
        1 if an IP address pattern is found, 0 otherwise.
    """
    return 1 if _IPV4_PATTERN.search(url) else 0


def _check_double_slash_redirect(url: str) -> int:
    """
    Detect '//' appearing after the protocol separator.

    Attackers use double-slash redirects to obfuscate the true
    destination. E.g., http://legit.com//evil.com

    Returns:
        1 if suspicious double-slash found, 0 otherwise.
    """
    # Remove the protocol prefix before checking
    stripped = url.split("://", 1)[-1] if "://" in url else url
    return 1 if "//" in stripped else 0


def _tokenize_url(url: str) -> List[str]:
    """
    Split a URL into tokens using common delimiters.

    Tokens are useful for statistical features like longest/average
    token length, which can distinguish human-readable URLs from
    machine-generated phishing URLs.
    """
    return re.split(r"[/\-_.?=&@#~%]+", url)


# ──────────────────────────────────────────────────────────────
# Main extraction function
# ──────────────────────────────────────────────────────────────

def extract_features(url: str) -> Dict[str, float]:
    """
    Extract all features from a single URL.

    This is the core function called during both training (via
    `extract_features_batch`) and real-time inference (via the
    FastAPI endpoint).

    Args:
        url: The full URL string to analyse.

    Returns:
        A dictionary mapping feature names to their numeric values.
        Keys match FEATURE_NAMES for guaranteed ordering.
    """
    # Ensure the URL has a scheme for proper parsing
    normalized_url = url.strip()
    if not normalized_url.startswith(("http://", "https://")):
        normalized_url = "http://" + normalized_url

    # Parse the URL into components
    parsed = urlparse(normalized_url)
    extracted = tldextract.extract(normalized_url)

    # Build the full domain string
    domain = extracted.domain + "." + extracted.suffix if extracted.suffix else extracted.domain
    subdomain = extracted.subdomain

    path = parsed.path or ""
    query = parsed.query or ""

    # Tokenize for statistical features
    tokens = [t for t in _tokenize_url(normalized_url) if t]  # filter empty
    token_lengths = [len(t) for t in tokens] if tokens else [0]

    # Count query parameters
    params = parse_qs(query)

    # ── Assemble feature dictionary ──
    features: Dict[str, float] = {
        # --- Length-based features ---
        "url_length":            len(normalized_url),
        "domain_length":         len(domain),
        "path_length":           len(path),

        # --- Character-count features ---
        "num_dots":              _count_char(normalized_url, "."),
        "num_hyphens":           _count_char(normalized_url, "-"),
        "num_underscores":       _count_char(normalized_url, "_"),
        "num_slashes":           _count_char(normalized_url, "/"),
        "num_question_marks":    _count_char(normalized_url, "?"),
        "num_equals":            _count_char(normalized_url, "="),
        "num_at_signs":          _count_char(normalized_url, "@"),
        "num_ampersands":        _count_char(normalized_url, "&"),
        "num_exclamation":       _count_char(normalized_url, "!"),
        "num_tildes":            _count_char(normalized_url, "~"),
        "num_percent":           _count_char(normalized_url, "%"),

        # --- Digit-based features ---
        "num_digits":            sum(c.isdigit() for c in normalized_url),
        "digit_ratio":           round(
            sum(c.isdigit() for c in normalized_url) / max(len(normalized_url), 1), 4
        ),

        # --- Binary indicator features ---
        "has_ip_address":        _has_ip_address(normalized_url),
        "has_at_sign":           1 if "@" in normalized_url else 0,
        "has_double_slash_redir": _check_double_slash_redirect(normalized_url),
        "uses_https":            1 if parsed.scheme == "https" else 0,

        # --- Domain-based features ---
        "num_subdomains":        len(subdomain.split(".")) if subdomain else 0,
        "domain_entropy":        _shannon_entropy(domain),
        "path_entropy":          _shannon_entropy(path),
        "has_suspicious_tld":    1 if extracted.suffix.lower() in SUSPICIOUS_TLDS else 0,

        # --- Query & token features ---
        "num_params":            len(params),
        "longest_token_length":  max(token_lengths),
        "avg_token_length":      round(np.mean(token_lengths), 4),
    }

    return features


def extract_features_batch(urls: pd.Series) -> pd.DataFrame:
    """
    Extract features for an entire Series of URLs.

    Used during model training to vectorize the full dataset
    efficiently.

    Args:
        urls: A pandas Series of URL strings.

    Returns:
        A DataFrame with one row per URL and columns matching
        FEATURE_NAMES.
    """
    logger.info(f"Extracting features for {len(urls):,} URLs...")
    records = []

    for i, url in enumerate(urls):
        try:
            features = extract_features(str(url))
            records.append(features)
        except Exception as e:
            # Log the error and fill with zeros so the row isn't lost
            logger.warning(f"Feature extraction failed for URL index {i}: {e}")
            records.append({name: 0.0 for name in FEATURE_NAMES})

    df = pd.DataFrame(records, columns=FEATURE_NAMES)
    logger.info(f"Feature extraction complete. Shape: {df.shape}")
    return df


def get_feature_warnings(features: Dict[str, float]) -> List[str]:
    """
    Generate human-readable warning messages based on extracted
    features. Used by the Streamlit dashboard to highlight
    specific risk indicators.

    Args:
        features: Dictionary of extracted features.

    Returns:
        List of warning strings describing detected risk signals.
    """
    warnings = []

    if features.get("has_ip_address", 0) == 1:
        warnings.append(
            "🔴 **IP Address Detected** — The URL contains a raw IP "
            "address instead of a domain name. Legitimate sites rarely "
            "do this."
        )

    if features.get("has_at_sign", 0) == 1:
        warnings.append(
            "🔴 **@ Symbol in URL** — The '@' sign can be used to "
            "trick browsers into ignoring the text before it, "
            "redirecting to an attacker-controlled domain."
        )

    if features.get("has_double_slash_redir", 0) == 1:
        warnings.append(
            "🟠 **Double-Slash Redirect** — A suspicious '//' was "
            "found after the protocol, which may indicate a redirect "
            "attack."
        )

    if features.get("uses_https", 0) == 0:
        warnings.append(
            "🟠 **No HTTPS** — The URL does not use HTTPS encryption. "
            "While not definitive, most legitimate modern sites use HTTPS."
        )

    if features.get("has_suspicious_tld", 0) == 1:
        warnings.append(
            "🟡 **Suspicious TLD** — The top-level domain is commonly "
            "associated with phishing campaigns (e.g., .xyz, .tk, .top)."
        )

    if features.get("url_length", 0) > 75:
        warnings.append(
            "🟡 **Unusually Long URL** — Phishing URLs are often longer "
            f"than normal ({int(features['url_length'])} characters). "
            "Attackers pad URLs to hide the real destination."
        )

    if features.get("num_subdomains", 0) > 3:
        warnings.append(
            "🟡 **Excessive Subdomains** — The URL has "
            f"{int(features['num_subdomains'])} subdomain levels, which "
            "may indicate subdomain abuse."
        )

    entropy = features.get("domain_entropy", 0)
    if entropy > 3.8:
        warnings.append(
            f"🟡 **High Domain Entropy** ({entropy:.2f}) — The domain "
            "appears to contain random characters, a common trait of "
            "algorithmically generated phishing domains."
        )

    if features.get("num_at_signs", 0) > 1:
        warnings.append(
            "🔴 **Multiple @ Signs** — Multiple '@' characters are "
            "a strong indicator of credential-harvesting attacks."
        )

    if features.get("digit_ratio", 0) > 0.3:
        warnings.append(
            "🟡 **High Digit Ratio** — The URL is composed of "
            f"{features['digit_ratio']*100:.1f}% digits, which is "
            "unusual for legitimate URLs."
        )

    return warnings
