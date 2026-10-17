"""
============================================================
generate_dataset.py — Synthetic Dataset Generator
============================================================
Since real phishing datasets require access to threat-intel feeds,
this script generates a realistic synthetic dataset for training
and evaluation.

It creates two categories:
  • Legitimate URLs — modeled after real-world website patterns
  • Phishing URLs    — modeled after known phishing URL traits

The output CSV has two columns:
  • url   — the full URL string
  • label — 0 (legitimate) or 1 (phishing)

Usage:
    python generate_dataset.py

Output:
    data/phishing_dataset.csv

Author:  Senior AI & Cybersecurity Engineer
Version: 1.0.0
============================================================
"""

import os
import random
import string
import csv
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s — %(message)s")
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────
NUM_LEGITIMATE = 5000
NUM_PHISHING = 5000
OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "phishing_dataset.csv")
RANDOM_SEED = 42

# ──────────────────────────────────────────────────────────────
# Vocabulary banks for generating realistic URLs
# ──────────────────────────────────────────────────────────────

LEGIT_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "linkedin.com", "twitter.com", "reddit.com",
    "netflix.com", "spotify.com", "dropbox.com", "medium.com",
    "nytimes.com", "bbc.co.uk", "cnn.com", "youtube.com",
    "zoom.us", "slack.com", "notion.so", "figma.com",
    "stripe.com", "shopify.com", "wordpress.com", "adobe.com",
    "salesforce.com", "oracle.com", "ibm.com", "intel.com",
    "nvidia.com", "samsung.com", "paypal.com", "ebay.com",
    "etsy.com", "airbnb.com", "uber.com", "lyft.com",
    "twitch.tv", "discord.com", "telegram.org", "whatsapp.com",
]

LEGIT_PATHS = [
    "/", "/about", "/contact", "/products", "/pricing",
    "/blog", "/help", "/support", "/docs", "/login",
    "/signup", "/dashboard", "/settings", "/profile",
    "/search", "/terms", "/privacy", "/careers", "/news",
    "/features", "/enterprise", "/downloads", "/api",
    "/status", "/community", "/resources", "/learning",
]

LEGIT_SUBDOMAINS = [
    "", "www", "mail", "docs", "drive", "app", "api",
    "support", "help", "blog", "cdn", "static", "m",
]

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "confirm", "banking", "signin", "security", "alert",
    "suspend", "unlock", "recover", "authenticate", "validate",
    "password", "credential", "webmail", "service", "payment",
    "invoice", "billing", "wallet", "reward", "bonus",
]

PHISHING_BRAND_MIMICS = [
    "google", "facebook", "apple", "microsoft", "amazon",
    "paypal", "netflix", "linkedin", "instagram", "twitter",
    "bank", "chase", "wellsfargo", "citibank", "hsbc",
    "dropbox", "icloud", "outlook", "yahoo", "aol",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".gq", ".ml", ".cf",
    ".ga", ".tk", ".buzz", ".surf", ".rest", ".fit",
    ".icu", ".click", ".link", ".info", ".online", ".site", ".pw",
]

LEGIT_TLDS = [
    ".com", ".org", ".net", ".edu", ".gov", ".io", ".co",
    ".us", ".uk", ".de", ".fr", ".jp", ".au", ".ca",
]


def random_string(min_len: int = 3, max_len: int = 10) -> str:
    """Generate a random lowercase alphanumeric string."""
    length = random.randint(min_len, max_len)
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def random_ip() -> str:
    """Generate a random IPv4 address."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


# ──────────────────────────────────────────────────────────────
# Legitimate URL generator
# ──────────────────────────────────────────────────────────────

def generate_legitimate_url() -> str:
    """
    Generate a URL that mimics legitimate website patterns:
      - Uses well-known domains
      - Clean, short paths
      - Mostly HTTPS
      - Optional standard subdomains (www, docs, etc.)
    """
    scheme = "https" if random.random() < 0.85 else "http"
    domain = random.choice(LEGIT_DOMAINS)
    subdomain = random.choice(LEGIT_SUBDOMAINS)

    host = f"{subdomain}.{domain}" if subdomain else domain
    path = random.choice(LEGIT_PATHS)

    # Occasionally add a clean query parameter
    query = ""
    if random.random() < 0.2:
        query = f"?page={random.randint(1, 20)}"
    elif random.random() < 0.1:
        query = f"?q={random_string(3, 8)}"

    # Occasionally add a deeper path
    if random.random() < 0.3 and path != "/":
        path += f"/{random_string(4, 12)}"

    return f"{scheme}://{host}{path}{query}"


# ──────────────────────────────────────────────────────────────
# Phishing URL generator
# ──────────────────────────────────────────────────────────────

def generate_phishing_url() -> str:
    """
    Generate a URL that mimics known phishing patterns.

    Phishing URL archetypes used:
      1. Brand-in-subdomain:  secure-apple.login.xyz
      2. IP-based:            http://192.168.1.100/login
      3. Long obfuscated:     http://x3k2j.tk/verify-account?...
      4. @ symbol redirect:   http://google.com@evil.com/phish
      5. Typosquatting:        http://g00gle.com/login
      6. Keyword-stuffed:     http://secure-login-verify.top/...
    """
    archetype = random.choices(
        ["brand_subdomain", "ip_based", "obfuscated", "at_redirect",
         "typosquat", "keyword_stuffed"],
        weights=[25, 15, 20, 10, 10, 20],
        k=1
    )[0]

    scheme = "http" if random.random() < 0.6 else "https"

    if archetype == "brand_subdomain":
        # Example: secure-apple-login.verify.xyz
        brand = random.choice(PHISHING_BRAND_MIMICS)
        keyword = random.choice(PHISHING_KEYWORDS)
        tld = random.choice(SUSPICIOUS_TLDS)
        separator = random.choice(["-", ".", "-"])
        subdomain_part = f"{keyword}{separator}{brand}"
        domain = f"{random_string(4, 8)}{tld}"
        path = f"/{random.choice(PHISHING_KEYWORDS)}/{random_string(8, 20)}"
        url = f"{scheme}://{subdomain_part}.{domain}{path}"

    elif archetype == "ip_based":
        # Example: http://192.168.45.12/secure/login.html
        ip = random_ip()
        keyword = random.choice(PHISHING_KEYWORDS)
        path = f"/{keyword}/{random_string(5, 15)}.html"
        url = f"http://{ip}{path}"

    elif archetype == "obfuscated":
        # Example: http://x8k2mq9z.tk/a1b2c3?redirect=...
        domain = f"{random_string(8, 20)}{random.choice(SUSPICIOUS_TLDS)}"
        path = f"/{random_string(5, 15)}"
        # Add multiple query params to increase complexity
        params = "&".join(
            f"{random_string(2, 5)}={random_string(5, 20)}"
            for _ in range(random.randint(2, 6))
        )
        url = f"{scheme}://{domain}{path}?{params}"

    elif archetype == "at_redirect":
        # Example: http://google.com@evil-server.com/phish
        legit_looking = random.choice(LEGIT_DOMAINS)
        evil_domain = f"{random_string(5, 12)}{random.choice(SUSPICIOUS_TLDS)}"
        keyword = random.choice(PHISHING_KEYWORDS)
        url = f"{scheme}://{legit_looking}@{evil_domain}/{keyword}"

    elif archetype == "typosquat":
        # Example: http://amaz0n.com/login, http://g00gle.com/verify
        brand = random.choice(PHISHING_BRAND_MIMICS)
        # Apply random character substitutions
        typo_brand = brand.replace("o", "0", 1) if "o" in brand else brand
        typo_brand = typo_brand.replace("l", "1", 1) if "l" in typo_brand else typo_brand
        typo_brand = typo_brand.replace("i", "1", 1) if random.random() < 0.4 else typo_brand
        # Sometimes add extra chars
        if random.random() < 0.5:
            typo_brand += random.choice(["-secure", "-login", "-verify", "-auth"])
        tld = random.choice(SUSPICIOUS_TLDS + [".com", ".net"])
        keyword = random.choice(PHISHING_KEYWORDS)
        url = f"{scheme}://{typo_brand}{tld}/{keyword}"

    else:  # keyword_stuffed
        # Example: http://secure-login-verify-account-update.top/...
        num_keywords = random.randint(3, 6)
        keywords = random.sample(PHISHING_KEYWORDS, num_keywords)
        domain_name = "-".join(keywords)
        tld = random.choice(SUSPICIOUS_TLDS)
        path = f"/{random_string(10, 30)}"
        url = f"{scheme}://{domain_name}{tld}{path}"

    return url


# ──────────────────────────────────────────────────────────────
# Main generator
# ──────────────────────────────────────────────────────────────

def main():
    """Generate the complete dataset and save to CSV."""
    random.seed(RANDOM_SEED)

    logger.info("Generating synthetic phishing dataset...")

    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Generate URLs
    legitimate_urls = [(generate_legitimate_url(), 0) for _ in range(NUM_LEGITIMATE)]
    phishing_urls = [(generate_phishing_url(), 1) for _ in range(NUM_PHISHING)]

    # Combine and shuffle
    all_urls = legitimate_urls + phishing_urls
    random.shuffle(all_urls)

    # Write to CSV
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(all_urls)

    logger.info(f"Dataset saved to {OUTPUT_FILE}")
    logger.info(f"  Total samples:  {len(all_urls):,}")
    logger.info(f"  Legitimate (0): {NUM_LEGITIMATE:,}")
    logger.info(f"  Phishing   (1): {NUM_PHISHING:,}")

    # Quick sanity check — print a few samples
    logger.info("\n--- Sample Legitimate URLs ---")
    for url, label in legitimate_urls[:3]:
        logger.info(f"  [{label}] {url}")

    logger.info("\n--- Sample Phishing URLs ---")
    for url, label in phishing_urls[:3]:
        logger.info(f"  [{label}] {url}")


if __name__ == "__main__":
    main()
