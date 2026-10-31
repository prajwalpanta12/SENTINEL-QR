"""
AI-Based QR Code Threat Analyzer
Module: features.py
Purpose: Advanced URL Feature Engineering Pipeline (36 Dimensions).
         Extracts lexical, domain, structural, entropy, and redirection features
         for weighted soft-voting ensemble machine-learning inference and training.
"""

import math
import re
import urllib.parse
from collections import Counter
import requests
import tldextract

# List of known URL shortening domains frequently abused in QR quishing
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "goo.gl", "cutt.ly", "shorturl.at", "tiny.cc",
    "bl.ink", "hyperurl.co", "trib.al", "qr.ae", "q-r.to", "linktr.ee"
}

# Suspicious keywords commonly observed in credential harvesting and quishing scams
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "bank", "banking", "update", "secure",
    "security", "account", "signin", "wallet", "confirm", "confirmation",
    "paypal", "apple", "microsoft", "netflix", "crypto", "support", "billing",
    "free", "gift", "prize", "recover", "authenticate", "passcode", "service",
    "identity", "unlock", "alert", "ebay", "amazon"
]

# High-abuse TLDs often favored in throwaway malicious campaigns
SUSPICIOUS_TLDS = {
    "tk", "xyz", "top", "ml", "ga", "cf", "gq", "buzz", "work",
    "icu", "loan", "click", "fit", "live", "club", "surf", "monster"
}

# Recognized popular target brands (for spoofing / impersonation detection)
POPULAR_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "binance", "metamask",
    "facebook", "instagram", "whatsapp", "telegram", "coinbase"
]

# Suspicious file extensions downloadable via QR
SENSITIVE_EXTENSIONS = {
    ".exe", ".apk", ".zip", ".rar", ".bat", ".sh", ".vbs", ".scr", ".msi", ".iso"
}

# Complete 36-Feature Specification
FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "path_length",
    "count_dots",
    "count_hyphens",
    "count_underline",
    "count_slash",
    "count_question",
    "count_equal",
    "count_at",
    "count_percent",
    "count_exclamation",
    "count_ampersand",
    "count_digits",
    "digits_ratio",
    "special_chars_ratio",
    "count_subdomains",
    "has_ip_address",
    "is_https",
    "is_shortened",
    "suspicious_keywords_count",
    "shannon_entropy",
    "suspicious_tld",
    "has_port",
    "punycode_present",
    "brand_in_subdomain_or_path",
    # Advanced / Research-grade Features (35+ Dimensions)
    "redirect_count",
    "has_redirect",
    "subdomain_length",
    "tld_length",
    "count_params",
    "query_length",
    "query_entropy",
    "has_sensitive_extension",
    "vowel_consonant_ratio",
    "count_subdomain_levels"
]


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes character-level Shannon entropy of the string.
    High entropy indicates random generation, obfuscation, or DGA algorithms.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def expand_shortened_url(url: str, max_hops: int = 4, timeout: float = 2.0) -> dict:
    """
    Follows HTTP redirect chains to uncover the final destination landing URL.
    Returns:
        dict: {'final_url': str, 'redirect_count': int, 'chain': list[str]}
    """
    cleaned = url.strip()
    chain = [cleaned]
    current = cleaned

    try:
        session = requests.Session()
        session.max_redirects = max_hops
        # Perform HEAD request with timeout to avoid downloading payloads
        resp = session.head(
            current,
            allow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (SentinelQR/2.4; SecurityScanner)"}
        )
        if resp.history:
            chain = [r.url for r in resp.history] + [resp.url]
            return {
                "final_url": resp.url,
                "redirect_count": len(resp.history),
                "chain": chain
            }
    except Exception:
        pass

    return {
        "final_url": cleaned,
        "redirect_count": 0,
        "chain": chain
    }


def extract_url_features(url: str, resolve_redirects: bool = False) -> dict:
    """
    Extracts a rich dictionary of 36 features across Lexical, Domain, Security,
    Structural, and Redirection dimensions.
    """
    cleaned_url = url.strip()
    parsed = urllib.parse.urlparse(cleaned_url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    # Domain parsing using tldextract
    ext = tldextract.extract(cleaned_url)
    subdomain = ext.subdomain.lower()
    registered_domain = ext.registered_domain.lower()
    tld = ext.suffix.lower()

    # 1. Lexical Counts
    url_length = len(cleaned_url)
    domain_length = len(netloc)
    path_length = len(path)
    subdomain_length = len(subdomain)
    tld_length = len(tld)

    count_dots = cleaned_url.count(".")
    count_hyphens = cleaned_url.count("-")
    count_underline = cleaned_url.count("_")
    count_slash = cleaned_url.count("/")
    count_question = cleaned_url.count("?")
    count_equal = cleaned_url.count("=")
    count_at = cleaned_url.count("@")
    count_percent = cleaned_url.count("%")
    count_exclamation = cleaned_url.count("!")
    count_ampersand = cleaned_url.count("&")

    # 2. Digits & Special character density
    count_digits = sum(c.isdigit() for c in cleaned_url)
    digits_ratio = round(count_digits / max(1, url_length), 4)

    special_chars = set(".-_/?=@%!&")
    count_special = sum(c in special_chars for c in cleaned_url)
    special_chars_ratio = round(count_special / max(1, url_length), 4)

    # 3. Subdomain depth
    subdomains_list = [s for s in subdomain.split(".") if s]
    count_subdomains = len(subdomains_list)
    count_subdomain_levels = count_subdomains

    # 4. IP Address check
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$"
    has_ip_address = 1 if re.match(ip_pattern, netloc) else 0

    # 5. HTTPS check
    is_https = 1 if scheme == "https" else 0

    # 6. Shortener check
    is_shortened = 1 if registered_domain in SHORTENER_DOMAINS or netloc in SHORTENER_DOMAINS else 0

    # 7. Suspicious Keywords
    lower_url = cleaned_url.lower()
    suspicious_keywords_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_url)

    # 8. Shannon Entropy of complete URL
    shannon_entropy = calculate_shannon_entropy(cleaned_url)

    # 9. High-abuse TLD
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # 10. Non-standard port
    has_port = 0
    if ":" in netloc:
        port_part = netloc.split(":")[-1]
        if port_part.isdigit() and port_part not in ["80", "443"]:
            has_port = 1

    # 11. Punycode check
    punycode_present = 1 if "xn--" in netloc else 0

    # 12. Brand Spoofing Check
    brand_in_subdomain_or_path = 0
    for brand in POPULAR_BRANDS:
        if brand in subdomain or brand in path or brand in query:
            if brand not in registered_domain:
                brand_in_subdomain_or_path = 1
                break

    # 13. Query Parameter Analysis
    query_params = urllib.parse.parse_qs(query)
    count_params = len(query_params)
    query_length = len(query)
    query_entropy = calculate_shannon_entropy(query)

    # 14. Dangerous File Extension Download
    has_sensitive_extension = 0
    for ext_candidate in SENSITIVE_EXTENSIONS:
        if path.lower().endswith(ext_candidate):
            has_sensitive_extension = 1
            break

    # 15. Vowel-to-Consonant Ratio (DGA detection in domain)
    letters_in_domain = [c for c in registered_domain if c.isalpha()]
    if letters_in_domain:
        vowels = sum(c in "aeiou" for c in letters_in_domain)
        consonants = len(letters_in_domain) - vowels
        vowel_consonant_ratio = round(vowels / max(1, consonants), 4)
    else:
        vowel_consonant_ratio = 0.5

    # 16. Optional Redirection Expansion (offline-safe)
    redirect_count = 0
    if resolve_redirects and is_shortened:
        exp = expand_shortened_url(cleaned_url)
        redirect_count = exp["redirect_count"]

    has_redirect = 1 if redirect_count > 0 else 0

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_underline": count_underline,
        "count_slash": count_slash,
        "count_question": count_question,
        "count_equal": count_equal,
        "count_at": count_at,
        "count_percent": count_percent,
        "count_exclamation": count_exclamation,
        "count_ampersand": count_ampersand,
        "count_digits": count_digits,
        "digits_ratio": digits_ratio,
        "special_chars_ratio": special_chars_ratio,
        "count_subdomains": count_subdomains,
        "has_ip_address": has_ip_address,
        "is_https": is_https,
        "is_shortened": is_shortened,
        "suspicious_keywords_count": suspicious_keywords_count,
        "shannon_entropy": shannon_entropy,
        "suspicious_tld": suspicious_tld,
        "has_port": has_port,
        "punycode_present": punycode_present,
        "brand_in_subdomain_or_path": brand_in_subdomain_or_path,
        # Advanced Features (36 Dimensions)
        "redirect_count": redirect_count,
        "has_redirect": has_redirect,
        "subdomain_length": subdomain_length,
        "tld_length": tld_length,
        "count_params": count_params,
        "query_length": query_length,
        "query_entropy": query_entropy,
        "has_sensitive_extension": has_sensitive_extension,
        "vowel_consonant_ratio": vowel_consonant_ratio,
        "count_subdomain_levels": count_subdomain_levels
    }


def get_feature_vector(url: str, resolve_redirects: bool = False) -> list:
    """
    Returns ordered numeric feature vector matching FEATURE_COLUMNS.
    """
    feat_dict = extract_url_features(url, resolve_redirects=resolve_redirects)
    return [feat_dict[col] for col in FEATURE_COLUMNS]
