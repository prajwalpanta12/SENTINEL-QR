"""
AI-Based QR Code Threat Analyzer
Module: rules.py
Purpose: Deterministic Cybersecurity Rule-Based Heuristics Engine (16 Rules).
         Evaluates structural, lexical, domain, and transport anomalies to assign
         fixed penalty points and plain-English threat rationale.
"""

from features import extract_url_features, SHORTENER_DOMAINS, SUSPICIOUS_TLDS, POPULAR_BRANDS, SENSITIVE_EXTENSIONS

RULES_SPEC = [
    {
        "id": "RULE_IP_HOST",
        "name": "Raw IP Address as Host",
        "severity": "CRITICAL",
        "points": 25,
        "description": "Legitimate enterprise portals use registered domain names. Raw numeric IP addresses are frequently deployed by short-lived phishing campaigns to evade domain-level reputation defenses."
    },
    {
        "id": "RULE_DANGEROUS_DOWNLOAD",
        "name": "Executable / Malware Download Target",
        "severity": "CRITICAL",
        "points": 30,
        "description": "The URL path targets a direct binary or script download (.exe, .apk, .zip, .bat, .sh). Quishing drives malware delivery by prompting mobile users to download unverified application packages."
    },
    {
        "id": "RULE_AT_SYMBOL",
        "name": "Embedded '@' Authentication Evasion",
        "severity": "CRITICAL",
        "points": 25,
        "description": "The '@' symbol instructs web clients to interpret preceding text as authentication credentials, silently routing the browser to the destination host following '@'."
    },
    {
        "id": "RULE_PUNYCODE",
        "name": "Punycode / IDN Homograph Spoof",
        "severity": "CRITICAL",
        "points": 25,
        "description": "The domain employs 'xn--' Punycode to visually mimic familiar brand names using lookalike Cyrillic or Greek glyphs (Homograph Attack)."
    },
    {
        "id": "RULE_BRAND_SPOOFING",
        "name": "Deceptive Brand Name Impersonation",
        "severity": "HIGH",
        "points": 25,
        "description": "A high-value brand appears in the subdomain or URL path, while the apex registered domain belongs to an unrelated third party."
    },
    {
        "id": "RULE_URL_SHORTENER",
        "name": "URL Obfuscation Service (Shortener)",
        "severity": "HIGH",
        "points": 20,
        "description": "The URL utilizes a link shortening service (e.g., bit.ly, tinyurl), concealing the true landing page from pre-scan inspection."
    },
    {
        "id": "RULE_REDIRECT_CHAIN",
        "name": "Multi-Hop Redirection Chain",
        "severity": "HIGH",
        "points": 20,
        "description": "The URL redirects across multiple intermediary hops before reaching its destination, a technique used to evade automated sandbox scanners."
    },
    {
        "id": "RULE_SUSPICIOUS_KEYWORD",
        "name": "Sensitive Phishing & Credential Lures",
        "severity": "HIGH",
        "points": 20,
        "description": "The URL contains credential harvesting keywords ('login', 'verify', 'update', 'banking', 'wallet') strongly linked to account takeover attempts."
    },
    {
        "id": "RULE_NO_HTTPS",
        "name": "Insecure Cleartext HTTP Protocol",
        "severity": "MEDIUM",
        "points": 15,
        "description": "The destination lacks Transport Layer Security (TLS/HTTPS). Transmitted data is unencrypted and vulnerable to Man-in-the-Middle (MitM) eavesdropping."
    },
    {
        "id": "RULE_HIGH_ENTROPY",
        "name": "High Character Entropy (DGA Pattern)",
        "severity": "MEDIUM",
        "points": 15,
        "description": "The URL exhibits an elevated Shannon entropy score (> 4.2), indicating pseudo-random character generation common in botnets and DGA algorithms."
    },
    {
        "id": "RULE_DGA_VOWEL_ANOMALY",
        "name": "Algorithmic DGA Domain Pattern",
        "severity": "MEDIUM",
        "points": 15,
        "description": "The domain displays an unnatural vowel-to-consonant ratio (< 0.20), a statistical hallmark of automated Domain Generation Algorithms."
    },
    {
        "id": "RULE_SUSPICIOUS_TLD",
        "name": "High-Abuse Disposable TLD",
        "severity": "MEDIUM",
        "points": 15,
        "description": "The domain uses a TLD with historically high abuse rates (.xyz, .top, .buzz, .tk) disproportionately favored in disposable cybercrime campaigns."
    },
    {
        "id": "RULE_EXCESSIVE_SUBDOMAINS",
        "name": "Deeply Nested Subdomains (>= 3 levels)",
        "severity": "MEDIUM",
        "points": 15,
        "description": "The domain features three or more nested subdomain levels, often used to mimic complex corporate portals on free dynamic DNS providers."
    },
    {
        "id": "RULE_NON_STANDARD_PORT",
        "name": "Non-Standard Network Port",
        "severity": "MEDIUM",
        "points": 15,
        "description": "The URL targets a non-standard network port rather than standard 80 or 443, commonly done to evade perimeter enterprise firewall filters."
    },
    {
        "id": "RULE_PARAMETER_SMUGGLING",
        "name": "Query Parameter Smuggling",
        "severity": "LOW",
        "points": 10,
        "description": "URL query string contains extensive complex parameters with high entropy, indicating tracking token smuggling or payload delivery."
    },
    {
        "id": "RULE_EXCESSIVE_LENGTH",
        "name": "Excessive Length (> 75 chars)",
        "severity": "LOW",
        "points": 10,
        "description": "The URL exceeds 75 characters. Excessive padding is frequently used to truncate the visible destination on mobile device screens."
    }
]


def evaluate_rules(url: str, features: dict = None) -> dict:
    """Evaluates 16 cybersecurity heuristics against extracted features."""
    if features is None:
        features = extract_url_features(url)

    triggered = []
    total_score = 0

    def add_rule(rule_id, custom_reason=None, override_pts=None):
        nonlocal total_score
        r = next((item for item in RULES_SPEC if item["id"] == rule_id), None)
        if r:
            pts = override_pts if override_pts is not None else r["points"]
            desc = custom_reason if custom_reason else r["description"]
            triggered.append({**r, "points": pts, "reason": desc})
            total_score += pts

    # 1. IP Host
    if features.get("has_ip_address", 0) == 1:
        add_rule("RULE_IP_HOST")

    # 2. Sensitive Extension Download
    if features.get("has_sensitive_extension", 0) == 1:
        add_rule("RULE_DANGEROUS_DOWNLOAD", "URL links directly to an executable, archive, or script package.")

    # 3. @ Symbol
    if features.get("count_at", 0) > 0:
        add_rule("RULE_AT_SYMBOL", f"Contains {features['count_at']} '@' symbol(s) used for credential authority diversion.")

    # 4. Punycode
    if features.get("punycode_present", 0) == 1:
        add_rule("RULE_PUNYCODE")

    # 5. Brand Spoofing
    if features.get("brand_in_subdomain_or_path", 0) == 1:
        add_rule("RULE_BRAND_SPOOFING")

    # 6. URL Shortener
    if features.get("is_shortened", 0) == 1:
        add_rule("RULE_URL_SHORTENER")

    # 7. Multi-hop Redirection
    if features.get("redirect_count", 0) >= 2:
        add_rule("RULE_REDIRECT_CHAIN", f"URL traverses {features['redirect_count']} intermediary redirect hops.")

    # 8. Phishing Keywords
    kw_count = features.get("suspicious_keywords_count", 0)
    if kw_count >= 1:
        pts = min(25, 15 + (kw_count - 1) * 5)
        add_rule("RULE_SUSPICIOUS_KEYWORD", f"Found {kw_count} credential or account lure term(s) in URL.", override_pts=pts)

    # 9. No HTTPS
    if features.get("is_https", 0) == 0:
        add_rule("RULE_NO_HTTPS")

    # 10. High Shannon Entropy
    if features.get("shannon_entropy", 0.0) >= 4.2:
        add_rule("RULE_HIGH_ENTROPY", f"Shannon entropy is {features['shannon_entropy']:.2f} bits, indicating high token randomness.")

    # 11. DGA Vowel Ratio
    if features.get("vowel_consonant_ratio", 0.5) < 0.20 and features.get("domain_length", 0) >= 8:
        add_rule("RULE_DGA_VOWEL_ANOMALY")

    # 12. Suspicious TLD
    if features.get("suspicious_tld", 0) == 1:
        add_rule("RULE_SUSPICIOUS_TLD")

    # 13. Excessive Subdomains
    if features.get("count_subdomains", 0) >= 3:
        add_rule("RULE_EXCESSIVE_SUBDOMAINS", f"Domain contains {features['count_subdomains']} nested subdomains.")

    # 14. Non-standard Port
    if features.get("has_port", 0) == 1:
        add_rule("RULE_NON_STANDARD_PORT")

    # 15. Parameter Smuggling
    if features.get("count_params", 0) >= 3 and features.get("query_entropy", 0) > 3.8:
        add_rule("RULE_PARAMETER_SMUGGLING")

    # 16. Excessive URL Length
    if features.get("url_length", 0) > 75:
        add_rule("RULE_EXCESSIVE_LENGTH", f"Length is {features['url_length']} characters (threshold: 75).")

    normalized_score = min(100, total_score)

    return {
        "rule_score": normalized_score,
        "raw_points": total_score,
        "triggered_rules": triggered,
        "total_rules_checked": len(RULES_SPEC),
        "rule_count": len(triggered)
    }
