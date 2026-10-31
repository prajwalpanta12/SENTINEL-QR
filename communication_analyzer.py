"""
AI-Based QR Code Threat Analyzer
Module: communication_analyzer.py
Purpose: Security Inspection for Email (mailto:) and Phone (tel:) QR Payloads.
         Detects email spoofing, credential harvesting lures, and toll-fraud / vishing phone numbers.
"""

from qr_types import parse_email_payload, parse_phone_payload

PHISHING_SUBJECT_KEYWORDS = [
    "suspended", "urgent", "security alert", "verify", "password",
    "unauthorized", "invoice", "payment", "bank", "freeze", "compromised"
]

HIGH_ABUSE_EMAIL_DOMAINS = [
    "xyz", "top", "buzz", "tk", "ml", "ga", "cf", "gq", "work", "icu"
]

PREMIUM_TOLL_PREFIXES = ["+1900", "+881", "+882", "+232", "+247", "+248", "+252"]


def analyze_email_payload(raw_text: str) -> dict:
    """
    Audits a mailto: QR code for phishing and social engineering triggers.
    """
    data = parse_email_payload(raw_text)
    red_flags = []
    penalty = 0

    domain = data["domain"].lower()
    subject = data["subject"].lower()
    body = data["body"].lower()

    # 1. Suspicious high-abuse domain
    tld = domain.split(".")[-1] if "." in domain else ""
    if tld in HIGH_ABUSE_EMAIL_DOMAINS:
        red_flags.append({
            "rule": "HIGH_ABUSE_EMAIL_DOMAIN",
            "severity": "HIGH",
            "points": 35,
            "title": "High-Abuse Disposable Email Domain",
            "description": f"Recipient domain (.{tld}) is in high-abuse registrar lists frequently used for transient phishing."
        })
        penalty += 35

    # 2. Phishing lure in subject
    lures = [kw for kw in PHISHING_SUBJECT_KEYWORDS if kw in subject or kw in body]
    if lures:
        points = min(40, len(lures) * 20)
        red_flags.append({
            "rule": "PHISHING_EMAIL_LURE",
            "severity": "HIGH",
            "points": points,
            "title": "Social Engineering / Phishing Lure in Email",
            "description": f"Email pre-populates urgent alarmist keywords: '{', '.join(lures)}'."
        })
        penalty += points

    final_score = min(100, penalty)
    verdict = "SAFE" if final_score <= 25 else ("SUSPICIOUS" if final_score <= 55 else "MALICIOUS")
    verdict_color = "#10b981" if verdict == "SAFE" else ("#f59e0b" if verdict == "SUSPICIOUS" else "#ef4444")

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "summary": f"Email target: {data['recipient']}",
        "red_flags": red_flags,
        "parsed_data": data,
        "actionable_guidance": [
            "Verify the recipient address before hitting send.",
            "Never send confidential passwords, credit card numbers, or OTPs via unencrypted email."
        ]
    }


def analyze_phone_payload(raw_text: str) -> dict:
    """
    Audits a tel: phone number QR code for toll fraud and vishing triggers.
    """
    data = parse_phone_payload(raw_text)
    red_flags = []
    penalty = 0

    number = data["phone_number"]

    # 1. Premium-rate toll fraud prefix
    if any(number.startswith(prefix) for prefix in PREMIUM_TOLL_PREFIXES):
        red_flags.append({
            "rule": "PREMIUM_RATE_TOLL_FRAUD",
            "severity": "CRITICAL",
            "points": 70,
            "title": "Premium-Rate International Toll Number",
            "description": "Dialing this number connects to high-tariff international or satellite billing lines (Wangiri / Toll Fraud)."
        })
        penalty += 70

    # 2. Suspicious length (too short or excessively long USSD)
    if len(number) < 5:
        red_flags.append({
            "rule": "SUSPICIOUS_SHORT_CODE",
            "severity": "MEDIUM",
            "points": 25,
            "title": "Short Code / Potential USSD Dial Lure",
            "description": "Number is a short code that might trigger automated carrier service activations or subscription charges."
        })
        penalty += 25

    final_score = min(100, penalty)
    verdict = "SAFE" if final_score <= 25 else ("SUSPICIOUS" if final_score <= 55 else "MALICIOUS")
    verdict_color = "#10b981" if verdict == "SAFE" else ("#f59e0b" if verdict == "SUSPICIOUS" else "#ef4444")

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "summary": f"Phone target: {data['phone_number']}",
        "red_flags": red_flags,
        "parsed_data": data,
        "actionable_guidance": [
            "Confirm the number identity before placing a phone call.",
            "Be vigilant against Vishing (Voice Phishing) agents asking for one-time passwords."
        ]
    }
