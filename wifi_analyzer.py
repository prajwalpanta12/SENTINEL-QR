"""
AI-Based QR Code Threat Analyzer
Module: wifi_analyzer.py
Purpose: Wi-Fi QR Code Security and Rogue Access Point (AP) Analyzer.
         Audits Wi-Fi configuration payloads for open unencrypted networks,
         obsolete WEP ciphers, hidden SSIDs, weak passphrases, and Evil Twin honeypots.
"""

from qr_types import parse_wifi_payload

# Common Evil Twin / Honeypot SSID lures
PUBLIC_VENUE_LURES = [
    "airport", "free", "guest", "starbucks", "hotel", "metro", "station",
    "cafe", "mall", "public", "open", "wifi_free", "highspeed", "library"
]

# Weak Default / Common Dictionary Passwords
WEAK_PASSWORDS = {
    "password", "12345678", "123456789", "admin", "admin123", "guest123",
    "welcome", "internet", "wifi1234", "qwerty1234", "11111111", "00000000"
}


def analyze_wifi_payload(raw_text: str) -> dict:
    """
    Analyzes security posture of a Wi-Fi network configuration QR code.
    Returns:
        dict: {
            'risk_score': int (0-100),
            'verdict': str ('SECURE', 'WEAK SECURITY', 'CRITICAL RISK'),
            'verdict_color': str,
            'red_flags': list[dict],
            'parsed_data': dict,
            'actionable_guidance': list[str],
            'summary': str
        }
    """
    data = parse_wifi_payload(raw_text)
    red_flags = []
    penalty_score = 0

    auth_raw = data["auth_type_raw"].upper()
    ssid = data["ssid"]
    password = data["password"]
    is_hidden = data["hidden"]
    ssid_lower = ssid.lower()

    # Check 1: Open / Unencrypted Network (Rogue AP / MitM Danger)
    if data["is_open"]:
        red_flags.append({
            "rule": "UNENCRYPTED_OPEN_NETWORK",
            "severity": "CRITICAL",
            "points": 65,
            "title": "Unencrypted Open Wireless Network",
            "description": "Network transmits all radio frames in plaintext without 802.11 cipher encryption. Anyone within radio range can sniff unencrypted traffic or execute Man-in-the-Middle (MitM) packet injection."
        })
        penalty_score += 65

        # Check 1b: Evil Twin / Fake Public Hotspot Lure
        if any(lure in ssid_lower for lure in PUBLIC_VENUE_LURES):
            red_flags.append({
                "rule": "EVIL_TWIN_HONEYPOT_LURE",
                "severity": "CRITICAL",
                "points": 25,
                "title": "Potential Evil Twin / Rogue AP Honeypot",
                "description": f"SSID ('{ssid}') mimics a public hotspot lure while requiring zero authentication. Attackers deploy Rogue APs with lookalike names to intercept victim credentials."
            })
            penalty_score += 25

    # Check 2: Obsolete / Cracked WEP Encryption
    elif auth_raw == "WEP":
        red_flags.append({
            "rule": "OBSOLETE_WEP_CIPHER",
            "severity": "HIGH",
            "points": 45,
            "title": "Vulnerable WEP Encryption Standard",
            "description": "Wired Equivalent Privacy (WEP) has cryptographic weaknesses (RC4 IV collisions) and can be cracked in under 60 seconds using commodity tools."
        })
        penalty_score += 45

    # Check 3: Hidden SSID Network
    if is_hidden:
        red_flags.append({
            "rule": "HIDDEN_SSID_NETWORK",
            "severity": "MEDIUM",
            "points": 15,
            "title": "Hidden Network Broadcast (Suppressed SSID)",
            "description": "SSID is marked as hidden. Devices configured for hidden SSIDs broadcast probing packets continuously, leaking your connection history."
        })
        penalty_score += 15

    # Check 3b: Empty / suppressed SSID field (stealth beacon)
    if not ssid or not ssid.strip():
        red_flags.append({
            "rule": "EMPTY_SSID_FIELD",
            "severity": "MEDIUM",
            "points": 20,
            "title": "Empty / Suppressed SSID Field",
            "description": "SSID name field is empty. Stealth networks with blank SSIDs evade visual inspection and are commonly used in Evil Twin staging."
        })
        penalty_score += 20

    # Check 4: Weak / Common Dictionary Passphrase
    if not data["is_open"]:
        if password.lower() in WEAK_PASSWORDS or (len(password) > 0 and len(password) < 8):
            red_flags.append({
                "rule": "TRIVIAL_WEAK_PASSWORD",
                "severity": "HIGH",
                "points": 30,
                "title": "Trivially Guessable Wi-Fi Password",
                "description": f"Password ('{password}') is in common dictionary wordlists or shorter than 8 characters, susceptible to instant offline dictionary cracking."
            })
            penalty_score += 30

    final_score = min(100, penalty_score)

    # Assign Verdict
    if final_score <= 20:
        verdict = "SECURE"
        verdict_color = "#10b981"
        summary = f"Standard protected Wi-Fi network using {data['auth_type']} encryption."
    elif final_score <= 50:
        verdict = "WEAK SECURITY"
        verdict_color = "#f59e0b"
        summary = "Elevated network risk: Contains weak password or suppressed SSID. Proceed with basic security precautions."
    else:
        verdict = "CRITICAL RISK"
        verdict_color = "#ef4444"
        summary = "CRITICAL WIRELESS HAZARD: Unencrypted open network or Rogue AP signature. Connecting exposes your device to traffic sniffing."

    # Guidance
    guidance = []
    if verdict == "CRITICAL RISK":
        guidance.append("🚨 DO NOT CONNECT: This network has no encryption. Attackers can monitor your web traffic, DNS queries, and cookies.")
        guidance.append("If connection is unavoidable, ensure an authenticated, encrypted VPN (Virtual Private Network) is active BEFORE joining.")
        guidance.append("Never enter passwords, credit card numbers, or sensitive data on open Wi-Fi.")
    elif verdict == "WEAK SECURITY":
        guidance.append("Upgrade the Wi-Fi router passphrase to at least 12 random characters.")
        guidance.append("Migrate router settings from WEP or WPA to WPA2-AES or WPA3-SAE.")
    else:
        guidance.append(f"Network is encrypted with {data['auth_type']}.")
        guidance.append("Always verify the network belongs to the expected host or establishment before joining.")

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "summary": summary,
        "red_flags": red_flags,
        "parsed_data": data,
        "actionable_guidance": guidance
    }
