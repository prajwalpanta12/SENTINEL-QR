"""
AI-Based QR Code Threat Analyzer
Module: qr_types.py
Purpose: Multi-Type QR Code Payload Classification and Structured Parsers.
         Classifies payloads into URL, UPI, WiFi, Email, Phone, or Plain Text
         and extracts structured forensic fields for domain-specific security analysis.
"""

import re
import urllib.parse


class QRType:
    URL = "URL"
    UPI = "UPI"
    WIFI = "WIFI"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    TEXT = "TEXT"


def detect_qr_type(raw_text: str) -> str:
    """
    Classifies the raw decoded QR string into a high-level payload category.
    Returns:
        str: One of QRType (URL, UPI, WIFI, EMAIL, PHONE, TEXT)
    """
    if not raw_text or not isinstance(raw_text, str):
        return QRType.TEXT

    raw = raw_text.strip()
    raw_lower = raw.lower()

    # 1. UPI Payment Protocol (upi://pay?pa=... or contains upi payment query format)
    if raw_lower.startswith("upi://") or (("pa=" in raw_lower or "upi:" in raw_lower) and "@" in raw):
        return QRType.UPI

    # 2. Wi-Fi Network Configuration (WIFI:T:...;S:...;P:...;;)
    if raw.upper().startswith("WIFI:") or raw_lower.startswith("wifi:"):
        return QRType.WIFI

    # 3. Email Protocol (mailto:user@domain.com?subject=...)
    if raw_lower.startswith("mailto:") or re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", raw):
        return QRType.EMAIL

    # 4. Phone Dial Protocol (tel:+1234567890)
    if raw_lower.startswith("tel:") or re.match(r"^(\+?\d{1,4}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}$", raw):
        return QRType.PHONE

    # 5. Web URL (http://, https://, or standard domain string)
    if raw_lower.startswith("http://") or raw_lower.startswith("https://"):
        return QRType.URL
    if raw_lower.startswith("www.") or re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", raw):
        return QRType.URL

    # 6. Fallback: Generic Plain Text or Custom Payload
    return QRType.TEXT


def parse_upi_payload(raw_text: str) -> dict:
    """
    Extracts forensic fields from an Indian NPCI / BHIM UPI payment URI.
    Format: upi://pay?pa=recipient@bank&pn=MerchantName&am=1500.00&tn=Note&cu=INR&mc=1234
    """
    raw = raw_text.strip()
    # Normalize scheme
    if not raw.lower().startswith("upi://"):
        if "pa=" in raw:
            raw = "upi://pay?" + raw.split("?", 1)[-1]
        else:
            raw = "upi://pay?" + raw

    parsed = urllib.parse.urlparse(raw)
    query_params = urllib.parse.parse_qs(parsed.query)

    def get_val(key, default=""):
        return query_params.get(key, [default])[0].strip()

    pa = get_val("pa")  # Payee VPA / Address (Mandatory)
    pn = get_val("pn")  # Payee Name
    am = get_val("am")  # Transaction Amount (Optional in dynamic, empty in static)
    tn = get_val("tn")  # Transaction Note / Remark
    mc = get_val("mc")  # Merchant Category Code (4 digits)
    tid = get_val("tid") or get_val("tr")  # Transaction ID / Reference
    cu = get_val("cu", "INR")  # Currency
    ref_url = get_val("url")  # Reference URL

    # Extract VPA handle/bank
    vpa_user = ""
    vpa_provider = ""
    if "@" in pa:
        parts = pa.split("@", 1)
        vpa_user = parts[0]
        vpa_provider = parts[1].lower()

    # Float conversion for amount if present
    parsed_amount = 0.0
    try:
        if am:
            parsed_amount = float(am)
    except ValueError:
        pass

    return {
        "raw_uri": raw,
        "payee_vpa": pa,
        "payee_user": vpa_user,
        "vpa_provider": vpa_provider,
        "payee_name": pn,
        "amount": parsed_amount,
        "amount_str": am,
        "note": tn,
        "merchant_code": mc,
        "transaction_id": tid,
        "currency": cu,
        "ref_url": ref_url,
        "is_static": parsed_amount == 0.0,
        "is_merchant": len(mc) > 0 and mc.isdigit()
    }


def parse_wifi_payload(raw_text: str) -> dict:
    """
    Parses Wi-Fi network configuration QR payload.
    Format: WIFI:T:<WPA|WEP|nopass>;S:<SSID>;P:<Password>;H:<true|false>;;
    """
    raw = raw_text.strip()
    clean = raw
    if clean.upper().startswith("WIFI:"):
        clean = clean[5:]
    if clean.endswith(";;"):
        clean = clean[:-2]
    elif clean.endswith(";"):
        clean = clean[:-1]

    tokens = clean.split(";")
    data = {"auth_type": "nopass", "ssid": "", "password": "", "hidden": False}

    for token in tokens:
        if not token:
            continue
        if ":" in token:
            k, v = token.split(":", 1)
            k = k.strip().upper()
            v = v.strip()
            if k == "T":
                data["auth_type"] = v.upper() if v else "nopass"
            elif k == "S":
                data["ssid"] = v
            elif k == "P":
                data["password"] = v
            elif k == "H":
                data["hidden"] = v.lower() in ["true", "1", "yes"]

    # Normalize authentication type
    auth_normalized = data["auth_type"].upper()
    if auth_normalized in ["", "NOPASS", "NONE", "OPEN"]:
        auth_normalized = "OPEN (No Encryption)"
    elif auth_normalized in ["WPA", "WPA2", "WPA/WPA2", "WPA3"]:
        auth_normalized = auth_normalized
    elif auth_normalized == "WEP":
        auth_normalized = "WEP (Legacy Deprecated)"

    return {
        "raw_string": raw,
        "auth_type_raw": data["auth_type"],
        "auth_type": auth_normalized,
        "ssid": data["ssid"],
        "password": data["password"],
        "hidden": data["hidden"],
        "password_length": len(data["password"]),
        "is_open": data["auth_type"].upper() in ["", "NOPASS", "NONE", "OPEN"]
    }


def parse_email_payload(raw_text: str) -> dict:
    """
    Parses mailto: email QR payloads.
    Format: mailto:security@domain.com?subject=Alert&body=ClickHere
    """
    raw = raw_text.strip()
    recipient = ""
    subject = ""
    body = ""

    if raw.lower().startswith("mailto:"):
        parsed = urllib.parse.urlparse(raw)
        recipient = parsed.path
        params = urllib.parse.parse_qs(parsed.query)
        subject = params.get("subject", [""])[0]
        body = params.get("body", [""])[0]
    else:
        recipient = raw

    return {
        "raw": raw,
        "recipient": recipient,
        "domain": recipient.split("@")[-1].lower() if "@" in recipient else "",
        "subject": subject,
        "body": body
    }


def parse_phone_payload(raw_text: str) -> dict:
    """
    Parses tel: phone dial QR payloads.
    Format: tel:+18005550199
    """
    raw = raw_text.strip()
    phone_clean = raw
    if phone_clean.lower().startswith("tel:"):
        phone_clean = phone_clean[4:]

    # Remove non-numeric except leading +
    digits_only = re.sub(r"[^\d+]", "", phone_clean)

    return {
        "raw": raw,
        "phone_number": digits_only,
        "is_international": digits_only.startswith("+"),
        "digits_length": len(re.sub(r"\D", "", digits_only))
    }
