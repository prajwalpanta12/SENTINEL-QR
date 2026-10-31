"""
AI-Based QR Code Threat Analyzer
Module: upi_analyzer.py
Purpose: UPI Payment Fraud Detection Engine.
         Analyzes Unified Payments Interface (UPI) QR codes for reverse-charge scams,
         mule VPAs, deceptive institutional impersonation, and fraudulent auto-debit entrapment.
"""

import re
from qr_types import parse_upi_payload

# Mock Threat Intelligence: Blacklisted UPI IDs and known mule handles
BLACKLISTED_VPAS = {
    "sbi.refund.portal@ybl",
    "paytm_cashback_care@paytm",
    "electricity_bill_officer@axl",
    "npci.rewards.support@okhdfcbank",
    "customer.care.airtel@oksbi",
    "googlepay.refund.desk@okaxis",
    "lottery.claim.officer@ybl",
    "olx.safety.deposit@icici",
    "kyc.update.support@paytm",
    "amazon.voucher.claim@upi"
}

# Scam Lure Keywords in Transaction Note (Reverse-Charge Scam)
CASHBACK_LURE_KEYWORDS = [
    "cashback", "refund", "reward", "prize", "lottery", "bonus", "claim",
    "congratulations", "win", "winner", "credit", "receive", "disbursement",
    "subsidy", "kyc", "unlock", "activation", "approved"
]

# Trusted Merchant Category Codes (NPCI MCC)
LEGIT_MERCHANT_MCCS = {
    "5411", "5812", "5814", "5311", "5912", "5541", "4111", "4814", "4900"
}

# Institutional Brand Names frequently spoofed in UPI Phishing
INSTITUTIONAL_BRANDS = [
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "google pay",
    "amazon", "flipkart", "npci", "electricity", "bsnl", "airtel", "jio",
    "income tax", "customs", "cyber cell", "olx"
]


def analyze_upi_payload(raw_text: str) -> dict:
    """
    Executes deep forensic inspection of a UPI payment QR payload.
    Returns:
        dict: {
            'risk_score': int (0-100),
            'verdict': str ('SAFE', 'SUSPICIOUS', 'FRAUD RISK'),
            'verdict_color': str,
            'red_flags': list[dict],
            'parsed_data': dict,
            'actionable_guidance': list[str],
            'summary': str
        }
    """
    data = parse_upi_payload(raw_text)
    red_flags = []
    penalty_score = 0

    vpa = data["payee_vpa"].lower()
    name = data["payee_name"].lower()
    note = data["note"].lower()
    amount = data["amount"]
    mc = data["merchant_code"]

    # Check 1: Blacklisted Mule VPA
    if vpa in BLACKLISTED_VPAS:
        red_flags.append({
            "rule": "BLACKLISTED_UPI_VPA",
            "severity": "CRITICAL",
            "points": 100,
            "title": "Confirmed Malicious Mule VPA",
            "description": f"The recipient VPA '{data['payee_vpa']}' matches active cybercrime threat intelligence reports."
        })
        penalty_score += 100

    # Check 2: Reverse-Charge / Fake Cashback Auto-Debit Trap (CRITICAL SCAM)
    # If amount is set AND note mentions cashback/refund/prize
    lure_found = [kw for kw in CASHBACK_LURE_KEYWORDS if kw in note or kw in name]
    if amount > 0 and lure_found:
        red_flags.append({
            "rule": "REVERSE_CHARGE_CASHBACK_SCAM",
            "severity": "CRITICAL",
            "points": 65,
            "title": "Reverse-Charge Auto-Debit Trap Detected",
            "description": f"The QR embeds an auto-debit of ₹{amount:,.2f} while using lure text ('{', '.join(lure_found)}'). Entering your PIN will DEBIT money from your bank account, not credit it!"
        })
        penalty_score += 65

    # Check 3: High Unverified Auto-Debit Amount
    if amount >= 5000.0 and not data["is_merchant"]:
        red_flags.append({
            "rule": "HIGH_AUTO_DEBIT_AMOUNT",
            "severity": "HIGH",
            "points": 35,
            "title": "High Unverified Auto-Debit Request",
            "description": f"QR requests immediate auto-debit of ₹{amount:,.2f} without a registered Merchant Category Code (MCC)."
        })
        penalty_score += 35
    elif amount >= 2000.0 and not data["is_merchant"]:
        red_flags.append({
            "rule": "ELEVATED_AUTO_DEBIT_AMOUNT",
            "severity": "MEDIUM",
            "points": 20,
            "title": "Elevated Personal Payment Amount",
            "description": f"QR pre-populates an auto-debit of ₹{amount:,.2f} to an individual personal VPA."
        })
        penalty_score += 20

    # Check 4: Payee Name vs. VPA Handle Discrepancy (Brand Impersonation)
    brand_in_name = any(brand in name for brand in INSTITUTIONAL_BRANDS)
    brand_in_vpa = any(brand in vpa for brand in INSTITUTIONAL_BRANDS)

    if brand_in_name and not brand_in_vpa and not data["is_merchant"]:
        red_flags.append({
            "rule": "NAME_VPA_DISCREPANCY",
            "severity": "HIGH",
            "points": 40,
            "title": "Deceptive Brand Impersonation in Payee Name",
            "description": f"Payee name displays institutional brand ('{data['payee_name']}'), but the VPA ('{data['payee_vpa']}') routes funds to an unverified private individual."
        })
        penalty_score += 40

    # Check 5: Suspicious Pseudo-Random / DGA VPA Handle
    vpa_user = data["payee_user"]
    # Exempt plain Indian mobile-number handles (10 digits starting 6-9, optional 91 prefix),
    # which are the default VPA format of several UPI apps and are not disposable by themselves.
    is_mobile_handle = re.fullmatch(r"(91)?[6-9]\d{9}", vpa_user) is not None
    if (not is_mobile_handle) and len(vpa_user) >= 10 and re.match(r"^[a-z0-9]+$", vpa_user) and sum(c.isdigit() for c in vpa_user) >= 5:
        red_flags.append({
            "rule": "HIGH_ENTROPY_VPA",
            "severity": "MEDIUM",
            "points": 20,
            "title": "Suspicious Random / Disposable VPA Pattern",
            "description": "VPA user handle consists of automated alphanumeric sequence typical of disposable money-mule accounts."
        })
        penalty_score += 20

    # Check 6: Suspicious Keywords in VPA
    if any(k in vpa for k in ["refund", "care", "support", "tollfree", "reward", "lottery"]):
        red_flags.append({
            "rule": "SUSPICIOUS_VPA_KEYWORD",
            "severity": "MEDIUM",
            "points": 25,
            "title": "Social Engineering Keywords in VPA",
            "description": "VPA address contains deceptive support or refund keywords designed to look like an official service desk."
        })
        penalty_score += 25

    # Check 7: Reference URL Parameter Present (Quishing Redirection)
    if data["ref_url"]:
        red_flags.append({
            "rule": "EXTERNAL_URL_IN_UPI",
            "severity": "MEDIUM",
            "points": 15,
            "title": "External URL Reference Embedded",
            "description": f"UPI QR embeds an external web link ({data['ref_url']}) which could trigger secondary web phishing."
        })
        penalty_score += 15

    # Calculate Normalized Risk Score
    final_score = min(100, penalty_score)

    # Assign Verdict
    if final_score <= 25:
        verdict = "SAFE"
        verdict_color = "#10b981"
        summary = "Standard UPI payment recipient. No deceptive reverse-charge or impersonation markers detected."
    elif final_score <= 55:
        verdict = "SUSPICIOUS"
        verdict_color = "#f59e0b"
        summary = "Elevated payment risk: Contains auto-debit amount or minor identity discrepancies. Verify recipient manually before payment."
    else:
        verdict = "FRAUD RISK"
        verdict_color = "#ef4444"
        summary = "CRITICAL UPI FRAUD DETECTED: This QR displays signatures of a reverse-charge auto-debit scam or spoofed institution."

    # Actionable Guidance
    guidance = []
    if verdict == "FRAUD RISK":
        guidance.append("🚨 DO NOT SCAN OR PAY: Entering your UPI PIN will DEBIT money from your bank account.")
        guidance.append("⚠️ Golden Rule of UPI: You NEVER need to enter a UPI PIN to receive money, cashback, or refunds.")
        guidance.append(f"Report VPA '{data['payee_vpa']}' on the National Cyber Crime Reporting Portal (1930) or your banking app.")
    elif verdict == "SUSPICIOUS":
        guidance.append("Check the exact payee name displayed on your banking screen before authorising.")
        guidance.append(f"Confirm whether you intended to send ₹{amount:,.2f} to this individual.")
        guidance.append("Do not make payments to unknown personal handles claiming to represent utility companies or banks.")
    else:
        guidance.append("Verify the recipient name and amount on your payment app before entering your UPI PIN.")
        guidance.append("Only pay merchants you physically recognize or have verified invoices for.")

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "summary": summary,
        "red_flags": red_flags,
        "parsed_data": data,
        "actionable_guidance": guidance
    }
