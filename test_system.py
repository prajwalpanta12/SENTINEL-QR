"""
SENTINEL-QR — Comprehensive System Test Suite v2.5
Tests all QR types, 36-feature extraction, ensemble model, and domain engines.
Run: python test_system.py
"""

import os
import sys
import time
import traceback

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Color codes for terminal
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

PASS = f"{GREEN}✅ PASS{RESET}"
FAIL = f"{RED}❌ FAIL{RESET}"
WARN = f"{YELLOW}⚠️  WARN{RESET}"

test_results = {"passed": 0, "failed": 0, "warnings": 0}


def run_test(name: str, fn):
    print(f"\n  {CYAN}Test:{RESET} {name}")
    try:
        result = fn()
        if result is True:
            print(f"  {PASS}")
            test_results["passed"] += 1
        elif result is False:
            print(f"  {FAIL}")
            test_results["failed"] += 1
        elif result == "WARN":
            print(f"  {WARN}")
            test_results["warnings"] += 1
        else:
            print(f"  {PASS}  (returned: {str(result)[:80]})")
            test_results["passed"] += 1
    except Exception as e:
        print(f"  {FAIL}  — Exception: {e}")
        traceback.print_exc()
        test_results["failed"] += 1


def header(title: str):
    print(f"\n{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'='*62}{RESET}")


# ═══════════════════════════════════════════════════════════════
#  PHASE 1: QR TYPE DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════
header("PHASE 1 — QR Type Detection Engine")
from qr_types import detect_qr_type, parse_upi_payload, parse_wifi_payload, parse_email_payload, parse_phone_payload, QRType

def test_url_detection():
    return detect_qr_type("https://www.google.com/search?q=cybersecurity") == QRType.URL

def test_upi_detection():
    return detect_qr_type("upi://pay?pa=test@ybl&pn=TestUser&am=100") == QRType.UPI

def test_wifi_detection():
    return detect_qr_type("WIFI:T:WPA;S:MyHomeNetwork;P:SecretPass123;;") == QRType.WIFI

def test_email_detection():
    return detect_qr_type("mailto:info@example.com?subject=Hello") == QRType.EMAIL

def test_phone_detection():
    return detect_qr_type("tel:+919876543210") == QRType.PHONE

def test_text_detection():
    return detect_qr_type("Just a plain text string") == QRType.TEXT

def test_upi_parse():
    parsed = parse_upi_payload("upi://pay?pa=merchant@okaxis&pn=ShopName&am=500.00&tn=Purchase&cu=INR")
    return ("payee_vpa" in parsed and parsed.get("payee_vpa") == "merchant@okaxis")

def test_wifi_parse():
    parsed = parse_wifi_payload("WIFI:T:WPA;S:CafeNet;P:cafepass123;;")
    return parsed.get("auth_type_raw") == "WPA" and parsed.get("ssid") == "CafeNet"

run_test("URL type detection", test_url_detection)
run_test("UPI type detection", test_upi_detection)
run_test("Wi-Fi type detection", test_wifi_detection)
run_test("Email type detection", test_email_detection)
run_test("Phone type detection", test_phone_detection)
run_test("Text type detection", test_text_detection)
run_test("UPI payload parsing — field extraction", test_upi_parse)
run_test("Wi-Fi payload parsing — field extraction", test_wifi_parse)


# ═══════════════════════════════════════════════════════════════
#  PHASE 2: UPI FRAUD DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════
header("PHASE 2 — UPI Fraud Detection Engine")
from upi_analyzer import analyze_upi_payload

def test_upi_fraud_cashback():
    """Reverse-charge cashback scam — should be FRAUD RISK."""
    r = analyze_upi_payload("upi://pay?pa=sbi.refund.portal@ybl&pn=SBI_Reward_Support&am=4999.00&tn=Claim_Your_Cashback_Reward&cu=INR")
    return r["verdict"] in ["FRAUD RISK", "SUSPICIOUS"] and r["risk_score"] >= 50

def test_upi_open_amount():
    """No amount specified — legitimate merchant scenario, safe."""
    r = analyze_upi_payload("upi://pay?pa=merchant@okaxis&pn=GroceryStore")
    return r["risk_score"] < 60

def test_upi_high_amount():
    """High pre-filled amount (₹50,000) — should flag."""
    r = analyze_upi_payload("upi://pay?pa=vendor@upi&pn=VendorName&am=50000.00&tn=payment")
    return r["risk_score"] >= 30  # at least flagged

def test_upi_blacklisted():
    """Blacklisted UPI ID."""
    r = analyze_upi_payload("upi://pay?pa=fake.sbi.refund@ybl&pn=Reward&am=1.00")
    return r["risk_score"] >= 20

def test_upi_safe_merchant():
    """Normal merchant QR — should be SAFE or low risk."""
    r = analyze_upi_payload("upi://pay?pa=zomato@icici&pn=Zomato_India&am=249.00&tn=Food_Order&cu=INR")
    return r["verdict"] in ["SAFE", "SUSPICIOUS"] and r["risk_score"] < 70

run_test("UPI Fraud — Cashback scam (reverse-charge) → FRAUD RISK", test_upi_fraud_cashback)
run_test("UPI — No amount QR → low risk", test_upi_open_amount)
run_test("UPI — High pre-filled amount → flagged", test_upi_high_amount)
run_test("UPI — Blacklisted pattern → flagged", test_upi_blacklisted)
run_test("UPI — Legitimate merchant QR → SAFE or low SUSPICIOUS", test_upi_safe_merchant)


# ═══════════════════════════════════════════════════════════════
#  PHASE 3: WI-FI SECURITY ANALYZER
# ═══════════════════════════════════════════════════════════════
header("PHASE 3 — Wi-Fi Security Analyzer")
from wifi_analyzer import analyze_wifi_payload

def test_wifi_open_rogue():
    """Open network with lure SSID → CRITICAL RISK."""
    r = analyze_wifi_payload("WIFI:T:nopass;S:Airport_Free_HighSpeed_WiFi;P:;;")
    return r["verdict"] in ["CRITICAL RISK", "FRAUD RISK", "MALICIOUS"] and r["risk_score"] >= 70

def test_wifi_wep_encryption():
    """WEP encryption (deprecated) → flagged."""
    r = analyze_wifi_payload("WIFI:T:WEP;S:OldRouter;P:12345;;")
    return r["risk_score"] >= 40

def test_wifi_wpa3_strong():
    """WPA3 with strong password → SAFE or low risk."""
    r = analyze_wifi_payload("WIFI:T:WPA3;S:HomeNetwork;P:C0mpl3x!P@ss#2024;;")
    return r["risk_score"] < 40

def test_wifi_weak_password():
    """Weak WPA password → flagged."""
    r = analyze_wifi_payload("WIFI:T:WPA;S:HomeNet;P:password;;")
    return r["risk_score"] >= 30

def test_wifi_hidden_ssid():
    """Hidden SSID (no name or empty) → suspicious."""
    r = analyze_wifi_payload("WIFI:T:WPA;S:;P:somepass;;")
    return r["risk_score"] >= 20

run_test("Wi-Fi — Open rogue AP with venue lure → CRITICAL RISK", test_wifi_open_rogue)
run_test("Wi-Fi — WEP encryption (deprecated) → flagged", test_wifi_wep_encryption)
run_test("Wi-Fi — WPA3 with strong password → SAFE", test_wifi_wpa3_strong)
run_test("Wi-Fi — Weak WPA password → flagged", test_wifi_weak_password)
run_test("Wi-Fi — Hidden SSID → suspicious", test_wifi_hidden_ssid)


# ═══════════════════════════════════════════════════════════════
#  PHASE 4: COMMUNICATION ANALYZER (EMAIL / PHONE)
# ═══════════════════════════════════════════════════════════════
header("PHASE 4 — Email & Phone Analyzers")
from communication_analyzer import analyze_email_payload, analyze_phone_payload

def test_email_phishing():
    """Phishing email QR → SUSPICIOUS or MALICIOUS."""
    r = analyze_email_payload("mailto:support@paypa1-security.xyz?subject=Account_Suspended_Action_Required")
    return r["verdict"] in ["SUSPICIOUS", "MALICIOUS"] and r["risk_score"] >= 40

def test_email_safe():
    """Normal support email → SAFE."""
    r = analyze_email_payload("mailto:support@company.com?subject=Help")
    return r["risk_score"] < 50

def test_phone_premium():
    """Premium/toll-free phishing number."""
    r = analyze_phone_payload("tel:+19001234567")
    return r["risk_score"] >= 30

def test_phone_normal():
    """Normal Indian mobile number → SAFE."""
    r = analyze_phone_payload("tel:+919876543210")
    return r["risk_score"] < 40

run_test("Email — Phishing lure (paypa1-security.xyz) → SUSPICIOUS/MALICIOUS", test_email_phishing)
run_test("Email — Normal support email → SAFE", test_email_safe)
run_test("Phone — Premium toll number → flagged", test_phone_premium)
run_test("Phone — Normal mobile → SAFE", test_phone_normal)


# ═══════════════════════════════════════════════════════════════
#  PHASE 5: 36-FEATURE EXTRACTION
# ═══════════════════════════════════════════════════════════════
header("PHASE 5 — 36-Feature URL Feature Extraction")
from features import extract_url_features, get_feature_vector, FEATURE_COLUMNS

def test_feature_count():
    feats = extract_url_features("https://www.google.com/search?q=test")
    return len(feats) == len(FEATURE_COLUMNS) and len(FEATURE_COLUMNS) == 36

def test_feature_columns_count():
    return len(FEATURE_COLUMNS) == 36

def test_ip_feature():
    feats = extract_url_features("http://192.168.1.1/login.php")
    return feats.get("has_ip_address") == 1

def test_https_feature():
    feats = extract_url_features("https://secure-site.com/")
    return feats.get("is_https") == 1

def test_entropy_feature():
    feats = extract_url_features("http://x7k2mq9p4v3z.xyz/admin")
    return feats.get("shannon_entropy", 0) > 3.0  # High-entropy domain

def test_get_feature_vector():
    vec = get_feature_vector("https://github.com/features/security")
    return len(vec) == 36

def test_sensitive_extension():
    feats = extract_url_features("http://evil.com/malware/payload.exe")
    return feats.get("has_sensitive_extension", 0) == 1

run_test("Feature count == 36", test_feature_count)
run_test("FEATURE_COLUMNS length == 36", test_feature_columns_count)
run_test("IP address detection feature", test_ip_feature)
run_test("HTTPS detection feature", test_https_feature)
run_test("Entropy calculation for DGA domain", test_entropy_feature)
run_test("get_feature_vector() returns vector of length 36", test_get_feature_vector)
run_test("Sensitive extension (.exe) detection", test_sensitive_extension)


# ═══════════════════════════════════════════════════════════════
#  PHASE 6: HEURISTIC RULE ENGINE
# ═══════════════════════════════════════════════════════════════
header("PHASE 6 — Heuristic Rule Engine (16 Rules)")
from rules import evaluate_rules

def test_rules_ip_based():
    feats = extract_url_features("http://192.168.1.100:8080/verify")
    r = evaluate_rules("http://192.168.1.100:8080/verify", feats)
    # Should trigger IP rule and port rule
    return r["rule_count"] >= 1 and r["rule_score"] >= 10

def test_rules_clean_url():
    feats = extract_url_features("https://www.wikipedia.org/wiki/Python")
    r = evaluate_rules("https://www.wikipedia.org/wiki/Python", feats)
    return r["rule_count"] == 0 and r["rule_score"] == 0

def test_rules_phishing_keywords():
    url = "http://secure-login-verify.com/account/update.php?token=abc"
    feats = extract_url_features(url)
    r = evaluate_rules(url, feats)
    return r["rule_count"] >= 1

def test_rules_triggered_rules_structure():
    url = "http://192.168.1.1/phish?token=xyz&redirect=http://evil.com"
    feats = extract_url_features(url)
    r = evaluate_rules(url, feats)
    triggered = r["triggered_rules"]
    return all("name" in t and "severity" in t and "points" in t for t in triggered)

run_test("Rules — IP-based URL triggers ≥1 rule", test_rules_ip_based)
run_test("Rules — Clean Wikipedia URL triggers 0 rules", test_rules_clean_url)
run_test("Rules — Phishing keywords trigger rules", test_rules_phishing_keywords)
run_test("Rules — Triggered rule objects have correct schema", test_rules_triggered_rules_structure)


# ═══════════════════════════════════════════════════════════════
#  PHASE 7: ML MODEL (ENSEMBLE)
# ═══════════════════════════════════════════════════════════════
header("PHASE 7 — ML Model Prediction (Ensemble)")
from model import predict_threat, get_model_metadata

def test_ml_safe_url():
    r = predict_threat("https://www.wikipedia.org/wiki/Machine_learning")
    return r["malicious_prob"] < 0.55 and "confidence_pct" in r

def test_ml_malicious_url():
    r = predict_threat("http://192.168.1.100:8080/phishing/steal-credentials.php")
    return r["malicious_prob"] > 0.4 and r.get("prediction_label") in [0, 1]

def test_ml_result_schema():
    r = predict_threat("https://github.com/features/security")
    required = ["malicious_prob", "prediction_label", "model_used", "confidence_pct"]
    return all(k in r for k in required)

def test_metadata_structure():
    m = get_model_metadata()
    has_ensemble = "ensemble_metrics" in m and "xgboost_metrics" in m
    has_feat_count = ("n_features" in m) or ("feature_count" in m)
    return has_ensemble and has_feat_count

def test_metadata_is_not_fabricated_when_present():
    """The shipped metadata must describe the actual 943-row corpus."""
    import csv
    meta = get_model_metadata()
    with open(os.path.join(BASE_DIR, "data", "dataset.csv"), newline="", encoding="utf-8") as f:
        rows = sum(1 for _ in csv.DictReader(f))
    return meta.get("dataset_samples") == rows and rows == 943

run_test("ML — Safe URL → low malicious_prob", test_ml_safe_url)
run_test("ML — IP phishing URL → elevated malicious_prob", test_ml_malicious_url)
run_test("ML — Result dict has required schema keys", test_ml_result_schema)
run_test("Metadata — model_metadata.joblib loads correctly", test_metadata_structure)
run_test("Metadata — sample count matches the shipped corpus", test_metadata_is_not_fabricated_when_present)


# ═══════════════════════════════════════════════════════════════
#  PHASE 8: HYBRID RISK SCORE ENGINE + EXPLAINABILITY
# ═══════════════════════════════════════════════════════════════
header("PHASE 8 — Hybrid Risk Score + Explainability")
from explainability import calculate_hybrid_risk_score, generate_explanation

def test_hybrid_safe():
    r = calculate_hybrid_risk_score(0.05, 0, {"is_blacklisted": False}, qr_context_risk=0)
    return r["final_score"] < 30 and r["verdict"] == "SAFE"

def test_hybrid_malicious():
    r = calculate_hybrid_risk_score(0.95, 80, {"is_blacklisted": True, "urlhaus": {"status": "malware"}}, qr_context_risk=70)
    return r["final_score"] >= 60 and r["verdict"] == "MALICIOUS"

def test_explanation_structure():
    risk_info = calculate_hybrid_risk_score(0.7, 50, {"is_blacklisted": False}, qr_context_risk=20)
    feats = extract_url_features("http://x7k2mq9p4v.xyz/login")
    url_f = extract_url_features("http://x7k2mq9p4v.xyz/login")
    url_feats_res = evaluate_rules("http://x7k2mq9p4v.xyz/login", url_f)
    xai = generate_explanation(risk_info, url_feats_res["triggered_rules"], feats, {"is_blacklisted": False})
    return "top_5_factors" in xai and "guidance" in xai and "why_flagged" in xai

def test_rule_floor_is_monotone():
    """A higher raw score must not fall below a lower raw score with equal rules."""
    low = calculate_hybrid_risk_score(0.08, 100, {"is_blacklisted": False}, qr_context_risk=0)["final_score"]
    high = calculate_hybrid_risk_score(0.20, 100, {"is_blacklisted": False}, qr_context_risk=0)["final_score"]
    return low >= 50 and high >= low

run_test("Hybrid — Low threat → SAFE score < 30", test_hybrid_safe)
run_test("Hybrid — High threat → MALICIOUS score ≥ 60", test_hybrid_malicious)
run_test("Explanation — Returns top_5_factors, guidance, why_flagged", test_explanation_structure)
run_test("Hybrid — Rule floor is monotone in the raw score", test_rule_floor_is_monotone)


# ═══════════════════════════════════════════════════════════════
#  PHASE 9: PDF REPORT GENERATION
# ═══════════════════════════════════════════════════════════════
header("PHASE 9 — PDF Audit Report Generation")
from utils import generate_security_pdf_report

def test_pdf_url_report():
    pdf = generate_security_pdf_report(
        payload="https://phishing-example.com/verify.php",
        qr_type="Web URL",
        risk_score=85,
        verdict="MALICIOUS",
        ml_prob=0.87,
        rule_score=70,
        triggered_rules=[{"name": "RULE_PHISHING_KEYWORDS", "severity": "HIGH",
                          "points": 20, "reason": "Suspicious keyword detected"}],
        threat_intel={"is_blacklisted": True, "urlhaus": {"status": "malware"}}
    )
    return isinstance(pdf, bytes) and len(pdf) > 2000 and pdf[:4] == b'%PDF'

def test_pdf_upi_report():
    pdf = generate_security_pdf_report(
        payload="upi://pay?pa=fraud@ybl&pn=FraudUser&am=9999.00",
        qr_type="UPI Payment",
        risk_score=90,
        verdict="FRAUD RISK",
        ml_prob=0.0,
        rule_score=90,
        triggered_rules=[],
        threat_intel={"is_blacklisted": False}
    )
    return isinstance(pdf, bytes) and len(pdf) > 2000

def test_pdf_escapes_untrusted_payload():
    """Markup in a decoded payload or rule description must be escaped."""
    import hashlib
    import io
    from unittest.mock import patch

    from pypdf import PdfReader
    import utils

    payload = 'https://example.com/?q=<script>alert(1)</script>&x="y"'
    description = '<b>INJECTED</b><script>alert(2)</script>'
    seen = []
    original_escape = utils.xml_escape

    def spy(value):
        seen.append(str(value))
        return original_escape(value)

    with patch.object(utils, "xml_escape", side_effect=spy):
        pdf = utils.generate_security_pdf_report(
            payload=payload,
            qr_type="Web URL",
            risk_score=50,
            verdict="SUSPICIOUS",
            ml_prob=0.5,
            rule_score=50,
            triggered_rules=[{
                "id": "R-TEST",
                "severity": "HIGH",
                "points": 10,
                "description": description,
            }],
            threat_intel={"is_blacklisted": False},
        )
    if not (isinstance(pdf, bytes) and len(pdf) > 2000 and pdf[:4] == b"%PDF"):
        return False
    reader = PdfReader(io.BytesIO(pdf))
    text = "".join((reader.pages[0].extract_text() or "").split())
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return (
        payload in seen
        and description in seen
        and digest in text
        and "notadigitalsignature" in text
    )

from threat_intel import _feed_state

def test_intel_distinguishes_offline_from_clean():
    offline = _feed_state({"threat_level": "OFFLINE", "status": "URLhaus Live Query Skipped (Offline Mode)"})
    clean = _feed_state({"threat_level": "CLEAN", "status": "Clean in URLhaus Threat Feed"})
    missing_key = _feed_state({"status": "No VT API Key Configured"})
    return offline == "unavailable" and clean == "clean" and missing_key == "not_configured"

import threat_intel
from threat_intel import query_urlhaus, summarize_intel_status


class _FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def _with_fake_post(fake, fn):
    """Run fn with requests.post replaced and URLHAUS_AUTH_KEY unset; no network is used."""
    original, saved_env = threat_intel.requests.post, os.environ.pop("URLHAUS_AUTH_KEY", None)
    threat_intel.requests.post = fake
    try:
        return fn()
    finally:
        threat_intel.requests.post = original
        if saved_env is not None:
            os.environ["URLHAUS_AUTH_KEY"] = saved_env


def test_urlhaus_without_key_is_not_configured():
    calls = []
    res = _with_fake_post(lambda *a, **k: calls.append(k),
                          lambda: query_urlhaus("http://example.com/x"))
    return not calls and _feed_state(res) == "not_configured"


def test_urlhaus_sends_auth_key_header():
    seen = {}

    def fake(url, data=None, headers=None, timeout=None):
        seen.update(headers or {})
        return _FakeResponse(200, {"query_status": "no_results"})
    res = _with_fake_post(fake, lambda: query_urlhaus("http://example.com/x", auth_key="test-key"))
    return seen.get("Auth-Key") == "test-key" and _feed_state(res) == "clean"


def test_urlhaus_rejected_key_is_unavailable():
    res = _with_fake_post(lambda *a, **k: _FakeResponse(401),
                          lambda: query_urlhaus("http://example.com/x", auth_key="bad"))
    return _feed_state(res) == "unavailable"


def test_intel_card_never_says_clean_without_a_query():
    none_queried = summarize_intel_status({"feeds_available": [], "feeds_unavailable": ["URLhaus"],
                                           "feeds_not_configured": ["VirusTotal", "Google Safe Browsing"]})
    partial = summarize_intel_status({"feeds_available": ["URLhaus"], "feeds_unavailable": [],
                                      "feeds_not_configured": ["VirusTotal"]})
    full = summarize_intel_status({"feeds_available": ["URLhaus", "VirusTotal", "Google Safe Browsing"]})
    hit = summarize_intel_status({"feeds_available": ["URLhaus"], "is_blacklisted": True})
    return (none_queried["label"] == "Not checked" and none_queried["tone"] == "y"
            and partial["label"] == "No match" and partial["tone"] == "y" and "only" in partial["detail"]
            and full["tone"] == "g" and full["detail"] == "URLhaus + VT + GSB"
            and hit["label"] == "Blacklisted" and "Clean" not in str([none_queried, partial, full, hit]))


run_test("PDF — URL Malicious report generates valid PDF bytes", test_pdf_url_report)
run_test("PDF — UPI Fraud report generates valid PDF bytes", test_pdf_upi_report)
run_test("PDF — Untrusted payload markup is escaped", test_pdf_escapes_untrusted_payload)
run_test("Threat intel — Offline, clean, and unconfigured are distinct", test_intel_distinguishes_offline_from_clean)
run_test("Threat intel — URLhaus without Auth-Key makes no request, reports not configured", test_urlhaus_without_key_is_not_configured)
run_test("Threat intel — URLhaus sends the Auth-Key header", test_urlhaus_sends_auth_key_header)
run_test("Threat intel — Rejected URLhaus key is reported unavailable", test_urlhaus_rejected_key_is_unavailable)
run_test("Threat intel — UI card never shows a clean result without a successful query", test_intel_card_never_says_clean_without_a_query)


# ═══════════════════════════════════════════════════════════════
#  PHASE 10: QR DECODE ENGINE
# ═══════════════════════════════════════════════════════════════
header("PHASE 10 — QR Decode Engine")
from utils import decode_qr_code
from PIL import Image

def test_decode_from_generated_qr():
    """Decode a QR from test_samples if it exists."""
    sample_path = os.path.join(BASE_DIR, "test_samples", "1_safe_wikipedia.png")
    if not os.path.exists(sample_path):
        return "WARN"  # Demo QRs not generated yet, skip
    img = Image.open(sample_path)
    decoded, annotated, engine = decode_qr_code(img)
    return decoded is not None and "wikipedia" in decoded.lower()

def test_decode_upi_qr():
    """Decode UPI demo QR if it exists."""
    path = os.path.join(BASE_DIR, "test_samples", "7_upi_fraud.png")
    if not os.path.exists(path):
        return "WARN"
    img = Image.open(path)
    decoded, _, _ = decode_qr_code(img)
    return decoded is not None and "upi://" in decoded.lower()

run_test("Decode — Wikipedia QR from demo samples", test_decode_from_generated_qr)
run_test("Decode — UPI Fraud QR from demo samples", test_decode_upi_qr)


# ═══════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*62}{RESET}")
print(f"{BOLD}  TEST SUITE COMPLETE — SENTINEL-QR v2.5{RESET}")
print(f"{BOLD}{'='*62}{RESET}")
total = test_results["passed"] + test_results["failed"] + test_results["warnings"]
print(f"\n  {GREEN}✅ Passed  : {test_results['passed']}{RESET}")
print(f"  {RED}❌ Failed  : {test_results['failed']}{RESET}")
print(f"  {YELLOW}⚠️  Warnings: {test_results['warnings']}{RESET}")
print(f"\n  Total Tests: {total}")

if test_results["failed"] == 0:
    print(f"\n  {GREEN}{BOLD}ALL TESTS PASSED — wiring and behaviour checks complete.{RESET}")
else:
    print(f"\n  {RED}{BOLD}⚠️  {test_results['failed']} test(s) failed — review failures above.{RESET}")
    print(f"  Tip: If models are missing, run:")
    print(f"       python data/create_dataset.py")
    print(f"       python train_model.py")
    print(f"  Then re-run: python test_system.py\n")

sys.exit(0 if test_results["failed"] == 0 else 1)
