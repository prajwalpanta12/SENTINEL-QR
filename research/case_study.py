"""Case-study evidence: decode all demo QRs and run the full pipeline end-to-end."""
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from PIL import Image  # noqa: E402

from utils import decode_qr_code, validate_and_clean_url, check_ssl_certificate  # noqa: E402
from qr_types import detect_qr_type, QRType  # noqa: E402
from features import extract_url_features  # noqa: E402
from rules import evaluate_rules  # noqa: E402
from model import predict_threat  # noqa: E402
from threat_intel import query_threat_intelligence  # noqa: E402
from explainability import calculate_hybrid_risk_score, generate_explanation  # noqa: E402
from upi_analyzer import analyze_upi_payload  # noqa: E402
from wifi_analyzer import analyze_wifi_payload  # noqa: E402
from communication_analyzer import analyze_email_payload, analyze_phone_payload  # noqa: E402

SAMPLES = os.path.join(BASE, "test_samples")
out = []

for name in sorted(os.listdir(SAMPLES)):
    if not name.lower().endswith(".png"):
        continue
    path = os.path.join(SAMPLES, name)
    img = Image.open(path).convert("RGB")
    text, annotated, engine = decode_qr_code(img)
    rec = {"file": name, "decoded": bool(text), "payload": text, "decoder": engine}
    if not text:
        out.append(rec)
        continue
    qt = detect_qr_type(text)
    rec["qr_type"] = str(qt)
    if qt == QRType.URL:
        v = validate_and_clean_url(text)
        rec["url_valid"] = v["is_valid_url"]
        if v["is_valid_url"]:
            u = v["cleaned_url"]
            f = extract_url_features(u)
            r = evaluate_rules(u, f)
            m = predict_threat(u)
            t = query_threat_intelligence(u)
            h = calculate_hybrid_risk_score(m["malicious_prob"], r["rule_score"], t, 0)
            xai = generate_explanation(h, r["triggered_rules"], f, t)
            try:
                dom = u.split("/")[2]
                ssl_info = check_ssl_certificate(dom)
            except Exception:
                ssl_info = {}
            rec.update({
                "cleaned_url": u,
                "ml_prob": m["malicious_prob"],
                "ml_confidence": m["confidence_pct"],
                "rule_score": r["rule_score"],
                "rules_triggered": [x["id"] for x in r["triggered_rules"]],
                "intel_status": t.get("status"),
                "intel_blacklisted": t.get("is_blacklisted"),
                "final_score": h["final_score"],
                "verdict": h["verdict"],
                "ml_component": h["ml_component"],
                "rule_component": h["rule_component"],
                "intel_component": h["intel_component"],
                "top_factors": [x["factor"] for x in xai["top_5_factors"]],
                "ssl_valid": ssl_info.get("ssl_valid"),
            })
    else:
        fn = {QRType.UPI: analyze_upi_payload, QRType.WIFI: analyze_wifi_payload,
              QRType.EMAIL: analyze_email_payload, QRType.PHONE: analyze_phone_payload}.get(qt)
        if fn:
            rr = fn(text)
            rec.update({
                "verdict": rr.get("verdict"),
                "risk_score": rr.get("risk_score"),
                "red_flags": [fl.get("title") for fl in rr.get("red_flags", [])],
                "summary": rr.get("summary"),
            })
    out.append(rec)

dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "experiments", "case_study.json")
with open(dst, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)

for r in out:
    print(f"{r['file']:<34} {r.get('qr_type','-'):<8} "
          f"{r.get('verdict', '-'):<14} {str(r.get('final_score', r.get('risk_score', '-'))):>4} "
          f"ML={r.get('ml_prob', '-')} R={r.get('rule_score', '-')} {r.get('payload','')[:48]}")
