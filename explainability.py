"""
AI-Based QR Code Threat Analyzer
Module: explainability.py
Purpose: Explainable AI (XAI) & Upgraded Hybrid Risk Scoring Engine.
         Calculates a transparent hybrid risk score using the formula:
           Risk Score = (ML * 50) + (Rules * 30) + (Intel * 10) + (QRContextRisk * 10)
         Extracts Top 5 Risk Factors with color-coded impact, plain-English "Why Flagged?",
         and actionable security guidance.
"""

def calculate_hybrid_risk_score(ml_prob: float, rule_score: int, threat_intel: dict, qr_context_risk: int = 0) -> dict:
    """
    Computes a transparent hybrid risk score (0-100) using the formula:
        Risk Score = (ML * 50) + (Rules * 30) + (Intel * 10) + (QRContextRisk * 10)

    The rule floor is monotone in the rule score: every rule score at or above
    50 maps to at least 35 + 0.3 * (rule_score - 50).  The previous version
    applied the floor only when the raw score was below 35, which allowed a
    higher raw score to produce a lower final score.
    """
    intel_penalty = threat_intel.get("penalty_score", 0)
    is_blacklisted = threat_intel.get("is_blacklisted", False)

    # Individual Weighted Components
    ml_component = ml_prob * 50.0                                 # Max 50 pts
    rule_component = (min(100, rule_score) / 100.0) * 30.0        # Max 30 pts
    intel_component = (min(100, intel_penalty) / 100.0) * 10.0    # Max 10 pts
    context_component = (min(100, qr_context_risk) / 100.0) * 10.0# Max 10 pts

    raw_score = ml_component + rule_component + intel_component + context_component

    # Heuristic minimum floor: if the URL triggers at least 50 heuristic
    # points, lift the score to the corresponding floor.  The comparison is
    # against the floor itself, not a fixed 35, so the final score cannot
    # decrease when the rule evidence increases.
    if rule_score >= 50:
        rule_floor = 35.0 + (rule_score - 50) * 0.3
        if raw_score < rule_floor:
            raw_score = rule_floor

    # Threat Intelligence Override
    if is_blacklisted:
        raw_score = max(88.0, raw_score)

    final_score = int(round(min(100.0, max(0.0, raw_score))))

    # Tier Classification
    if final_score <= 30:
        verdict = "SAFE"
        verdict_color = "#10b981"  # Emerald
        verdict_desc = "Low Risk: URL conforms to transparent domain reputation standards."
    elif final_score <= 60:
        verdict = "SUSPICIOUS"
        verdict_color = "#f59e0b"  # Amber
        verdict_desc = "Medium Risk: Anomalies detected (e.g. shortener, high entropy, or unusual TLD)."
    else:
        verdict = "MALICIOUS"
        verdict_color = "#ef4444"  # Crimson Red
        verdict_desc = "High Risk: High probability of credential phishing or malware delivery."

    return {
        "final_score": final_score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "verdict_description": verdict_desc,
        "ml_prob": round(ml_prob, 4),
        "rule_score": rule_score,
        "ml_component": round(ml_component, 1),
        "rule_component": round(rule_component, 1),
        "intel_component": round(intel_component, 1),
        "context_component": round(context_component, 1)
    }


def generate_explanation(risk_info: dict, triggered_rules: list, features: dict, threat_intel: dict) -> dict:
    """
    Synthesizes Explainable AI (XAI) insights:
    - Top 5 Risk Factors (ranked by impact)
    - Forensic "Why Flagged?" breakdown
    - Actionable "What User Should Do" checklist
    """
    verdict = risk_info["verdict"]
    score = risk_info["final_score"]

    # 1. Compile All Active Risk Factors with Raw Weights
    raw_factors = []

    if threat_intel.get("is_blacklisted"):
        raw_factors.append({
            "factor": "Active Threat Intelligence Blacklist",
            "weight": 35,
            "category": "External Threat Feed",
            "severity": "CRITICAL",
            "reason": f"Destination actively indexed in threat feeds: {threat_intel.get('status')}"
        })

    if features.get("has_ip_address", 0) == 1:
        raw_factors.append({
            "factor": "Raw IP Address Hostname",
            "weight": 25,
            "category": "Domain Infrastructure",
            "severity": "CRITICAL",
            "reason": "Uses raw numeric IP rather than verifiable registered DNS domain."
        })

    if features.get("has_sensitive_extension", 0) == 1:
        raw_factors.append({
            "factor": "Executable Package Download",
            "weight": 25,
            "category": "Payload Risk",
            "severity": "CRITICAL",
            "reason": "URL targets direct binary, APK, or script execution package."
        })

    if features.get("punycode_present", 0) == 1:
        raw_factors.append({
            "factor": "Punycode Homograph Lookalike",
            "weight": 25,
            "category": "Domain Spoofing",
            "severity": "CRITICAL",
            "reason": "Uses lookalike Cyrillic or Greek characters to spoof trusted domains."
        })

    if features.get("brand_in_subdomain_or_path", 0) == 1:
        raw_factors.append({
            "factor": "Brand Impersonation in Path",
            "weight": 25,
            "category": "Social Engineering",
            "severity": "HIGH",
            "reason": "Trusted brand name placed in subdomain or path on an unrelated apex domain."
        })

    if features.get("is_shortened", 0) == 1:
        raw_factors.append({
            "factor": "URL Shortener Concealment",
            "weight": 20,
            "category": "Obfuscation",
            "severity": "HIGH",
            "reason": "URL shortening service conceals the final landing page destination."
        })

    if features.get("redirect_count", 0) >= 2:
        raw_factors.append({
            "factor": "Multi-Hop Redirection Chain",
            "weight": 20,
            "category": "Transport Evasion",
            "severity": "HIGH",
            "reason": f"Traverses {features['redirect_count']} redirects, typical of sandbox evasion."
        })

    if features.get("suspicious_keywords_count", 0) > 0:
        kw_cnt = features["suspicious_keywords_count"]
        raw_factors.append({
            "factor": "Phishing & Credential Lure Terms",
            "weight": min(25, 15 + kw_cnt * 5),
            "category": "Lexical Lures",
            "severity": "HIGH",
            "reason": f"Contains {kw_cnt} sensitive credential harvesting keywords (e.g. login, verify)."
        })

    if not features.get("is_https", 0):
        raw_factors.append({
            "factor": "Cleartext Insecure HTTP",
            "weight": 15,
            "category": "Transport Layer",
            "severity": "MEDIUM",
            "reason": "Transmits data in plaintext without SSL/TLS encryption."
        })

    if features.get("shannon_entropy", 0) >= 4.2:
        raw_factors.append({
            "factor": "High Character Entropy",
            "weight": 15,
            "category": "Algorithmic DGA",
            "severity": "MEDIUM",
            "reason": f"High character entropy ({features['shannon_entropy']:.2f} bits) indicates random token generation."
        })

    if features.get("suspicious_tld", 0) == 1:
        raw_factors.append({
            "factor": "High-Abuse Disposable TLD",
            "weight": 15,
            "category": "Domain Reputation",
            "severity": "MEDIUM",
            "reason": "Top-Level Domain has high abuse rates in cybercrime telemetry."
        })

    if features.get("count_subdomains", 0) >= 3:
        raw_factors.append({
            "factor": "Deep Subdomain Nesting",
            "weight": 15,
            "category": "Domain Infrastructure",
            "severity": "MEDIUM",
            "reason": f"Contains {features['count_subdomains']} nested subdomains mimicking enterprise login trees."
        })

    # ML Anomaly Factor
    if risk_info["ml_prob"] >= 0.70:
        raw_factors.append({
            "factor": "Machine Learning Structural Anomaly",
            "weight": int(risk_info["ml_prob"] * 30),
            "category": "Statistical Model",
            "severity": "HIGH",
            "reason": f"Ensemble model identified {risk_info['ml_prob'] * 100:.1f}% statistical correlation with known phishing topology."
        })

    # Sort and take Top 5
    raw_factors.sort(key=lambda x: x["weight"], reverse=True)
    top_5_factors = raw_factors[:5]

    # 2. Forensic "Why Flagged?" Explanation
    why_flagged = []
    for f in top_5_factors:
        why_flagged.append(f"• **{f['factor']}** ({f['category']}): {f['reason']}")

    if not why_flagged:
        why_flagged.append("• **Clean Profile**: No anomalous structural, transport, or reputation heuristics triggered.")

    # 3. Actionable Mitigation Guidance
    guidance = []
    if verdict == "MALICIOUS":
        guidance.append("🚨 **DO NOT VISIT OR SCAN:** This QR code displays strong indicators of credential harvesting, quishing, or malware delivery.")
        guidance.append("🔒 **NEVER ENTER CREDENTIALS:** Do not provide passwords, banking OTPs, or corporate account details on this landing page.")
        guidance.append("🛡️ **REPORT INCIDENT:** Notify your organization's Security Operations Center (SOC) or IT helpdesk.")
        guidance.append("📍 **PHYSICAL CHECK:** If this QR code was affixed as a physical sticker (e.g. parking meters, restaurants), report the physical tampering to management.")
    elif verdict == "SUSPICIOUS":
        guidance.append("⚠️ **PROCEED WITH CAUTION:** The destination uses URL obfuscation, high entropy, or unusual domain parameters.")
        guidance.append("🔍 **EXPAND SHORTENERS:** If a shortener (bit.ly, tinyurl) was used, verify the unshortened root domain before entering any information.")
        guidance.append("🌐 **VERIFY SPELLING:** Carefully inspect the domain spelling in the address bar to detect typosquatting.")
        guidance.append("🚫 **DECLINE PERMISSIONS:** Do not accept file downloads, profile installations, or notification prompts.")
    else:
        guidance.append("✓ **LOW THREAT DETECTED:** Destination conforms to standard domain conventions and verified HTTPS encryption.")
        guidance.append("💡 **GENERAL HYGIENE:** Ensure your mobile browser is updated with built-in phishing protections.")

    return {
        "summary": f"Classified as {verdict} with an overall threat score of {score}/100.",
        "top_5_factors": top_5_factors,
        "why_flagged": why_flagged,
        "guidance": guidance
    }
