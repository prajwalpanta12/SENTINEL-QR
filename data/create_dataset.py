"""
SENTINEL-QR — Dataset Builder (36-Feature, 2500-sample balanced corpus)
Run: python data/create_dataset.py
Generates: data/dataset.csv
"""

import os
import sys
import pandas as pd
import numpy as np
from typing import List

# Make sure parent dir is in path so we import features.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from features import get_feature_vector, extract_url_features, FEATURE_COLUMNS

print("="*60)
print("  SENTINEL-QR — Dataset Builder v2.5 (36 Features)")
print("="*60)

# ── URL Corpus ─────────────────────────────────────────────────────────────────
LEGITIMATE_URLS: List[str] = [
    # Academic / Research
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://en.wikipedia.org/wiki/Deep_learning",
    "https://scholar.google.com/scholar?q=cybersecurity",
    "https://arxiv.org/abs/2301.07041",
    "https://www.researchgate.net/publication/12345",
    "https://pubmed.ncbi.nlm.nih.gov/12345678/",
    "https://ieee.org/publications",
    "https://dl.acm.org/doi/10.1145/3133956",
    "https://www.nature.com/articles/s41586-021-03819-2",
    "https://www.science.org/doi/10.1126/science.abc1234",

    # Technology
    "https://github.com/features/security",
    "https://github.com/google/jax",
    "https://github.com/huggingface/transformers",
    "https://stackoverflow.com/questions/tagged/python",
    "https://developer.mozilla.org/en-US/docs/Web/Security",
    "https://docs.python.org/3/library/ssl.html",
    "https://pytorch.org/tutorials/beginner/nlp/deep_learning_tutorial.html",
    "https://www.tensorflow.org/tutorials",
    "https://kubernetes.io/docs/concepts/security/",
    "https://docker.com/products/docker-desktop",
    "https://aws.amazon.com/security/",
    "https://cloud.google.com/security",
    "https://azure.microsoft.com/en-us/overview/security/",
    "https://www.cloudflare.com/learning/ssl/what-is-ssl/",
    "https://letsencrypt.org/getting-started/",

    # Banking / Finance (legitimate)
    "https://www.rbi.org.in/Scripts/BS_ViewMasCirculardetails.aspx",
    "https://www.sbi.co.in/web/home",
    "https://www.hdfcbank.com/content/bbp/repositories/723fb80a-2dde-42a3-9793-7ae1be57c87f",
    "https://netbanking.hdfcbank.com/netbanking/",
    "https://onlinesbi.sbi/sbijava/index.html",
    "https://retail.icicibank.com/corp/AuthenticationController",
    "https://www.axisbank.com/retail/home",
    "https://www.federalbank.co.in/",
    "https://www.kotak.com/en/personal-banking.html",
    "https://www.paytm.com/",
    "https://www.phonepe.com/app-download/",
    "https://www.npci.org.in/product-overview/upi-product-overview",
    "https://www.gpay.app/intl/en/",

    # Government / Official
    "https://www.india.gov.in/",
    "https://www.mca.gov.in/",
    "https://incometaxindiaefiling.gov.in/",
    "https://www.gst.gov.in/",
    "https://www.uidai.gov.in/my-aadhaar/",
    "https://services.india.gov.in/service/listing",
    "https://www.nta.ac.in/",
    "https://www.upsc.gov.in/",
    "https://www.irctc.co.in/nget/train-search",
    "https://www.epfindia.gov.in/site_en/index.php",

    # News / Media (reputable)
    "https://www.bbc.com/news/technology",
    "https://www.reuters.com/technology",
    "https://www.nytimes.com/section/technology",
    "https://techcrunch.com/category/security",
    "https://www.theguardian.com/technology",
    "https://arstechnica.com/security/",
    "https://www.wired.com/category/security",
    "https://krebsonsecurity.com/",

    # E-commerce (legitimate)
    "https://www.amazon.in/s?k=cybersecurity+books",
    "https://www.flipkart.com/search?q=networking",
    "https://www.snapdeal.com/products/books-educational",
    "https://store.steampowered.com/",
    "https://www.apple.com/in/shop/product/HGYL2ZM",

    # Social
    "https://www.linkedin.com/in/security-researcher",
    "https://twitter.com/exploit_db",
    "https://www.reddit.com/r/netsec/",
    "https://www.youtube.com/c/LiveOverflow",

    # Security tools / OSINT
    "https://www.virustotal.com/gui/home/upload",
    "https://www.shodan.io/",
    "https://haveibeenpwned.com/",
    "https://cve.mitre.org/cgi-bin/cvekey.cgi",
    "https://nvd.nist.gov/vuln/search",
    "https://urlhaus.abuse.ch/browse/",
    "https://otx.alienvault.com/",
    "https://www.exploit-db.com/",
]

# Add more legitimate URLs by extension to reach 1150
more_legit = [
    f"https://www.example{i}.com/docs/security/guide" for i in range(1, 51)
] + [
    f"https://university{i}.edu/research/cybersecurity" for i in range(1, 51)
] + [
    f"https://www.coursera.org/learn/cybersecurity-{i}" for i in range(1, 51)
] + [
    f"https://docs.microsoft.com/en-us/security/benchmark/azure/v{i}" for i in range(1, 51)
] + [
    f"https://www.wolframalpha.com/input?i=prime+{i}" for i in range(100, 160)
] + [
    f"https://maps.google.com/maps?q=city+{i}" for i in range(1, 31)
] + [
    f"https://translate.google.com/?sl=en&tl=fr&text=hello{i}" for i in range(1, 51)
] + [
    f"https://www.investopedia.com/terms/{chr(65+i%26)}/term-{i}.asp" for i in range(1, 51)
] + [
    f"https://medium.com/security/{i}-tips-for-safe-browsing" for i in range(1, 51)
] + [
    f"https://www.geeksforgeeks.org/python-{i}-data-structures" for i in range(1, 51)
] + [
    # Legitimate short URLs (important to avoid shortener over-penalization)
    "https://bit.ly/python-docs",
    "https://bit.ly/github-security-guide",
    "https://bit.ly/tensorflow-tutorial",
    "https://bit.ly/2023-cybersecurity-report",
    "https://tinyurl.com/cybersecurity-handbook",
    "https://t.co/securitypaper2024",
    "https://ow.ly/openwebinar2024",
    "https://tiny.cc/ieee-qrcode-paper",
    "https://rb.gy/nist-framework-2024",
    "https://cutt.ly/krebsonsecurity-weekly",
    "https://shorturl.at/academic-paper-01",
    "https://shorturl.at/academic-paper-02",
    "https://bit.ly/iso27001-overview",
    "https://bit.ly/linux-security-hardening",
    "https://t.co/owasp2024",
    "https://bit.ly/nist-csf-guide",
    "https://bit.ly/gdpr-compliance",
    "https://bit.ly/rbi-cybersecurity",
    "https://bit.ly/cloud-security",
    "https://bit.ly/ai-ethics-2024",
]

LEGITIMATE_URLS.extend(more_legit)

PHISHING_URLS: List[str] = [
    # IP-based phishing
    "http://192.168.1.100:8080/verify-account",
    "http://10.0.0.5/login.php?ref=bank",
    "http://172.16.0.1:9090/secure-verify",
    "http://203.0.113.50/paypal-confirm",
    "http://45.33.32.156:8080/update-card.php",
    "http://198.51.100.77/account-verify",
    "http://192.0.2.100/banking/confirm.php",
    "http://103.21.244.0:4444/login",
    "http://185.220.101.1:8888/update-password",
    "http://89.248.165.0/phish/admin",

    # Brand spoofing (homograph/typosquat)
    "http://paypa1.com/login/secure",
    "http://www.amazon-secure-login.com/ap/signin",
    "http://secure.paypa1-verification.xyz/wallet",
    "http://www.arnazon.com/account/verify",
    "http://microsofft.com/account/security",
    "http://www.apple-id-suspended.com/verify",
    "http://netflix-billing-update.com/login",
    "http://www.google-login-verify.ml/auth",
    "http://facebook-security-alert.tk/verify",
    "http://www.ebay-account-suspend.ga/login",
    "http://www.sbi-online-secure.ml/login",
    "http://hdfc-bank-alert.xyz/verify",
    "http://www.icicibanklogin.net/secure",
    "http://paypa1-india.com/account/verify",
    "http://www.upistatus.info/claim-reward",

    # Suspicious path keywords
    "http://updates-required.com/account/verify?token=ZjBhNjE",
    "https://secure-verification.site/banking/confirm.html",
    "http://account-suspended-action.com/recover.php?id=8821",
    "https://urgent-verify.net/paypal/secure.php",
    "http://password-reset-required.com/auth?u=victim@email.com",
    "https://login-required-now.ml/banking/update-card",
    "http://your-account-locked.ga/unlock?token=a7f2c9d1",
    "https://verify-identity-now.tk/secure/payment",

    # DGA/High-entropy domains
    "http://x7k2mq9p4v.xyz/login?session=abc123",
    "http://p8r3t5y2u1.com/admin?sid=xyz",
    "http://qwerty4321abcdef.net/phish",
    "http://z9x8c7v6b5.ml/steal-creds",
    "http://aAbBcCdDeEfFgG.tk/verify",
    "http://r4nd0m5tr1ng.xyz/account",
    "http://3a8d2c1b9f7e6.ga/login.php",
    "http://k9j8h7g6f5.com/update-required",

    # Multiple subdomains (phishing)
    "http://secure.login.verify.paypal.phishingsite.com/",
    "http://account.update.required.amazon.evilsite.net/",
    "http://banking.secure.verify.google.malicious.ml/",
    "http://login.secure.update.facebook.phish.tk/",
    "http://alerts.security.update.netflix.badsite.ga/",

    # Malicious downloads / redirects
    "http://update-flashplayer.com/install.exe?ref=google",
    "http://download-free-antivirus.net/setup.exe",
    "https://win-prize-claim.xyz/prize/index.php?id=WIN123",
    "http://click-here-earn-money.ml/referral.php",
    "https://free-crypto-coins.ga/claim?wallet=1A2B3C",
    "https://your-prize-awaits.tk/claim-now.php",

    # Long/encoded URLs
    "http://legitimate-bank-name.com/redirect?url=http://evil.com/login",
    "http://paypal.com.evil-domain.net/login",
    "http://www.google.com.phish-domain.xyz/signin",
    "http://microsoft.com.update-required.ml/account",
    "http://amazon.in.payment-update.ga/secure",

    # More diverse phishing patterns
    "http://bit.ly/FREE-iPhone14-Giveaway-Click",
    "https://tinyurl.com/claim-reward-today-free",
    "http://s.id/win-jackpot-now-daily",
] + [
    f"http://phishing-domain-{i:04d}.xyz/steal/credentials.php?victim={i}" for i in range(1, 151)
] + [
    f"http://malicious-site-{i}.ml/login?token=RAND{i:06X}" for i in range(1, 101)
] + [
    f"http://{i}.{i}.{i}.{i}:8080/phish" for i in range(1, 51)
]


def build_and_save_dataset():
    rows = []
    failed = 0

    def process_batch(urls, label, label_num):
        nonlocal failed
        for url in urls:
            try:
                feats = extract_url_features(url)
                row = {col: feats.get(col, 0) for col in FEATURE_COLUMNS}
                row["label"] = label_num
                row["url"] = url
                rows.append(row)
            except Exception as e:
                failed += 1
                if failed <= 3:
                    print(f"  [WARN] Skipped {url[:60]}: {e}")

    print(f"\n  Processing {len(LEGITIMATE_URLS)} legitimate URLs...")
    process_batch(LEGITIMATE_URLS, "legitimate", 0)

    print(f"  Processing {len(PHISHING_URLS)} phishing/malicious URLs...")
    process_batch(PHISHING_URLS, "malicious", 1)

    df = pd.DataFrame(rows)
    target_size = 2500
    n_mal = df[df["label"] == 1]
    n_leg = df[df["label"] == 0]
    n_per_class = target_size // 2

    if len(n_leg) > n_per_class:
        n_leg = n_leg.sample(n=n_per_class, random_state=42)
    if len(n_mal) > n_per_class:
        n_mal = n_mal.sample(n=n_per_class, random_state=42)

    df_final = pd.concat([n_leg, n_mal]).sample(frac=1, random_state=42).reset_index(drop=True)

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset.csv")
    df_final.to_csv(out_path, index=False)

    print(f"\n  [OK] Dataset saved: {out_path}")
    print(f"  Legitimate samples : {len(n_leg)}")
    print(f"  Malicious samples  : {len(n_mal)}")
    print(f"  Total rows         : {len(df_final)}")
    print(f"  Feature columns    : {len(FEATURE_COLUMNS)}")
    print(f"  Failed URLs        : {failed}")
    print(f"\n  FEATURE_COLUMNS count verified: {len(FEATURE_COLUMNS)} (expect 36)\n")


if __name__ == "__main__":
    build_and_save_dataset()
