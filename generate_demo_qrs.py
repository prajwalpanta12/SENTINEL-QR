"""
SENTINEL-QR — Demo QR Generator
Generates multi-type QR codes for all demo presets in test_samples/.
Run: python generate_demo_qrs.py
"""

import os
import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import RoundedModuleDrawer
from PIL import Image, ImageDraw

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(BASE_DIR, "test_samples")
os.makedirs(OUT_DIR, exist_ok=True)


DEMO_QRS = [
    # (filename, payload, label, box_color_rgb)
    # ── URL — Safe ──────────────────────────────────────────────────────────
    ("1_safe_wikipedia.png",
     "https://en.wikipedia.org/wiki/QR_code",
     "Safe: Wikipedia (Academic URL)",
     (16, 185, 129)),   # emerald

    ("2_safe_github.png",
     "https://github.com/features/security",
     "Safe: GitHub Security Features",
     (16, 185, 129)),

    # ── URL — Suspicious ───────────────────────────────────────────────────
    ("3_suspicious_shortener.png",
     "https://bit.ly/3xSecurityCheckLogin",
     "Suspicious: Masked URL Shortener",
     (245, 158, 11)),   # amber

    # ── URL — Malicious ────────────────────────────────────────────────────
    ("4_malicious_ip_phish.png",
     "http://192.168.1.254:8080/verify-paypal-account.php?user=victim&token=abc123",
     "Malicious: IP-Based Phishing (Port 8080)",
     (239, 68, 68)),    # red

    ("5_malicious_paypal_spoof.png",
     "http://www.paypa1-verification-required.xyz/secure/wallet/confirm.php?sid=xX7z&user=admin",
     "Malicious: PayPal Brand Spoofing",
     (239, 68, 68)),

    ("6_malicious_dga_domain.png",
     "http://x7k2mq9p4v.com/login?redirect=paypal.com&session=z9x8w7v6u5t4s3r2",
     "Malicious: DGA Domain + Redirect Scam",
     (239, 68, 68)),

    # ── UPI — Fraud ────────────────────────────────────────────────────────
    ("7_upi_fraud.png",
     "upi://pay?pa=sbi.refund.portal@ybl&pn=SBI_Reward_Support&am=4999.00&tn=Claim_Your_Cashback_Reward&cu=INR",
     "UPI Fraud: Reverse-Charge Cashback Scam",
     (239, 68, 68)),

    # ── Wi-Fi — Rogue Open AP ──────────────────────────────────────────────
    ("8_rogue_wifi.png",
     "WIFI:T:nopass;S:Airport_Free_HighSpeed_WiFi;P:;;",
     "Wi-Fi: Rogue Open AP / Evil Twin",
     (239, 68, 68)),

    # ── Email — Phishing Lure ──────────────────────────────────────────────
    ("9_phishing_email.png",
     "mailto:support@paypa1-security.xyz?subject=Account_Suspended_Action_Required&body=Dear_user_click_the_link_below_to_restore_access",
     "Email: Phishing Lure (Account Suspension)",
     (239, 68, 68)),
]


def make_qr(payload: str, label: str, border_rgb: tuple) -> Image.Image:
    """Create a robust, decoder-friendly QR code with a label footer."""
    qr = qrcode.QRCode(
        version=None, error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10, border=4
    )
    qr.add_data(payload)
    qr.make(fit=True)
    # Plain square modules decode far more reliably than styled/rounded ones
    img = qr.make_image().convert("RGBA")

    # Scale with NEAREST to preserve crisp module edges (no blur)
    qr_size = 360
    img = img.resize((qr_size, qr_size), Image.NEAREST)
    canvas = Image.new("RGBA", (400, 440), (10, 15, 30, 255))
    canvas.paste(img, (20, 20), img.convert("RGBA"))

    draw = ImageDraw.Draw(canvas)
    # Colored border line at bottom
    draw.rectangle([0, 400, 400, 440], fill=(border_rgb[0], border_rgb[1], border_rgb[2], 255))
    # Label text
    draw.text((200, 420), label[:50], fill=(255, 255, 255, 230), anchor="mm")
    return canvas.convert("RGB")


def main():
    print(f"\n{'='*58}")
    print(f"  SENTINEL-QR - Demo QR Generator (Multi-Type Edition)")
    print(f"{'='*58}")
    print(f"  Output Dir: {OUT_DIR}")
    print(f"{'='*58}\n")

    for fname, payload, label, border_rgb in DEMO_QRS:
        outpath = os.path.join(OUT_DIR, fname)
        img = make_qr(payload, label, border_rgb)
        img.save(outpath)
        print(f"  [OK] [{label[:45]:<45}] -> {fname}")

    print(f"\n  Generated {len(DEMO_QRS)} demo QR codes.")
    print(f"  UPI Fraud QR    : 7_upi_fraud.png")
    print(f"  Rogue Wi-Fi QR  : 8_rogue_wifi.png")
    print(f"  Phishing Email  : 9_phishing_email.png")
    print(f"\n  Use: streamlit run app.py | Demo Presets tab\n")


if __name__ == "__main__":
    main()
