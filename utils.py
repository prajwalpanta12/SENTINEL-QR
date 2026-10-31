"""
AI-Based QR Code Threat Analyzer
Module: utils.py
Purpose: QR code decoding (OpenCV + pyzbar fallback), image annotation,
         URL validation/cleaning, SSL certificate auditing, and
         formal PDF security audit report generation with embedded QR images.
"""

import io
import re
import cv2
import hashlib
import numpy as np
from PIL import Image
import urllib.parse
import socket
import ssl
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
from xml.sax.saxutils import escape as xml_escape
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    from pyzbar.pyzbar import ZBarSymbol
    PYZBAR_AVAILABLE = True
except Exception:
    PYZBAR_AVAILABLE = False


def decode_qr_code(image_bytes_or_pil):
    """
    Decodes QR code from bytes or PIL Image using OpenCV with pyzbar fallback.
    Returns:
        tuple: (decoded_text: str or None, annotated_image: PIL.Image or None, method: str)
    """
    if isinstance(image_bytes_or_pil, bytes):
        pil_img = Image.open(io.BytesIO(image_bytes_or_pil)).convert("RGB")
    elif isinstance(image_bytes_or_pil, Image.Image):
        pil_img = image_bytes_or_pil.convert("RGB")
    else:
        return None, None, "Invalid image format"

    np_img = np.array(pil_img)
    cv_img = cv2.cvtColor(np_img, cv2.COLOR_RGB2BGR)
    annotated_cv = cv_img.copy()

    decoded_text = None
    engine_used = None

    # 1. Primary Engine: OpenCV QRCodeDetector
    try:
        detector = cv2.QRCodeDetector()
        val, points, _ = detector.detectAndDecode(cv_img)
        if val and len(val.strip()) > 0:
            decoded_text = val.strip()
            engine_used = "OpenCV Native (C++)"
            if points is not None and len(points) > 0:
                pts = points[0].astype(int)
                for i in range(len(pts)):
                    pt1 = tuple(pts[i])
                    pt2 = tuple(pts[(i + 1) % len(pts)])
                    cv2.line(annotated_cv, pt1, pt2, (0, 255, 0), 3)
    except Exception as exc:
        logger.warning("OpenCV QR decoding failed: %s", exc)

    # 2. Secondary Engine: pyzbar
    if not decoded_text and PYZBAR_AVAILABLE:
        try:
            # Restrict to QR symbols so 1-D product barcodes are not analysed as QR payloads.
            barcodes = pyzbar_decode(pil_img, symbols=[ZBarSymbol.QRCODE])
            for barcode in barcodes:
                if barcode.data:
                    decoded_text = barcode.data.decode("utf-8", errors="ignore").strip()
                    engine_used = "pyzbar"
                    rect = barcode.rect
                    cv2.rectangle(
                        annotated_cv,
                        (rect.left, rect.top),
                        (rect.left + rect.width, rect.top + rect.height),
                        (0, 255, 0),
                        3
                    )
                    break
        except Exception as exc:
            logger.warning("pyzbar QR decoding failed: %s", exc)

    # 3. Fallback: Contrast CLAHE enhancement
    if not decoded_text:
        try:
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enhanced = clahe.apply(gray)
            val, points, _ = cv2.QRCodeDetector().detectAndDecode(enhanced)
            if val and len(val.strip()) > 0:
                decoded_text = val.strip()
                engine_used = "OpenCV (CLAHE Enhanced)"
                if points is not None and len(points) > 0:
                    pts = points[0].astype(int)
                    for i in range(len(pts)):
                        pt1 = tuple(pts[i])
                        pt2 = tuple(pts[(i + 1) % len(pts)])
                        cv2.line(annotated_cv, pt1, pt2, (0, 255, 0), 3)
        except Exception as exc:
            logger.warning("CLAHE-enhanced QR decoding failed: %s", exc)

    annotated_rgb = cv2.cvtColor(annotated_cv, cv2.COLOR_BGR2RGB)
    annotated_pil = Image.fromarray(annotated_rgb)

    return decoded_text, annotated_pil, engine_used or "None"


def validate_and_clean_url(raw_text: str):
    """
    Validates and cleans URL from decoded text.
    """
    if not raw_text or not isinstance(raw_text, str):
        return {
            'is_valid_url': False,
            'cleaned_url': "",
            'scheme': "",
            'domain': "",
            'path': "",
            'is_wifi_or_other': False,
            'content_type': "empty",
            'error_message': "Empty payload received."
        }

    raw = raw_text.strip()

    cleaned = raw
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        if cleaned.startswith("www.") or re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", cleaned):
            cleaned = "http://" + cleaned

    try:
        parsed = urllib.parse.urlparse(cleaned)
        scheme = parsed.scheme.lower()
        domain = parsed.netloc.lower()
        path = parsed.path

        has_valid_scheme = scheme in ["http", "https"]
        has_valid_netloc = len(domain) > 0 and ("." in domain or re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain))

        if has_valid_scheme and has_valid_netloc:
            return {
                'is_valid_url': True,
                'cleaned_url': cleaned,
                'scheme': scheme,
                'domain': domain,
                'path': path,
                'is_wifi_or_other': False,
                'content_type': "Web URL",
                'error_message': None
            }
        else:
            return {
                'is_valid_url': False,
                'cleaned_url': raw,
                'scheme': scheme,
                'domain': domain,
                'path': path,
                'is_wifi_or_other': False,
                'content_type': "Non-URL Payload",
                'error_message': "Payload is not a valid HTTP/HTTPS web URL."
            }
    except Exception as e:
        return {
            'is_valid_url': False,
            'cleaned_url': raw,
            'scheme': "",
            'domain': "",
            'path': "",
            'is_wifi_or_other': False,
            'content_type': "Unparseable",
            'error_message': f"Parsing error: {str(e)}"
        }


def check_ssl_certificate(domain: str, port: int = 443, timeout: float = 2.5):
    """Checks SSL handshake validity and issuer."""
    host = domain.split(":")[0]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) or host in ["localhost", "127.0.0.1"]:
        return {'ssl_valid': False, 'issuer': 'None (Raw IP/Localhost)', 'expiry': 'N/A', 'error': 'Raw IP/Localhost'}

    try:
        context = ssl.create_default_context()
        context.timeout = timeout
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Unknown CA'))
                not_after = cert.get('notAfter', 'Unknown')
                return {
                    'ssl_valid': True,
                    'status': 'valid',
                    'issuer': issuer_name,
                    'expiry': not_after,
                    'error': None
                }
    except ssl.SSLCertVerificationError as e:
        return {'ssl_valid': False, 'status': 'cert_invalid', 'issuer': 'Invalid / Self-Signed', 'expiry': 'N/A', 'error': f"Verification failed: {e.reason}"}
    except Exception as e:
        return {'ssl_valid': False, 'status': 'unreachable', 'issuer': 'Connection Failed / Unreachable', 'expiry': 'N/A', 'error': str(e)}


def generate_security_pdf_report(payload: str, qr_type: str, risk_score: int, verdict: str,
                                 ml_prob: float, rule_score: int, triggered_rules: list,
                                 threat_intel: dict, qr_image_pil: Image.Image = None,
                                 report_note: str = None):
    """
    Generates a formal, hash-stamped cybersecurity audit report with an
    embedded QR image, the full SHA-256 checksum of the payload, and
    mitigation guidance.

    The checksum supports integrity checking of the payload text.  It is not
    a digital signature and does not prove who produced the report.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
        fontName="Helvetica-Bold"
    )
    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=14
    )
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6,
        fontName="Helvetica-Bold"
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor("#334155"),
        leading=13
    )
    code_style = ParagraphStyle(
        'Code',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor("#0284c7"),
        fontName="Courier"
    )

    story = []

    # Header Title
    story.append(Paragraph("SENTINEL-QR // FORENSIC SECURITY AUDIT REPORT", title_style))
    story.append(Paragraph(f"Digital Threat Assessment & Mitigation Document | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
    if report_note:
        story.append(Paragraph(f"<b>Report note:</b> {xml_escape(report_note)}", body_style))
        story.append(Spacer(1, 6))

    # SHA-256 checksum of the payload string.  The full digest is displayed in
    # two lines so that it remains readable inside the summary table.
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    hash_display = f"{payload_hash[:32]}<br/>{payload_hash[32:]}"

    # Verdict Colors
    verdict_color = colors.HexColor("#10b981") if verdict in ["SAFE", "SECURE"] else (
        colors.HexColor("#f59e0b") if verdict in ["SUSPICIOUS", "WEAK SECURITY"] else colors.HexColor("#ef4444")
    )

    # Overview Table Data (Left: Info, Right: Embedded QR Image if available)
    summary_cells = [
        [Paragraph("<b>Payload Category:</b>", body_style), Paragraph(f"<b>{xml_escape(str(qr_type))}</b>", body_style)],
        [Paragraph("<b>Security Verdict:</b>", body_style), Paragraph(f"<b><font color='{verdict_color.hexval()}'>{xml_escape(str(verdict))}</font></b>", body_style)],
        [Paragraph("<b>Threat Risk Score:</b>", body_style), Paragraph(f"<b>{risk_score} / 100</b>", body_style)],
        [Paragraph("<b>ML Ensemble Confidence:</b>", body_style), Paragraph(f"{ml_prob * 100:.1f}%", body_style)],
        [Paragraph("<b>Heuristic Penalty:</b>", body_style), Paragraph(f"{rule_score} pts", body_style)],
        [Paragraph("<b>SHA-256 Checksum:</b>", body_style), Paragraph(f"<code>{hash_display}</code>", code_style)]
    ]

    t_meta = Table(summary_cells, colWidths=[140, 240])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))

    # If QR image provided, embed side-by-side
    if qr_image_pil is not None:
        img_buffer = io.BytesIO()
        qr_image_pil.resize((120, 120)).save(img_buffer, format="PNG")
        img_buffer.seek(0)
        rl_img = RLImage(img_buffer, width=110, height=110)
        
        composite_table = Table([[t_meta, rl_img]], colWidths=[385, 145])
        composite_table.setStyle(TableStyle([
            ('ALIGN', (1, 0), (1, 0), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(composite_table)
    else:
        story.append(t_meta)

    story.append(Spacer(1, 10))

    # Decoded Payload Box
    story.append(Paragraph("<b>Decoded QR Target Payload:</b>", body_style))
    p_box = Table([[Paragraph(f"<code>{xml_escape(str(payload))}</code>", code_style)]], colWidths=[530])
    p_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(p_box)
    story.append(Spacer(1, 10))

    # Forensic Red Flags / Triggered Rules
    story.append(Paragraph("<b>Forensic Heuristics & Anomaly Evidence</b>", h2_style))
    if triggered_rules:
        rules_data = [["Rule ID", "Severity", "Points", "Forensic Technical Evidence"]]
        for r in triggered_rules:
            rules_data.append([
                r.get('rule', r.get('rule_id', r.get('id', 'RULE'))),
                r.get('severity', 'MED'),
                f"+{r.get('points', 0)}",
                Paragraph(xml_escape(str(r.get('description', r.get('reason', '')))), body_style)
            ])
        t_rules = Table(rules_data, colWidths=[110, 60, 45, 315])
        t_rules.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_rules)
    else:
        story.append(Paragraph("No anomalous heuristic security rules triggered. Payload structure matches baseline norms.", body_style))

    story.append(Spacer(1, 12))

    # Mitigation Guidance
    story.append(Paragraph("<b>Actionable Security Guidance & Mitigation</b>", h2_style))
    if verdict in ["MALICIOUS", "FRAUD RISK", "CRITICAL RISK"]:
        guidance_text = "<b>CRITICAL INCIDENT DETECTED:</b> High confidence threat of credential phishing, malware transmission, or payment auto-debit entrapment. <b>DO NOT</b> interact, enter PIN/credentials, or connect. Quarentine physical QR sticker or digital distribution source."
    elif verdict in ["SUSPICIOUS", "WEAK SECURITY"]:
        guidance_text = "<b>CAUTION ADVISED:</b> Elevated threat indicators present. Destination lacks verified credentials, uses URL obfuscation, or employs weak wireless ciphers. Validate the entity out-of-band before proceeding."
    else:
        guidance_text = "<b>CLEAN BASELINE:</b> Verified standard payload structure. No deceptive indicators detected. Standard operational security practices apply."

    story.append(Paragraph(guidance_text, body_style))
    story.append(Spacer(1, 15))
    story.append(Paragraph("<font size='7' color='#94a3b8'>Generated by Sentinel-QR Threat Engine | Hash-stamped report. The SHA-256 checksum is not a digital signature.</font>", body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
