"""Regression tests for the four defects fixed after the real-world evaluation."""
import ast, sys
from upi_analyzer import analyze_upi_payload
import utils, inspect
ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(('PASS ' if cond else 'FAIL ') + name); ok += cond; fail += (not cond)
# UPI: mobile handle no longer flagged; random handle still flagged
def rules(u):
    r = analyze_upi_payload(u)
    return [f.get('rule') for f in r.get('red_flags', r.get('flags', []))], r
m, _ = rules('upi://pay?pa=9876543210@okaxis&pn=Test%20User&cu=INR')
check('UPI 10-digit mobile handle not HIGH_ENTROPY_VPA', 'HIGH_ENTROPY_VPA' not in m)
m, _ = rules('upi://pay?pa=919876543210@ybl&pn=Test%20User&cu=INR')
check('UPI 91-prefixed mobile handle not HIGH_ENTROPY_VPA', 'HIGH_ENTROPY_VPA' not in m)
m, _ = rules('upi://pay?pa=x7k29q8m41z@ybl&pn=Test%20User&cu=INR')
check('UPI random alphanumeric handle still HIGH_ENTROPY_VPA', 'HIGH_ENTROPY_VPA' in m)
# PDF rule id reads 'id'
src = inspect.getsource(utils.generate_security_pdf_report)
check("PDF report falls back to rule key 'id'", "r.get('id'" in src)
pdf = utils.generate_security_pdf_report('https://example.test/', 'URL', 40, 'SUSPICIOUS', 0.1, 20,
        [{'id': 'RULE_SHORTENER', 'severity': 'MEDIUM', 'points': 20, 'description': 'x'}], {})
check('PDF generation still succeeds', isinstance(pdf, (bytes, bytearray)) and pdf[:4] == b'%PDF')
# SSL status field present in all branches
s = inspect.getsource(utils.check_ssl_certificate)
check('SSL result distinguishes valid/cert_invalid/unreachable', all(k in s for k in ["'valid'", "'cert_invalid'", "'unreachable'"]))
a = open('app.py').read()
check('App label shows "Cert invalid" for verification failure', '"cert_invalid": "Cert invalid"' in a)
check('Benchmark view carries synthetic-data warning', 'bundled template-generated dataset' in a)
check('Dashboard telemetry carries synthetic-data caption', 'Synthetic-benchmark figures' in a)
ast.parse(a); check('app.py parses', True)

# --- Decoder hardening (second audit) ---
import glob
from PIL import Image as _Img
from utils import decode_qr_code
demo = sorted(glob.glob('test_samples/*.png'))
dec = [decode_qr_code(_Img.open(f))[0] for f in demo]
check('All 9 demo QR images still decode', len(demo) == 9 and all(dec))
blank = _Img.new('RGB', (200, 200), 'white')
txt, ann, eng = decode_qr_code(blank)
check('Blank image returns no payload without raising', txt is None and eng == 'None')
usrc = open('utils.py').read()
check('pyzbar restricted to QR symbols', 'symbols=[ZBarSymbol.QRCODE]' in usrc)
check('Decoder failures are logged, not silently ignored', usrc.count('logger.warning') >= 3)
check('Sidebar shows URLhaus as inactive without an Auth-Key', 'no Auth-Key; not queried' in a)
check('Upload and webcam image errors are caught', a.count('could not be read as an image') == 2)

# --- Credential handling (second audit) ---
import threat_intel, requests as _rq
_orig = _rq.post
def _boom(url, *a, **k):
    raise _rq.exceptions.ConnectionError(f"HTTPSConnectionPool: Max retries exceeded with url: {url}")
_rq.post = _boom
try:
    _r = threat_intel.query_google_safe_browsing('https://example.test/', 'SECRET-KEY-123')
finally:
    _rq.post = _orig
check('Safe Browsing failure does not expose the API key', 'SECRET-KEY-123' not in str(_r))
check('Safe Browsing failure is reported as unavailable, not clean', threat_intel._feed_state(_r) == 'unavailable')

# --- Missing metadata is shown as N/A, not 0 (final audit) ---
check('Dashboard shows N/A instead of 0 when metadata is missing', 'st.metric(lab, "N/A")' in a)
check('Benchmark table shows N/A instead of 0 when metadata is missing', '"N/A" if not isinstance(md.get(k)' in a)
print(f'{ok} passed, {fail} failed'); sys.exit(1 if fail else 0)
