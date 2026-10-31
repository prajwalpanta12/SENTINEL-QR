"""
SENTINEL-QR // Threat Defense Platform v3.0
Module: app.py — Industry-grade SaaS cybersecurity dashboard.

Design system:
  bg #0B0F1A | glass cards | green #00FFB2 | yellow #FFC857
  red #FF4D4D | cyan #00D1FF | Inter / system sans
"""

import os
import time
from html import escape as html_escape
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
from PIL import Image

# ── Engine modules (unchanged backend) ─────────────────────────────────────────
from utils import (
    decode_qr_code, validate_and_clean_url, check_ssl_certificate,
    generate_security_pdf_report, PYZBAR_AVAILABLE,
)
from qr_types import detect_qr_type, QRType
from upi_analyzer import analyze_upi_payload
from wifi_analyzer import analyze_wifi_payload
from communication_analyzer import analyze_email_payload, analyze_phone_payload
from features import extract_url_features
from rules import evaluate_rules
from model import predict_threat, get_model_metadata
from threat_intel import query_threat_intelligence, summarize_intel_status
from explainability import calculate_hybrid_risk_score, generate_explanation

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "test_samples")

# ── Palette ────────────────────────────────────────────────────────────────────
BG = "#0B0F1A"
CARD = "rgba(21, 28, 46, 0.72)"
BORDER = "#1E2A45"
SAFE = "#00FFB2"
SUSPICIOUS = "#FFC857"
MALICIOUS = "#FF4D4D"
CYAN = "#00D1FF"
VIOLET = "#A78BFA"
MUTED = "#8B98B8"

st.set_page_config(
    page_title="Sentinel-QR | AI Threat Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL DESIGN SYSTEM
# ══════════════════════════════════════════════════════════════════════════════
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

/* ── Canvas ── */
.stApp {{
    background:
        radial-gradient(1000px 380px at 12% -6%, rgba(0,209,255,0.08), transparent 60%),
        radial-gradient(900px 360px at 88% -4%, rgba(124,58,237,0.09), transparent 60%),
        radial-gradient(700px 500px at 50% 110%, rgba(0,255,178,0.04), transparent 60%),
        {BG};
    color: #DCE6F5;
    font-family: 'Inter', -apple-system, 'Segoe UI', sans-serif;
}}
.block-container {{ max-width: 1220px !important; padding-top: 1.6rem !important; padding-bottom: 3rem !important; }}

/* ── Motion ── */
@keyframes fadeUp {{ from {{ opacity: 0; transform: translateY(12px); }} to {{ opacity: 1; transform: translateY(0); }} }}
@keyframes pulseRed {{ 0%,100% {{ box-shadow: 0 0 0 0 rgba(255,77,77,0.45); }} 50% {{ box-shadow: 0 0 28px 4px rgba(255,77,77,0.35); }} }}
@keyframes pulseGreen {{ 0%,100% {{ box-shadow: 0 0 0 0 rgba(0,255,178,0.35); }} 50% {{ box-shadow: 0 0 24px 3px rgba(0,255,178,0.28); }} }}
@keyframes sweep {{ 0% {{ transform: translateX(-120%); }} 100% {{ transform: translateX(500%); }} }}
@keyframes spinPulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.4; }} }}
.page-head, .verdict-banner, .m-card, .glass, .risk-factor, .drop-hint {{ animation: fadeUp 0.45s ease both; }}
.verdict-malicious {{ animation: fadeUp 0.45s ease both, pulseRed 2.4s ease-in-out infinite; }}
.verdict-safe {{ animation: fadeUp 0.45s ease both, pulseGreen 3s ease-in-out infinite; }}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, #0D1322 0%, #0A0F1C 100%) !important;
    border-right: 1px solid {BORDER} !important;
}}
.brand-name {{ font-size: 1.25rem; font-weight: 900; letter-spacing: -0.5px; color: #fff; }}
.brand-name span {{ color: {CYAN}; }}
.brand-sub {{ font-size: 0.7rem; color: {MUTED}; text-transform: uppercase; letter-spacing: 0.14em; margin-top: 2px; }}
section[data-testid="stSidebar"] .stRadio > div {{ gap: 4px; }}
section[data-testid="stSidebar"] .stRadio label {{
    background: transparent !important; border: 1px solid transparent !important;
    border-radius: 10px !important; padding: 9px 12px !important; margin: 1px 0 !important;
    transition: all 0.18s ease !important;
}}
section[data-testid="stSidebar"] .stRadio label:hover {{ background: rgba(0,209,255,0.07) !important; }}
section[data-testid="stSidebar"] .stRadio label:has(input:checked) {{
    background: linear-gradient(135deg, rgba(0,209,255,0.16), rgba(124,58,237,0.14)) !important;
    border-color: {CYAN} !important;
    box-shadow: 0 0 14px rgba(0,209,255,0.22);
}}
section[data-testid="stSidebar"] .stRadio label p {{ color: #C4D0E8 !important; font-weight: 600 !important; font-size: 0.9rem !important; }}

/* ── Page header ── */
.page-head {{
    background: linear-gradient(135deg, #101A33 0%, #141B3D 50%, #0E1E33 100%);
    border: 1px solid {BORDER}; border-radius: 16px;
    padding: 26px 30px 20px; margin-bottom: 22px;
    position: relative; overflow: hidden;
}}
.page-head::before {{
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
    background: linear-gradient(90deg, {SAFE}, {CYAN}, #7c3aed, {MALICIOUS});
}}
.page-head::after {{
    content: ''; position: absolute; top: 0; bottom: 0; width: 70px;
    background: linear-gradient(90deg, transparent, rgba(0,209,255,0.07), transparent);
    animation: sweep 7s linear infinite;
}}
.page-head h1 {{ color: #fff; font-size: 1.8rem; font-weight: 800; margin: 0; letter-spacing: -0.5px; }}
.page-head h1 span {{ color: {CYAN}; }}
.page-head p {{ color: {MUTED}; font-size: 0.92rem; margin: 6px 0 0 0; }}
.head-pill {{
    display: inline-block; margin-top: 12px; padding: 4px 12px; border-radius: 20px;
    font-size: 0.72rem; font-weight: 700; letter-spacing: 0.08em;
    background: rgba(0,209,255,0.1); border: 1px solid {CYAN}; color: {CYAN};
}}

/* ── Glass card ── */
.glass {{
    background: {CARD}; backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
    border: 1px solid {BORDER}; border-radius: 14px; padding: 20px;
    box-shadow: 0 10px 32px rgba(0,0,0,0.35);
}}
.glass h3, .glass h4 {{ color: #fff !important; }}

/* ── Dropzone ── */
.drop-hint {{
    border: 2px dashed #2B3D63; border-radius: 16px; padding: 26px 20px; text-align: center;
    background: rgba(0,209,255,0.03); margin-bottom: 6px; transition: all 0.2s ease;
}}
.drop-hint:hover {{ border-color: {CYAN}; background: rgba(0,209,255,0.06); box-shadow: 0 0 20px rgba(0,209,255,0.12); }}
.drop-hint .big {{ font-size: 2rem; }}
.drop-hint .t1 {{ color: #fff; font-weight: 800; font-size: 1.05rem; margin-top: 6px; }}
.drop-hint .t2 {{ color: {MUTED}; font-size: 0.82rem; margin-top: 4px; }}
div[data-testid="stFileUploader"] section {{
    background: transparent !important; border: none !important; padding: 0 !important;
}}
div[data-testid="stFileUploader"] section button {{
    background: linear-gradient(135deg, #00A8E8, #7c3aed) !important; color: #fff !important;
    border: none !important; border-radius: 10px !important; font-weight: 700 !important;
    padding: 0.55rem 1.6rem !important; transition: all 0.18s ease !important;
}}
div[data-testid="stFileUploader"] section button:hover {{
    transform: translateY(-1px); box-shadow: 0 6px 22px rgba(0,209,255,0.4);
}}

/* ── Buttons ── */
.stButton > button {{
    background: #141D33 !important; color: #E6EEFB !important;
    border: 1px solid #2B3D63 !important; border-radius: 11px !important;
    font-weight: 700 !important; transition: all 0.18s ease !important;
}}
.stButton > button:hover:not(:disabled) {{
    border-color: {CYAN} !important; transform: translateY(-1px);
    box-shadow: 0 6px 20px rgba(0,209,255,0.25);
}}
.stButton > button:disabled {{ opacity: 0.45; cursor: not-allowed; }}
.stButton > button[kind="primary"] {{
    background: linear-gradient(135deg, #00A8E8, #7c3aed) !important;
    border: none !important; color: #fff !important;
    box-shadow: 0 4px 18px rgba(0,209,255,0.35);
}}
.stButton > button[kind="primary"]:hover:not(:disabled) {{ box-shadow: 0 8px 28px rgba(124,58,237,0.5); }}
div[data-testid="stDownloadButton"] > button {{
    background: linear-gradient(135deg, #059669, #00FFB2) !important;
    border: none !important; color: #04241A !important; font-weight: 800 !important;
    border-radius: 11px !important; box-shadow: 0 4px 18px rgba(0,255,178,0.3);
    transition: all 0.18s ease !important;
}}
div[data-testid="stDownloadButton"] > button:hover {{ transform: translateY(-1px); box-shadow: 0 8px 26px rgba(0,255,178,0.45); }}

/* ── Verdict banner ── */
.verdict-banner {{
    border-radius: 16px; padding: 24px 28px; margin: 20px 0;
    display: flex; align-items: center; gap: 20px; border: 1.5px solid;
    box-shadow: 0 12px 36px rgba(0,0,0,0.4);
}}
.verdict-safe {{ background: linear-gradient(135deg, rgba(0,255,178,0.14), rgba(0,255,178,0.04)); border-color: {SAFE}; }}
.verdict-suspicious {{ background: linear-gradient(135deg, rgba(255,200,87,0.14), rgba(255,200,87,0.04)); border-color: {SUSPICIOUS}; }}
.verdict-malicious {{ background: linear-gradient(135deg, rgba(255,77,77,0.16), rgba(255,77,77,0.05)); border-color: {MALICIOUS}; }}
.verdict-icon {{ font-size: 3rem; line-height: 1; }}
.verdict-name {{ font-size: 1.9rem; font-weight: 900; letter-spacing: 0.02em; }}
.verdict-desc {{ font-size: 0.9rem; color: #B9C5DC; margin-top: 5px; max-width: 560px; }}
.verdict-score {{ margin-left: auto; text-align: right; }}
.verdict-num {{ font-size: 3rem; font-weight: 900; line-height: 1; }}
.verdict-cap {{ font-size: 0.7rem; color: {MUTED}; text-transform: uppercase; letter-spacing: 0.1em; margin-top: 4px; }}

/* ── Metric cards ── */
.m-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 18px 0; }}
.m-card {{
    background: {CARD}; backdrop-filter: blur(14px);
    border: 1px solid {BORDER}; border-radius: 13px; padding: 16px 14px;
    position: relative; overflow: hidden; transition: transform 0.18s ease, box-shadow 0.2s ease;
}}
.m-card:hover {{ transform: translateY(-3px); box-shadow: 0 10px 26px rgba(0,0,0,0.45); }}
.m-card::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; }}
.m-card.g::before {{ background: {SAFE}; }} .m-card.y::before {{ background: {SUSPICIOUS}; }}
.m-card.r::before {{ background: {MALICIOUS}; }} .m-card.c::before {{ background: {CYAN}; }}
.m-ico {{ font-size: 1.3rem; }} .m-lab {{ font-size: 0.68rem; color: {MUTED}; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 6px; }}
.m-val {{ font-size: 1.5rem; font-weight: 800; color: #fff; margin: 4px 0 2px; }}
.m-sub {{ font-size: 0.76rem; color: {MUTED}; }}

/* ── Payload / badges / factors ── */
.payload-box {{
    background: #060B16; border: 1px solid {BORDER}; border-left: 3px solid {CYAN};
    border-radius: 10px; padding: 14px 18px; font-family: ui-monospace, 'Cascadia Code', Consolas, monospace;
    font-size: 0.87rem; color: {CYAN}; word-break: break-all; margin: 10px 0;
}}
.qr-badge {{
    display: inline-flex; align-items: center; gap: 6px; padding: 5px 14px; border-radius: 20px;
    font-size: 0.8rem; font-weight: 800; letter-spacing: 0.04em; margin: 8px 0;
}}
.risk-factor {{
    background: #101829; border: 1px solid {BORDER}; border-left: 3.5px solid;
    border-radius: 10px; padding: 13px 16px; margin: 9px 0; transition: transform 0.15s ease;
}}
.risk-factor:hover {{ transform: translateX(3px); }}
.f-critical {{ border-left-color: {MALICIOUS}; }} .f-high {{ border-left-color: #FF8A3D; }}
.f-medium {{ border-left-color: {SUSPICIOUS}; }} .f-low {{ border-left-color: {CYAN}; }}
.f-title {{ font-weight: 700; font-size: 0.88rem; color: #fff; }}
.f-reason {{ font-size: 0.8rem; color: #A9B7D4; margin-top: 3px; }}
.guide {{
    background: #101829; border: 1px solid #23405E; border-radius: 10px;
    padding: 11px 15px; margin: 7px 0; font-size: 0.86rem; color: #B9C5DC;
}}
.step-row {{
    display: flex; align-items: center; gap: 10px; padding: 9px 14px; margin: 6px 0;
    background: #101829; border: 1px solid {BORDER}; border-radius: 10px; font-size: 0.86rem;
}}
.step-done {{ border-color: {SAFE} !important; }} .step-run {{ border-color: {CYAN} !important; box-shadow: 0 0 12px rgba(0,209,255,0.2); }}

/* ── Tabs / inputs / tables ── */
.stTabs [data-baseweb="tab-list"] {{ gap: 8px !important; border-bottom: 1px solid {BORDER} !important; padding-bottom: 10px; }}
.stTabs [data-baseweb="tab"] {{
    background: #101829 !important; color: {MUTED} !important; border: 1px solid {BORDER} !important;
    border-radius: 11px !important; padding: 9px 18px !important; font-weight: 700 !important; font-size: 0.85rem !important;
    transition: all 0.18s ease !important;
}}
.stTabs [data-baseweb="tab"]:hover {{ color: #fff !important; border-color: {CYAN} !important; }}
.stTabs [aria-selected="true"] {{
    background: linear-gradient(135deg, rgba(0,209,255,0.18), rgba(124,58,237,0.16)) !important;
    color: {CYAN} !important; border-color: {CYAN} !important;
}}
div[data-testid="stTextInput"] input, div[data-testid="stTextArea"] textarea {{
    background: #0A1120 !important; color: #E6EEFB !important;
    border: 1px solid #2B3D63 !important; border-radius: 11px !important;
}}
div[data-testid="stTextInput"] input:focus, div[data-testid="stTextArea"] textarea:focus {{
    border-color: {CYAN} !important; box-shadow: 0 0 0 1px #00D1FF66;
}}
div[data-testid="stSelectbox"] div[data-baseweb="select"] > div {{
    background: #0A1120 !important; color: #E6EEFB !important;
    border-color: #2B3D63 !important; border-radius: 11px !important;
}}
div[data-testid="stMetric"] {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 13px; padding: 12px 14px; }}
div[data-testid="stMetric"] label {{ color: {MUTED} !important; }}
div[data-testid="stMetric"] [data-testid="stMetricValue"] {{ color: #fff !important; }}
div[data-testid="stExpander"] {{ background: {CARD} !important; border: 1px solid {BORDER} !important; border-radius: 13px !important; }}
div[data-testid="stAlert"] {{
    background: #101829 !important; border: 1px solid {BORDER} !important;
    border-left: 3.5px solid {CYAN} !important; border-radius: 11px !important; color: #DCE6F5 !important;
}}
div[data-testid="stDataFrame"], div[data-testid="stTable"] {{ border-radius: 13px; overflow: hidden; }}
div[data-testid="stImage"] img {{ border-radius: 14px !important; border: 1px solid {BORDER} !important; }}
div[data-testid="stSpinner"] p {{ color: {CYAN} !important; font-weight: 700 !important; animation: spinPulse 1.2s ease-in-out infinite; }}
div[data-testid="stProgress"] > div > div > div {{ background: linear-gradient(90deg, {CYAN}, #7c3aed) !important; }}
footer {{ visibility: hidden; }}
@media (max-width: 768px) {{ .verdict-banner {{ flex-direction: column; text-align: center; }} .verdict-score {{ margin-left: 0; }} }}
</style>
""", unsafe_allow_html=True)

# ── Session state ──────────────────────────────────────────────────────────────
for _k, _v in [("scan_history", []), ("vt_api_key", ""),
               ("gsb_api_key", ""), ("urlhaus_auth_key", os.environ.get("URLHAUS_AUTH_KEY", "")),
               ("active_nav", "🔍 Scan & Analyze")]:
    if _k not in st.session_state:
        st.session_state[_k] = _v

NAV_OPTIONS = [
    "📊 Operations Dashboard",
    "🔍 Scan & Analyze",
    "📜 History & Analytics",
    "📄 Audit Reports",
    "⚙️ Model Benchmark",
]

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='padding: 14px 2px 10px 2px;'>
        <div class='brand-name'>🛡️ SENTINEL<span>-QR</span></div>
        <div class='brand-sub'>Threat Defense Platform · v3.0</div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()
    _idx = (NAV_OPTIONS.index(st.session_state["active_nav"])
            if st.session_state["active_nav"] in NAV_OPTIONS else 1)
    active_nav = st.radio("Navigate", NAV_OPTIONS, index=_idx, label_visibility="collapsed")
    st.session_state["active_nav"] = active_nav
    st.divider()
    with st.expander("🔑 API Credentials", expanded=False):
        _vt = st.text_input("VirusTotal API Key", value=st.session_state["vt_api_key"],
                            type="password")
        _gsb = st.text_input("Google Safe Browsing Key", value=st.session_state["gsb_api_key"],
                             type="password")
        _uh = st.text_input("URLhaus Auth-Key", value=st.session_state["urlhaus_auth_key"],
                            type="password")
        st.session_state["vt_api_key"] = _vt
        st.session_state["gsb_api_key"] = _gsb
        st.session_state["urlhaus_auth_key"] = _uh
        st.caption("Optional — the system works offline without keys. URLhaus needs a free "
                   "abuse.ch Auth-Key (or set URLHAUS_AUTH_KEY).")
    st.divider()
    st.markdown("<div class='brand-sub' style='margin-bottom:8px;'>Engine Status</div>",
                unsafe_allow_html=True)
    for _line in ["🟢 Ensemble (XGB + RF + LR)", "🟢 16-Rule Heuristics",
                  "🟢 URLhaus Feed", "🟢 UPI Fraud Engine",
                  "🟢 Wi-Fi Security Engine", "🟢 OpenCV Dual Decoder"]:
        st.markdown(f"<div style='font-size:0.82rem;color:{MUTED};padding:2px 0;'>{_line}</div>",
                    unsafe_allow_html=True)
    st.markdown(f"<div style='font-size:0.82rem;color:{MUTED};padding:2px 0;'>"
                f"{'🟢' if PYZBAR_AVAILABLE else '🟡'} pyzbar Fallback</div>",
                unsafe_allow_html=True)
    st.divider()
    if st.button("🗑️ Clear History", use_container_width=True):
        st.session_state["scan_history"] = []
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# SHARED HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def page_head(title_a, title_b, subtitle, pill):
    st.markdown(f"""
    <div class="page-head">
        <h1>{title_a} <span>{title_b}</span></h1>
        <p>{subtitle}</p>
        <span class="head-pill">{pill}</span>
    </div>
    """, unsafe_allow_html=True)


def verdict_style(verdict):
    if verdict in ["SAFE", "SECURE"]:
        return "verdict-safe", "✅", SAFE
    if verdict in ["SUSPICIOUS", "WEAK SECURITY"]:
        return "verdict-suspicious", "⚠️", SUSPICIOUS
    return "verdict-malicious", "🚨", MALICIOUS


def render_verdict_banner(verdict, score, desc):
    css_cls, icon, color = verdict_style(verdict)
    st.markdown(f"""
    <div class="verdict-banner {css_cls}">
        <div class="verdict-icon">{icon}</div>
        <div>
            <div class="verdict-name" style="color:{color}">{html_escape(str(verdict))}</div>
            <div class="verdict-desc">{html_escape(str(desc))}</div>
        </div>
        <div class="verdict-score">
            <div class="verdict-num" style="color:{color}">{score}<span style="font-size:1rem;color:{MUTED};">/100</span></div>
            <div class="verdict-cap">Threat Score</div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_risk_gauge(score, color):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": "Risk Level", "font": {"size": 14, "color": MUTED}},
        number={"suffix": "/100", "font": {"color": color, "size": 30}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#33415E",
                     "ticktext": ["Safe", "Suspicious", "Malicious"], "tickvals": [15, 45, 80]},
            "bar": {"color": color, "thickness": 0.24},
            "bgcolor": "#101829",
            "borderwidth": 1, "bordercolor": BORDER,
            "steps": [
                {"range": [0, 30], "color": "rgba(0,255,178,0.16)"},
                {"range": [30, 60], "color": "rgba(255,200,87,0.16)"},
                {"range": [60, 100], "color": "rgba(255,77,77,0.16)"},
            ],
            "threshold": {"line": {"color": "#ffffff", "width": 3}, "thickness": 0.85, "value": score},
        },
    ))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      height=250, margin=dict(l=20, r=20, t=30, b=10),
                      font=dict(color=MUTED))
    st.plotly_chart(fig, use_container_width=True)


def metric_cards(cards):
    """cards: list of (tone[g/y/r/c], icon, label, value, sub)."""
    html = '<div class="m-grid">'
    for tone, icon, label, value, sub in cards:
        html += f"""
        <div class="m-card {tone}">
            <div class="m-ico">{html_escape(str(icon))}</div>
            <div class="m-lab">{html_escape(str(label))}</div>
            <div class="m-val">{html_escape(str(value))}</div>
            <div class="m-sub">{html_escape(str(sub))}</div>
        </div>"""
    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)


def qr_badge(qr_type):
    colors = {QRType.URL: CYAN, QRType.UPI: VIOLET, QRType.WIFI: SUSPICIOUS,
              QRType.EMAIL: SAFE, QRType.PHONE: SUSPICIOUS, QRType.TEXT: MUTED}
    icons = {QRType.URL: "🌐", QRType.UPI: "💳", QRType.WIFI: "📶",
             QRType.EMAIL: "📧", QRType.PHONE: "📞", QRType.TEXT: "📄"}
    c = colors.get(qr_type, MUTED)
    st.markdown(f"""
    <span class="qr-badge" style="background:{c}1f;border:1px solid {c};color:{c};">
        {icons.get(qr_type, "📄")} {html_escape(str(qr_type))} PAYLOAD
    </span>""", unsafe_allow_html=True)


def log_history(qr_type, payload, verdict, score, source="Upload"):
    entry = {
        "Timestamp": time.strftime("%H:%M:%S"),
        "Source": source,
        "QR Type": qr_type,
        "Payload (short)": payload[:45] + "..." if len(payload) > 45 else payload,
        "Verdict": verdict,
        "Risk Score": score,
    }
    if (not st.session_state["scan_history"] or
            st.session_state["scan_history"][0].get("Payload (short)") != entry["Payload (short)"]):
        st.session_state["scan_history"].insert(0, entry)


# ── Staged pipeline with live step tracker ─────────────────────────────────────
STAGES = ["Decoding QR", "Extracting Features", "Running ML Model",
          "Applying Rules", "Fetching Threat Intel"]


def run_url_analysis(url, qr_image=None, tracker=None):
    """Full URL pipeline. tracker(step_idx, state) -> None for live UI steps."""
    def _mark(i, state):
        if tracker:
            tracker(i, state)

    _mark(0, "run")
    feats = extract_url_features(url)
    _mark(0, "done"); _mark(1, "run")
    rules_res = evaluate_rules(url, feats)
    _mark(1, "done"); _mark(2, "run")
    ml_res = predict_threat(url)
    _mark(2, "done"); _mark(3, "run")
    _mark(3, "done"); _mark(4, "run")
    try:
        intel_res = query_threat_intelligence(
            url, vt_api_key=st.session_state["vt_api_key"],
            gsb_api_key=st.session_state["gsb_api_key"],
            urlhaus_auth_key=st.session_state["urlhaus_auth_key"])
    except TypeError:
        intel_res = query_threat_intelligence(url, st.session_state["vt_api_key"])
    _mark(4, "done")
    try:
        risk_info = calculate_hybrid_risk_score(
            ml_res["malicious_prob"], rules_res["rule_score"], intel_res, qr_context_risk=0)
    except TypeError:
        risk_info = calculate_hybrid_risk_score(
            ml_res["malicious_prob"], rules_res["rule_score"], intel_res)
    xai = generate_explanation(risk_info, rules_res["triggered_rules"], feats, intel_res)
    domain = url.split("/")[2] if "//" in url else url.split("/")[0]
    ssl_info = check_ssl_certificate(domain)
    return {"url": url, "qr_type": QRType.URL, "feats": feats, "rules_res": rules_res,
            "ml_res": ml_res, "intel_res": intel_res, "risk_info": risk_info,
            "xai": xai, "ssl_info": ssl_info, "qr_image": qr_image}


def run_non_url_analysis(raw_text, qr_type, qr_image=None):
    result = None
    if qr_type == QRType.UPI:
        result = analyze_upi_payload(raw_text)
    elif qr_type == QRType.WIFI:
        result = analyze_wifi_payload(raw_text)
    elif qr_type == QRType.EMAIL:
        result = analyze_email_payload(raw_text)
    elif qr_type == QRType.PHONE:
        result = analyze_phone_payload(raw_text)
    if result:
        result["qr_type"] = qr_type
        result["qr_image"] = qr_image
        result["raw_text"] = raw_text
    return result


def live_tracker_box():
    """Returns (placeholder, progress, callback) rendering the 5-step tracker."""
    box = st.empty()
    prog = st.progress(0)

    def _cb(idx, state):
        rows = ""
        for i, name in enumerate(STAGES):
            if i < idx or (i == idx and state == "done"):
                rows += f"<div class='step-row step-done'>✅ {name} <span style='margin-left:auto;color:{SAFE};font-size:0.75rem;'>DONE</span></div>"
            elif i == idx:
                rows += f"<div class='step-row step-run'>🔄 {name} <span style='margin-left:auto;color:{CYAN};font-size:0.75rem;'>RUNNING…</span></div>"
            else:
                rows += f"<div class='step-row'>⏳ {name}</div>"
        box.markdown(rows, unsafe_allow_html=True)
        prog.progress(min(100, int((idx + (1 if state == "done" else 0)) / len(STAGES) * 100)))

    _cb(0, "run")
    return box, prog, _cb


# ── Result renderers ───────────────────────────────────────────────────────────
def render_overview_tab(res):
    ri = res["risk_info"]
    c1, c2 = st.columns([1, 1])
    with c1:
        _, color = verdict_style(ri["verdict"])[:1], ri["verdict_color"]
        render_risk_gauge(ri["final_score"], color)
    with c2:
        comp = pd.DataFrame([
            {"Component": "ML Model · 50%", "Score": ri["ml_component"]},
            {"Component": "Heuristics · 30%", "Score": ri["rule_component"]},
            {"Component": "Threat Intel · 10%", "Score": ri["intel_component"]},
            {"Component": "QR Context · 10%", "Score": ri["context_component"]},
        ])
        fig = px.bar(comp, x="Score", y="Component", orientation="h", text="Score",
                     color="Component",
                     color_discrete_sequence=[CYAN, VIOLET, SUSPICIOUS, SAFE])
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          font=dict(color=MUTED), height=240, showlegend=False,
                          margin=dict(l=0, r=20, t=30, b=0),
                          xaxis=dict(range=[0, 55], showgrid=True, gridcolor="#1E2A45"),
                          title=dict(text="Hybrid Score Components", font=dict(color="#fff", size=13)))
        st.plotly_chart(fig, use_container_width=True)


def render_xai_factors(xai, rules_res):
    st.markdown("#### 🔍 Why was this flagged?")
    top5 = xai.get("top_5_factors", [])
    if top5:
        for f in top5:
            sev = f.get("severity", "LOW").lower()
            css = {"critical": "f-critical", "high": "f-high",
                   "medium": "f-medium"}.get(sev, "f-low")
            col = { "critical": MALICIOUS, "high": "#FF8A3D",
                    "medium": SUSPICIOUS}.get(sev, CYAN)
            pct = min(100, int(f["weight"] / 35 * 100))
            st.markdown(f"""
            <div class="risk-factor {css}">
              <div class="f-title" style="color:{col}">{html_escape(str(f.get('factor', 'Risk factor')))}
                <span style="font-size:0.7rem;background:{col}22;color:{col};padding:2px 9px;border-radius:10px;">{html_escape(str(f.get('severity', 'LOW')))}</span>
                <span style="font-size:0.7rem;color:{MUTED};"> · impact {pct}%</span>
              </div>
              <div class="f-reason">{html_escape(str(f.get('reason', '')))}</div>
            </div>""", unsafe_allow_html=True)
    else:
        st.success("✓ No elevated risk factors — clean profile.")
    st.markdown("#### 🛡️ What should you do?")
    for g in xai.get("guidance", []):
        st.markdown(f"<div class='guide'>{html_escape(str(g))}</div>", unsafe_allow_html=True)
    if rules_res.get("triggered_rules"):
        st.markdown("#### ⚠️ Triggered Heuristic Rules")
        rows = [{"Rule": r.get("name", ""), "Severity": r.get("severity", ""),
                 "Points": f"+{r.get('points', 0)}", "Evidence": r.get("reason", "")}
                for r in rules_res["triggered_rules"]]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render_feature_importance():
    try:
        imps = get_model_metadata().get("ensemble_metrics", {}).get("feature_importances", {})
    except Exception:
        imps = {}
    if not imps:
        st.info("Feature importances unavailable — retrain to populate.")
        return
    top = sorted(imps.items(), key=lambda x: x[1], reverse=True)[:10]
    df = pd.DataFrame([{"Feature": k, "Importance": v} for k, v in top])
    fig = px.bar(df, x="Importance", y="Feature", orientation="h", text="Importance",
                 color="Importance", color_continuous_scale=[[0, "#1E2A45"], [1, CYAN]])
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(color=MUTED), height=320, showlegend=False,
                      margin=dict(l=0, r=20, t=30, b=0),
                      title=dict(text="Top-10 Model Features (XGBoost)",
                                 font=dict(color="#fff", size=13)))
    st.plotly_chart(fig, use_container_width=True)


def render_url_results(res):
    ri = res["risk_info"]
    ml_res, rules_res, intel_res, ssl_info = (res["ml_res"], res["rules_res"],
                                             res["intel_res"], res["ssl_info"])
    render_verdict_banner(ri["verdict"], ri["final_score"], ri["verdict_description"])

    ssl_ok = ssl_info.get("ssl_valid", False)
    intel_card = summarize_intel_status(intel_res)
    metric_cards([
        ("c", "🤖", "ML Probability", f"{ml_res['malicious_prob']*100:.1f}%",
         f"{ml_res.get('confidence_pct', 0):.0f}% confidence"),
        ("y", "📏", "Heuristic Score", f"{rules_res['rule_score']}",
         f"{rules_res['rule_count']} rules triggered"),
        (intel_card["tone"], "🌐", "Threat Intel", intel_card["label"], intel_card["detail"]),
        ("g" if ssl_ok else "y", "🔒", "SSL Security",
         "Valid" if ssl_ok else "No TLS", str(ssl_info.get("issuer", "N/A"))[:18]),
    ])

    t1, t2, t3, t4 = st.tabs(["📊 Overview", "🧠 AI Explanation", "🌐 Network Info", "🧾 Raw Features"])
    with t1:
        render_overview_tab(res)
    with t2:
        render_xai_factors(res["xai"], rules_res)
        st.divider()
        render_feature_importance()
    with t3:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("##### 🔒 SSL Certificate")
            for k, v in ssl_info.items():
                if k != "error":
                    st.markdown(f"**{k.replace('_', ' ').title()}:** `{v}`")
        with c2:
            st.markdown("##### 📡 Threat Intelligence")
            st.markdown(f"**URLhaus:** `{intel_res.get('urlhaus', {}).get('status', 'N/A')}`")
            if intel_res.get("virustotal"):
                st.markdown(f"**VirusTotal:** `{intel_res['virustotal'].get('status', 'Skipped')}`")
            if intel_res.get("google_safebrowsing"):
                st.markdown(f"**Safe Browsing:** `{intel_res['google_safebrowsing'].get('status', 'Skipped')}`")
    with t4:
        feat_df = pd.DataFrame([res["feats"]]).T.reset_index()
        feat_df.columns = ["Feature", "Value"]
        st.dataframe(feat_df, use_container_width=True, height=380, hide_index=True)


def render_non_url_results(res):
    verdict, score = res.get("verdict", "SAFE"), res.get("risk_score", 0)
    _cls, _ic, color = verdict_style(verdict)
    render_verdict_banner(verdict, score, res.get("summary", ""))
    render_risk_gauge(score, color)
    st.markdown("#### 🔬 Decoded Payload Fields")
    parsed = {k: str(v) for k, v in res.get("parsed_data", {}).items()
              if k not in ["raw_uri", "raw_string", "raw"]}
    if parsed:
        p_df = pd.DataFrame([parsed]).T.reset_index()
        p_df.columns = ["Field", "Value"]
        st.dataframe(p_df, use_container_width=True, hide_index=True)
    flags = res.get("red_flags", [])
    if flags:
        st.markdown("#### 🚨 Security Red Flags")
        for fl in flags:
            sev = fl.get("severity", "MEDIUM").lower()
            css = {"critical": "f-critical", "high": "f-high",
                   "medium": "f-medium"}.get(sev, "f-low")
            col = {"critical": MALICIOUS, "high": "#FF8A3D",
                   "medium": SUSPICIOUS}.get(sev, CYAN)
            st.markdown(f"""
            <div class="risk-factor {css}">
              <div class="f-title" style="color:{col}">{html_escape(str(fl.get('title', 'Alert')))}
                <span style="font-size:0.7rem;background:{col}22;color:{col};padding:2px 9px;border-radius:10px;">+{fl.get('points', 0)} pts · {html_escape(str(fl.get('severity', '')))}</span>
              </div>
              <div class="f-reason">{html_escape(str(fl.get('description', '')))}</div>
            </div>""", unsafe_allow_html=True)
    else:
        st.success("✓ No security red flags in this payload.")
    st.markdown("#### 🛡️ What should you do?")
    for g in res.get("actionable_guidance", []):
        st.markdown(f"<div class='guide'>{html_escape(str(g))}</div>", unsafe_allow_html=True)


def pdf_download(payload, qr_type, score, verdict, ml_prob, rule_score, rules, intel, img,
                 report_note=None):
    pdf = generate_security_pdf_report(
        payload=payload, qr_type=qr_type, risk_score=score, verdict=verdict,
        ml_prob=ml_prob, rule_score=rule_score, triggered_rules=rules,
        threat_intel=intel, qr_image_pil=img, report_note=report_note)
    st.download_button("📥 Generate Security Report (PDF)", data=pdf,
                       file_name=f"SentinelQR_Report_{int(time.time())}.pdf",
                       mime="application/pdf", use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# VIEW 1 · OPERATIONS DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
if active_nav == "📊 Operations Dashboard":
    page_head("Operations", "Dashboard",
              "Real-time security posture, engine telemetry and threat distribution.",
              "● COMMAND CENTER · LIVE")

    h = st.session_state["scan_history"]
    total = len(h)
    safe_n = sum(1 for x in h if x.get("Verdict", "").upper() in ["SAFE", "SECURE"])
    sus_n = sum(1 for x in h if x.get("Verdict", "").upper() in ["SUSPICIOUS", "WEAK SECURITY"])
    mal_n = total - safe_n - sus_n

    c = st.columns(4)
    for col, (t, v, tone) in zip(c, [
            ("Total Scans", total, "c"), ("✅ Safe", safe_n, "g"),
            ("⚠️ Suspicious", sus_n, "y"), ("🚨 Malicious / Fraud", mal_n, "r")]):
        with col:
            st.markdown(f"""<div class="m-card {tone}"><div class="m-lab">{t}</div>
                <div class="m-val">{v}</div></div>""", unsafe_allow_html=True)

    if total:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("<div class='glass'><h4>Threat Distribution</h4>", unsafe_allow_html=True)
            fig = go.Figure(go.Pie(
                labels=["Safe / Secure", "Suspicious", "Malicious / Fraud"],
                values=[safe_n, sus_n, mal_n], hole=0.58,
                marker=dict(colors=[SAFE, SUSPICIOUS, MALICIOUS],
                            line=dict(color=BG, width=2))))
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font=dict(color=MUTED),
                              height=270, margin=dict(l=0, r=0, t=10, b=0), showlegend=True,
                              legend=dict(font=dict(color=MUTED)))
            st.plotly_chart(fig, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
        with c2:
            st.markdown("<div class='glass'><h4>Scans by QR Type</h4>", unsafe_allow_html=True)
            tc = {}
            for x in h:
                tc[x.get("QR Type", "Unknown")] = tc.get(x.get("QR Type", "Unknown"), 0) + 1
            fig = px.bar(x=list(tc.keys()), y=list(tc.values()),
                         labels={"x": "QR Type", "y": "Count"},
                         color=list(tc.values()),
                         color_continuous_scale=[[0, "#1E2A45"], [1, CYAN]])
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              font=dict(color=MUTED), height=270, showlegend=False,
                              margin=dict(l=0, r=0, t=10, b=0),
                              xaxis=dict(showgrid=False), yaxis=dict(showgrid=True, gridcolor="#1E2A45"))
            st.plotly_chart(fig, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div class='glass'><h4>Recent Scans</h4>", unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(h[:8]), use_container_width=True, hide_index=True)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("🔍 No scans yet this session — head to **Scan & Analyze** to run your first analysis.")

    st.divider()
    meta = get_model_metadata().get("ensemble_metrics", {})
    st.markdown("##### 🤖 ML Engine Telemetry")
    mc = st.columns(5)
    for col, (lab, key) in zip(mc, [("Accuracy", "accuracy"), ("Precision", "precision"),
                                    ("Recall", "recall"), ("F1 Score", "f1"), ("ROC-AUC", "roc_auc")]):
        with col:
            v = meta.get(key, 0)
            st.metric(lab, f"{v*100:.2f}%" if key == "accuracy" else f"{v:.4f}")


# ══════════════════════════════════════════════════════════════════════════════
# VIEW 2 · SCAN & ANALYZE
# ══════════════════════════════════════════════════════════════════════════════
elif active_nav == "🔍 Scan & Analyze":
    page_head("Scan", "& Analyze",
              "Multi-type QR intelligence — URL · UPI · Wi-Fi · Email · Phone.",
              "● THREAT ANALYZER · READY")

    mode = st.segmented_control(
        "Input method",
        ["📁 Upload Image", "📷 Webcam", "⚡ Demo Samples", "🔗 Direct URL", "📦 Batch Scan"],
        default="📁 Upload Image", label_visibility="collapsed")

    image_in, direct_in, source = None, None, None

    if mode == "📁 Upload Image":
        st.markdown("""<div class="drop-hint"><div class="big">📤</div>
            <div class="t1">Drag &amp; Drop QR Code Here — or Click to Upload</div>
            <div class="t2">Supported formats · PNG · JPG · JPEG · WEBP</div></div>""",
                    unsafe_allow_html=True)
        up = st.file_uploader("QR image", type=["png", "jpg", "jpeg", "webp"],
                              label_visibility="collapsed")
        if up:
            image_in = Image.open(up)
            source = f"File: {up.name}"

    elif mode == "📷 Webcam":
        st.markdown("""<div class="drop-hint"><div class="big">📷</div>
            <div class="t1">Point your camera at a printed QR code</div>
            <div class="t2">Hold steady · ensure good lighting</div></div>""",
                    unsafe_allow_html=True)
        cam = st.camera_input("Capture QR frame", label_visibility="collapsed")
        if cam:
            image_in = Image.open(cam)
            source = "Webcam Capture"

    elif mode == "⚡ Demo Samples":
        presets = {
            "✅ Safe Academic URL (Wikipedia)": ("1_safe_wikipedia.png", "SAFE · ~1/100"),
            "🚨 Malicious Phishing (PayPal Spoof)": ("5_malicious_paypal_spoof.png", "MALICIOUS · ~71/100"),
            "🚨 UPI Payment Fraud (Cashback Scam)": ("7_upi_fraud.png", "FRAUD RISK · 100/100"),
            "🚨 Rogue Open Wi-Fi (Evil Twin)": ("8_rogue_wifi.png", "CRITICAL · 90/100"),
            "⚠️ Suspicious URL Shortener": ("3_suspicious_shortener.png", "SUSPICIOUS · ~36/100"),
            "🚨 Malicious IP Phish (:8080)": ("4_malicious_ip_phish.png", "MALICIOUS · high"),
            "✅ Safe Developer URL (GitHub)": ("2_safe_github.png", "SAFE · low"),
            "⚠️ Phishing Email QR (mailto lure)": ("9_phishing_email.png", "SUSPICIOUS · medium"),
        }
        dc = st.columns(4)
        for i, (label, (_, expect)) in enumerate(presets.items()):
            with dc[i % 4]:
                st.markdown(f"""<div class="m-card c"><div class="m-lab">{expect}</div>
                    <div class="m-val" style="font-size:0.95rem;">{label}</div></div>""",
                            unsafe_allow_html=True)
        sel = st.selectbox("Choose a scenario:", list(presets.keys()))
        if st.button("🚀 Run Demo Analysis", type="primary", use_container_width=True):
            path = os.path.join(SAMPLES_DIR, presets[sel][0])
            if os.path.exists(path):
                image_in = Image.open(path)
                source = f"Demo: {sel[:35]}..."
            else:
                st.error("❌ Demo file missing — run `python generate_demo_qrs.py` first.")

    elif mode == "🔗 Direct URL":
        direct_in = st.text_area(
            "Payload",
            placeholder="https://example.com  ·  upi://pay?pa=test@ybl&pn=Test&am=100  ·  WIFI:T:WPA;S:Net;P:Pass;;",
            height=90, label_visibility="collapsed")
        if st.button("🔍 Analyze Payload", type="primary", use_container_width=True):
            if direct_in and direct_in.strip():
                direct_in = direct_in.strip()
                source = "Direct Input"
            else:
                st.warning("⚠️ Paste a URL or payload first.")

    elif mode == "📦 Batch Scan":
        files = st.file_uploader("Multiple QR images", type=["png", "jpg", "jpeg", "webp"],
                                 accept_multiple_files=True, key="batch",
                                 label_visibility="collapsed")
        if files and st.button("⚡ Run Batch Audit", type="primary", use_container_width=True):
            rows, prog = [], st.progress(0)
            with st.status("🔍 Auditing batch…", expanded=False) as _st:
                for i, bf in enumerate(files):
                    try:
                        decoded, _, _ = decode_qr_code(Image.open(bf))
                        if decoded:
                            qt = detect_qr_type(decoded)
                            if qt == QRType.URL:
                                v = validate_and_clean_url(decoded)
                                if v["is_valid_url"]:
                                    u = v["cleaned_url"]
                                    f = extract_url_features(u)
                                    r = evaluate_rules(u, f)
                                    m = predict_threat(u)
                                    t = query_threat_intelligence(
                                        u, vt_api_key=st.session_state["vt_api_key"],
                                        gsb_api_key=st.session_state["gsb_api_key"],
                                        urlhaus_auth_key=st.session_state["urlhaus_auth_key"])
                                    try:
                                        hh = calculate_hybrid_risk_score(
                                            m["malicious_prob"], r["rule_score"], t)
                                    except TypeError:
                                        hh = calculate_hybrid_risk_score(
                                            m["malicious_prob"], r["rule_score"],
                                            t, qr_context_risk=0)
                                    rows.append({"File": bf.name, "QR Type": "URL",
                                                 "Verdict": hh["verdict"],
                                                 "Risk Score": hh["final_score"],
                                                 "ML %": f"{m['malicious_prob']*100:.1f}%",
                                                 "Rules": r["rule_count"]})
                                    log_history("URL", u, hh["verdict"], hh["final_score"], "Batch")
                            elif qt in [QRType.UPI, QRType.WIFI, QRType.EMAIL, QRType.PHONE]:
                                rr = run_non_url_analysis(decoded, qt)
                                rows.append({"File": bf.name, "QR Type": qt,
                                             "Verdict": rr["verdict"], "Risk Score": rr["risk_score"],
                                             "ML %": "N/A", "Rules": len(rr.get("red_flags", []))})
                            else:
                                rows.append({"File": bf.name, "QR Type": qt, "Verdict": "NON-URL",
                                             "Risk Score": 0, "ML %": "N/A", "Rules": 0})
                        else:
                            rows.append({"File": bf.name, "QR Type": "DECODE_ERR",
                                         "Verdict": "ERROR", "Risk Score": 0, "ML %": "N/A", "Rules": 0})
                    except Exception:
                        rows.append({"File": bf.name, "QR Type": "ERROR",
                                     "Verdict": "ERROR", "Risk Score": 0, "ML %": "N/A", "Rules": 0})
                    prog.progress((i + 1) / len(files))
            st.success(f"✅ Batch audit complete — {len(rows)} items.")
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    # ── Decode + analyze ──────────────────────────────────────────────────────
    raw_decoded, annotated, engine = None, None, None
    if image_in is not None:
        st.divider()
        cL, cR = st.columns([1, 2])
        with cL:
            st.markdown("#### 📷 Captured Input")
            try:
                raw_decoded, annotated, engine = decode_qr_code(image_in)
            except Exception as e:
                st.error(f"❌ Decoder error: {e}")
            st.image(annotated if annotated is not None else image_in,
                     caption=f"Decoder: {engine}" if engine else "Original",
                     use_container_width=True)
        with cR:
            if raw_decoded:
                qr_badge(detect_qr_type(raw_decoded))
                st.markdown(f'<div class="payload-box">{html_escape(raw_decoded)}</div>',
                            unsafe_allow_html=True)
                direct_in = raw_decoded
            else:
                st.error("❌ No QR code detected — use a clear, well-lit, unobstructed image.")

    payload = direct_in or raw_decoded
    if payload and (direct_in or image_in is not None):
        qt = detect_qr_type(payload)
        if qt == QRType.URL:
            v = validate_and_clean_url(payload)
            if not v["is_valid_url"]:
                st.warning(f"⚠️ URL validation failed: {v['error_message']}")
            else:
                st.divider()
                st.markdown("## 🔬 Hybrid URL Threat Analysis")
                box, prog, cb = live_tracker_box()
                try:
                    res = run_url_analysis(v["cleaned_url"], annotated, tracker=cb)
                finally:
                    box.empty()
                    prog.empty()
                render_url_results(res)
                log_history("URL", v["cleaned_url"], res["risk_info"]["verdict"],
                            res["risk_info"]["final_score"], source or "Direct")
                st.divider()
                with st.container():
                    st.markdown("<div class='glass'><h4>📄 Audit Report</h4>"
                                "<p style='color:#8B98B8;font-size:0.85rem;'>Formal hash-stamped PDF with "
                                "verdict, evidence table and mitigation guidance.</p>",
                                unsafe_allow_html=True)
                    pdf_download(v["cleaned_url"], "Web URL",
                                 res["risk_info"]["final_score"], res["risk_info"]["verdict"],
                                 res["ml_res"]["malicious_prob"], res["rules_res"]["rule_score"],
                                 res["rules_res"]["triggered_rules"], res["intel_res"], annotated)
                    st.markdown("</div>", unsafe_allow_html=True)
        elif qt in [QRType.UPI, QRType.WIFI, QRType.EMAIL, QRType.PHONE]:
            st.divider()
            titles = {QRType.UPI: "💳 UPI Payment Fraud Analysis",
                      QRType.WIFI: "📶 Wi-Fi Security Assessment",
                      QRType.EMAIL: "📧 Email Threat Inspection",
                      QRType.PHONE: "📞 Phone Security Check"}
            st.markdown(f"## {titles.get(qt, '🔍 Payload Analysis')}")
            with st.status("⚡ Running domain security checks…", expanded=False) as _st:
                res = run_non_url_analysis(payload, qt, annotated)
                _st.update(label="✅ Domain analysis complete", state="complete")
            if res:
                render_non_url_results(res)
                log_history(qt, payload, res["verdict"], res["risk_score"], source or "Direct")
                st.divider()
                pdf_download(payload, qt, res["risk_score"], res["verdict"], 0.0,
                             res["risk_score"], res.get("red_flags", []),
                             {"status": "Domain-Specific Engine",
                              "is_blacklisted": res["risk_score"] > 60}, annotated)
        else:
            st.divider()
            st.markdown("#### 📄 Plain Text Payload")
            st.info("Unrecognized type — no threat model applies. Content shown verbatim:")
            st.code(payload, language="text")


# ══════════════════════════════════════════════════════════════════════════════
# VIEW 3 · HISTORY & ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════
elif active_nav == "📜 History & Analytics":
    page_head("History", "& Analytics",
              "Session telemetry, verdict trends and payload breakdown.",
              "● ANALYTICS · SESSION")
    h = st.session_state["scan_history"]
    if not h:
        st.info("📭 No scans yet — run analyses in **Scan & Analyze** to populate this view.")
    else:
        total = len(h)
        safe_n = sum(1 for x in h if "SAFE" in x.get("Verdict", "").upper()
                     or "SECURE" in x.get("Verdict", "").upper())
        sus_n = sum(1 for x in h if "SUSPICIOUS" in x.get("Verdict", "").upper()
                    or "WEAK" in x.get("Verdict", "").upper())
        mal_n = total - safe_n - sus_n
        mc = st.columns(4)
        for col, (t, vv, tone) in zip(mc, [("Total Scans", total, "c"),
                                           ("✅ Safe / Secure", safe_n, "g"),
                                           ("⚠️ Suspicious", sus_n, "y"),
                                           ("🚨 Malicious / Fraud", mal_n, "r")]):
            with col:
                st.markdown(f"""<div class="m-card {tone}"><div class="m-lab">{t}</div>
                    <div class="m-val">{vv}</div></div>""", unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("<div class='glass'><h4>Verdict Distribution</h4>", unsafe_allow_html=True)
            fig = go.Figure(go.Pie(
                labels=["Safe / Secure", "Suspicious", "Malicious / Fraud"],
                values=[safe_n, sus_n, mal_n], hole=0.58,
                marker=dict(colors=[SAFE, SUSPICIOUS, MALICIOUS],
                            line=dict(color=BG, width=2))))
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font=dict(color=MUTED),
                              height=270, margin=dict(l=0, r=0, t=10, b=0))
            st.plotly_chart(fig, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
        with c2:
            st.markdown("<div class='glass'><h4>Risk Score Distribution</h4>", unsafe_allow_html=True)
            scores = [x.get("Risk Score", 0) for x in h
                      if isinstance(x.get("Risk Score"), int)]
            if scores:
                fig = px.histogram(x=scores, nbins=10, labels={"x": "Risk Score"},
                                   color_discrete_sequence=[CYAN])
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                  font=dict(color=MUTED), height=270, showlegend=False,
                                  margin=dict(l=0, r=0, t=10, b=0),
                                  xaxis=dict(showgrid=False, range=[0, 100]),
                                  yaxis=dict(showgrid=True, gridcolor="#1E2A45"))
                st.plotly_chart(fig, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='glass'><h4>📋 Scan Records</h4>", unsafe_allow_html=True)
        f1, f2 = st.columns([1, 2])
        with f1:
            vf = st.selectbox("Filter by verdict:",
                              ["All", "SAFE", "SECURE", "SUSPICIOUS",
                               "WEAK SECURITY", "MALICIOUS", "FRAUD RISK", "CRITICAL RISK"])
        with f2:
            q = st.text_input("🔍 Search:", placeholder="URL, QR type, source…",
                              label_visibility="collapsed")
        df = pd.DataFrame(h)
        if vf != "All":
            df = df[df["Verdict"] == vf]
        if q:
            df = df[df.apply(lambda r: r.astype(str).str.contains(q, case=False).any(), axis=1)]
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button("📥 Export Filtered CSV", data=df.to_csv(index=False).encode(),
                           file_name="sentinel_qr_history.csv", mime="text/csv",
                           use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# VIEW 4 · AUDIT REPORTS
# ══════════════════════════════════════════════════════════════════════════════
elif active_nav == "📄 Audit Reports":
    page_head("Audit", "Reports",
              "Generate formal forensic documentation for incidents and reviews.",
              "● FORENSICS · PDF")
    st.markdown("<div class='glass'><h4>📝 Custom Audit Report</h4>", unsafe_allow_html=True)
    r_url = st.text_input("Target URL or payload:",
                          placeholder="https://suspicious-domain.xyz/login.php")
    c1, c2 = st.columns(2)
    with c1:
        r_verdict = st.selectbox("Verdict:", ["SAFE", "SUSPICIOUS", "MALICIOUS"])
        r_score = st.slider("Risk score:", 0, 100, 75)
    with c2:
        r_ml = st.slider("ML probability (%):", 0.0, 100.0, 80.0) / 100.0
        r_rules = st.slider("Heuristic penalty:", 0, 100, 60)
    if st.button("📄 Generate Formal Audit Report", type="primary", use_container_width=True):
        if r_url:
            pdf_download(r_url, "Web URL (Manual Entry)", r_score, r_verdict,
                         r_ml, r_rules, [],
                         {"status": "Manual Report", "is_blacklisted": r_verdict == "MALICIOUS"},
                         None,
                         report_note=("Manual entry: the URL, score, and verdict were supplied by "
                                      "the user. This report is not the output of an automated scan."))
            st.success("✅ Report ready — use the download button above.")
        else:
            st.warning("⚠️ Enter a target URL or payload first.")
    st.markdown("</div>", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# VIEW 5 · MODEL BENCHMARK
# ══════════════════════════════════════════════════════════════════════════════
elif active_nav == "⚙️ Model Benchmark":
    page_head("Model", "Insights",
              "Weighted soft-voting ensemble vs. individual baselines.",
              "● ACADEMIC REVIEW · METRICS")
    meta = get_model_metadata()
    ens = meta.get("ensemble_metrics", {})
    rows = []
    for label, md in [("🏆 Voting Ensemble (Primary)", ens),
                      ("XGBoost", meta.get("xgboost_metrics", {})),
                      ("Random Forest", meta.get("random_forest_metrics", {})),
                      ("Logistic Regression", meta.get("logistic_regression_metrics", {}))]:
        rows.append({"Model": label,
                     "Accuracy": f"{md.get('accuracy', 0)*100:.2f}%",
                     "Precision": f"{md.get('precision', 0):.4f}",
                     "Recall": f"{md.get('recall', 0):.4f}",
                     "F1": f"{md.get('f1', 0):.4f}",
                     "ROC-AUC": f"{md.get('roc_auc', 0):.4f}"})
    st.markdown("<div class='glass'><h4>📊 Benchmark Comparison</h4>", unsafe_allow_html=True)
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("<div class='glass'><h4>🧠 What the Model Looks At</h4>", unsafe_allow_html=True)
    render_feature_importance()
    st.markdown("</div>", unsafe_allow_html=True)
    with st.expander("📦 Dataset & Training Spec"):
        st.markdown(f"**Samples:** `{meta.get('dataset_samples', meta.get('dataset_size', 'N/A'))}`  ·  "
                    f"**Features:** `{meta.get('feature_count', meta.get('n_features', 36))}`  ·  "
                    f"**Split:** stratified 80/20  ·  "
                    f"**CV accuracy:** `{meta.get('cv_accuracy_mean', 'N/A')}`")
