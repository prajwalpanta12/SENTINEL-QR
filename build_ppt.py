"""Build Review-I presentation draft for AI-Based QR Code Threat Analyzer."""
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

NAVY = RGBColor(7, 11, 20)
CYAN = RGBColor(56, 189, 248)
WHITE = RGBColor(255, 255, 255)
MUTED = RGBColor(148, 163, 184)
CARD = RGBColor(13, 21, 38)
VIOLET = RGBColor(167, 139, 250)
GREEN = RGBColor(16, 185, 129)
AMBER = RGBColor(245, 158, 11)
RED = RGBColor(239, 68, 68)

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
BLANK = prs.slide_layouts[6]


def new_slide():
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid()
    s.background.fill.fore_color.rgb = NAVY
    # top accent bar
    bar = s.shapes.add_shape(1, Inches(0), Inches(0), prs.slide_width, Pt(5))
    bar.fill.solid()
    bar.fill.fore_color.rgb = CYAN
    bar.line.fill.background()
    # footer
    foot = s.shapes.add_textbox(Inches(0.5), Inches(7.0), Inches(12.3), Inches(0.4))
    tf = foot.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = f"BCSE410L Cyber Security \u2014 Review I  |  AI-Based QR Code Threat Analyzer  |  Slide {len(prs.slides)}"
    p.font.size = Pt(9)
    p.font.color.rgb = MUTED
    return s


def title_block(s, kicker, title, subtitle=None):
    kick = s.shapes.add_textbox(Inches(0.7), Inches(0.5), Inches(11.9), Inches(0.4))
    r = kick.text_frame.paragraphs[0]
    r.text = kicker.upper()
    r.font.size = Pt(13)
    r.font.bold = True
    r.font.color.rgb = CYAN
    t = s.shapes.add_textbox(Inches(0.7), Inches(0.9), Inches(11.9), Inches(0.9))
    r = t.text_frame.paragraphs[0]
    r.text = title
    r.font.size = Pt(32)
    r.font.bold = True
    r.font.color.rgb = WHITE
    if subtitle:
        st = s.shapes.add_textbox(Inches(0.7), Inches(1.7), Inches(11.9), Inches(0.6))
        r = st.text_frame.paragraphs[0]
        r.text = subtitle
        r.font.size = Pt(15)
        r.font.color.rgb = MUTED


def bullets(s, items, left=0.7, top=2.6, width=11.9, size=16, gap=Pt(6)):
    box = s.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(4.2))
    tf = box.text_frame
    tf.word_wrap = True
    for i, (head, body) in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = gap
        rh = p.add_run()
        rh.text = "\u2022  " + head
        rh.font.size = Pt(size)
        rh.font.bold = True
        rh.font.color.rgb = WHITE
        if body:
            rb = p.add_run()
            rb.text = "  \u2014  " + body
            rb.font.size = Pt(size)
            rb.font.color.rgb = MUTED
    return box


def add_table(s, rows, cols, widths, top=2.6, font_size=12):
    left = (prs.slide_width - sum(widths)) / 2
    gt = s.shapes.add_table(len(rows), len(cols), left, Inches(top),
                            sum(widths), Inches(0.45 * len(rows)))
    tbl = gt.table
    for j, w in enumerate(widths):
        tbl.columns[j].width = w
    for i, row in enumerate(rows):
        for j, val in enumerate(row):
            cell = tbl.cell(i, j)
            cell.text = ""
            p = cell.text_frame.paragraphs[0]
            p.text = str(val)
            p.font.size = Pt(font_size + (1 if i == 0 else 0))
            p.font.bold = (i == 0)
            p.font.color.rgb = WHITE if i == 0 else MUTED
            if i == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(15, 52, 96)
            else:
                cell.fill.solid()
                cell.fill.fore_color.rgb = CARD if i % 2 else RGBColor(10, 17, 32)
    return gt


def note(s, text):
    s.notes_slide.placeholders[1].text = text


I = lambda v: Inches(v)

# ── 1. Title ─────────────────────────────────────────────
s = new_slide()
b = s.shapes.add_textbox(I(0.7), I(1.0), I(11.9), I(0.5))
r = b.text_frame.paragraphs[0]
r.text = "VIT \u2014 SCHOOL OF COMPUTER SCIENCE AND ENGINEERING (SCOPE)"
r.font.size = Pt(14); r.font.bold = True; r.font.color.rgb = CYAN
b = s.shapes.add_textbox(I(0.7), I(1.6), I(11.9), I(1.6))
r = b.text_frame.paragraphs[0]
r.text = "AI-Based QR Code Threat Analyzer"
r.font.size = Pt(44); r.font.bold = True; r.font.color.rgb = WHITE
b = s.shapes.add_textbox(I(0.7), I(3.1), I(11.9), I(0.7))
r = b.text_frame.paragraphs[0]
r.text = "Hybrid Defense Against QR Phishing (Quishing) Across URL, UPI, Wi-Fi & Email Payloads"
r.font.size = Pt(18); r.font.color.rgb = MUTED
b = s.shapes.add_textbox(I(0.7), I(4.4), I(11.9), I(1.8))
tf = b.text_frame; tf.word_wrap = True
for line in ["Course: BCSE410L \u2014 Cyber Security  |  Review: I",
             "Presented by: [Your Name],  Reg. No.: [____________]",
             "Faculty Guide: Dr. Arun Prasath G"]:
    p = tf.paragraphs[0] if line.startswith("Course") else tf.add_paragraph()
    p.text = line
    p.font.size = Pt(16); p.font.color.rgb = WHITE
note(s, "OPENING (1 min): greet, state title + Review-I objective. NOTE: replace bracketed name/reg-no before presenting.")

# ── 2. Introduction ──────────────────────────────────────
s = new_slide()
title_block(s, "01 \u2014 Introduction", "Why QR Codes Need a Security Layer")
bullets(s, [
    ("QR codes are trust blind-spots", "humans cannot read the payload before acting"),
    ("Quishing is rising", "QR phishing now targets UPI payments, login pages, Wi-Fi joins and app downloads"),
    ("One scan can cost money or credentials", "auto-filled UPI amounts, spoofed bank logins, malware links"),
    ("Goal of this project", "a scan-time verdict \u2014 Safe / Suspicious / Malicious \u2014 with reasons, before the user acts"),
])
note(s, "(1 min): motivate with a UPI-fraud anecdote; define quishing = QR + phishing.")

# ── 3. Problem Statement ─────────────────────────────────
s = new_slide()
title_block(s, "02 \u2014 Problem Statement", "What We Are Solving")
bullets(s, [
    ("Statement", "build a system that scans any QR code, extracts its payload, and classifies risk with explanations"),
    ("Why it matters", "existing scanners decode but never judge; users open malicious links blindly"),
    ("Target users", "general public, UPI payers, students, enterprises printing public QR codes"),
    ("Core challenges", "opaque payloads, shortened URLs, zero-day domains, and non-URL QR types (UPI / Wi-Fi / email)"),
])
note(s, "(1.5 min): map to rubric 'Problem Understanding' (4 marks) \u2014 statement, importance, users, challenges.")

# ── 4. Literature Survey ─────────────────────────────────
s = new_slide()
title_block(s, "03 \u2014 Literature Survey", "Five Recent Studies (2022\u20132026) \u2014 REPLACE WITH PAPERS YOU READ")
add_table(s,
    [["#", "Study Theme", "Objective", "Methodology", "Limitation"],
     ["1", "ML phishing-URL classifier", "Classify malicious URLs", "Random Forest / XGBoost on lexical features", "URL-only; ignores QR context"],
     ["2", "Deep-learning URL detector", "Catch obfuscated URLs", "CNN / LSTM on character sequences", "Data-hungry; black-box verdicts"],
     ["3", "Quishing user-susceptibility study", "Measure human risk", "Controlled user experiments", "No automated defense proposed"],
     ["4", "QR image-forgery detection", "Spot tampered codes", "Computer-vision anomaly checks", "Analyzes pixels, not payload"],
     ["5", "Threat-intel reputation feeds", "Block known-bad URLs", "Blocklists (URLhaus / Safe Browsing)", "Blind to zero-day, unlisted URLs"]],
    [0, 1, 2, 3, 4],
    [I(0.5), I(2.6), I(2.6), I(2.9), I(3.2)], top=2.5, font_size=11)
warn = s.shapes.add_textbox(I(0.7), I(6.3), I(11.9), I(0.5))
r = warn.text_frame.paragraphs[0]
r.text = "Draft placeholders \u2014 substitute author, venue & year for each paper you actually studied (IEEE / Springer / ACM / ScienceDirect)."
r.font.size = Pt(11); r.font.italic = True; r.font.color.rgb = AMBER
note(s, "(2 min): one line per paper \u2014 objective, method, advantage, limitation. Rubric weight: 4 marks.")

# ── 5. Existing solutions ────────────────────────────────
s = new_slide()
title_block(s, "04 \u2014 Existing Work Analysis", "How Current Solutions Compare")
add_table(s,
    [["Solution", "Technology", "Advantages", "Limitations"],
     ["Native camera scanners", "Decode only", "Instant, offline", "No security verdict at all"],
     ["Google Safe Browsing", "Blocklist API", "Broad coverage", "Needs key; misses zero-day URLs"],
     ["VirusTotal", "70+ engines", "Thorough verdicts", "Slow; quotas; uploads data"],
     ["URLhaus / PhishTank", "Community feeds", "Free intel", "Known threats only"],
     ["Academic ML classifiers", "XGBoost / RF / DL", "High URL accuracy", "URL-only; no QR, no explanation"]],
    [0, 1, 2, 3],
    [I(2.6), I(2.4), I(3.3), I(3.5)], top=2.5, font_size=11)
note(s, "(1.5 min): walk the table row by row; each limitation feeds the next slide's gap.")

# ── 6. Research gap ──────────────────────────────────────
s = new_slide()
title_block(s, "05 \u2014 Research Gap", "What Nobody Solves End-to-End")
bullets(s, [
    ("G1 \u2014 Decode without judgment", "scanners show the link but never warn"),
    ("G2 \u2014 Zero-day blindness", "reputation feeds miss fresh, unlisted phishing domains"),
    ("G3 \u2014 URL-only thinking", "no first-class handling of UPI, Wi-Fi, email or phone QR payloads"),
    ("G4 \u2014 Black-box verdicts", "users get 'malicious' with no reason, so they ignore warnings"),
    ("G5 \u2014 No unified scan-time hybrid", "rules + ML + intel are never fused into one explained score"),
])
note(s, "(1.5 min): explicitly tie each gap to a limitation from slide 5. Rubric: Novelty & Gap = 6 marks.")

# ── 7. Novelty ───────────────────────────────────────────
s = new_slide()
title_block(s, "06 \u2014 Novelty", "What Is New in Our Solution")
bullets(s, [
    ("Multi-type QR engine", "URL, UPI payment, Wi-Fi, email and phone payloads get dedicated analyzers"),
    ("Hybrid risk formula", "Risk = ML\u00d750 + Rules\u00d730 + Intel\u00d710 + QR-context\u00d710, normalized 0\u2013100"),
    ("Explainable AI", "top-5 risk factors, 'why flagged', and what-the-user-should-do guidance"),
    ("Payment & wireless fraud modules", "UPI VPA/amount/blacklist checks; rogue-AP and Evil-Twin Wi-Fi checks"),
    ("Weighted soft-voting ensemble", "XGBoost + Random Forest + Logistic Regression with confidence %, not a raw label"),
])
note(s, "(1.5 min): answer the guideline's 5 novelty questions; stress this is detection technique + AI integration, not a UI change.")

# ── 8. Architecture ──────────────────────────────────────
s = new_slide()
title_block(s, "07 \u2014 Proposed Architecture", "10-Stage Hybrid Pipeline")
bullets(s, [
    ("1\u20132 \u2014 Capture & decode", "image / webcam / URL input \u2192 dual OpenCV + pyzbar decoder with annotated output"),
    ("3 \u2014 Type detection", "payload classified as URL, UPI, Wi-Fi, email, phone or text before analysis"),
    ("4\u20135 \u2014 Features", "36 URL features (lexical, domain, entropy, redirect) or domain-specific parsers"),
    ("6\u20138 \u2014 Triple analysis", "16-rule heuristics + weighted soft-voting ML ensemble + URLhaus / VT / Safe-Browsing intel"),
    ("9\u201310 \u2014 Verdict & UI", "hybrid 0\u2013100 score \u2192 Safe / Suspicious / Malicious + XAI dashboard + PDF audit report"),
])
note(s, "(1.5 min): draw attention to module roles; be ready to whiteboard the data flow. Rubric: design = 4 marks.")

# ── 9. Tech stack ────────────────────────────────────────
s = new_slide()
title_block(s, "08 \u2014 Technology Stack", "Tools Chosen for Speed and Rigor")
add_table(s,
    [["Layer", "Choice", "Role"],
     ["Frontend", "Streamlit", "Demo dashboard: gauge, tabs, history, reports"],
     ["Computer Vision", "OpenCV + pyzbar", "Dual-engine QR detection & decoding"],
     ["Machine Learning", "XGBoost + scikit-learn", "Ensemble training & inference"],
     ["URL Intelligence", "tldextract, whois, validators", "Domain parsing, age, validation"],
     ["Threat Intel", "URLhaus, VirusTotal, Safe Browsing", "Live reputation with offline fallback"],
     ["Reporting", "ReportLab + Plotly", "PDF audit reports & risk visuals"]],
    [0, 1, 2],
    [I(3.0), I(3.8), I(5.0)], top=2.5, font_size=12)
note(s, "(1 min): justify each pick in one line \u2014 e.g., Streamlit for demo velocity, XGBoost for tabular accuracy.")

# ── 10. Implementation plan ──────────────────────────────
s = new_slide()
title_block(s, "09 \u2014 Implementation Plan", "Module-Wise Schedule & Testing")
add_table(s,
    [["Phase", "Modules", "Status / Target"],
     ["P1", "QR decode, validation, dataset (943 URLs)", "Complete"],
     ["P2", "36 features, 16 rules, ensemble training", "Complete"],
     ["P3", "Threat intel, hybrid scoring, XAI", "Complete"],
     ["P4", "UPI fraud + Wi-Fi + email/phone engines", "Complete"],
     ["P5", "Dashboard polish, PDF reports, docs", "In progress \u2192 Review II"],
     ["Testing", "44-case suite + 9 demo QRs + 5-fold CV", "44/44 passing"]],
    [0, 1, 2],
    [I(1.6), I(5.6), I(4.6)], top=2.5, font_size=12)
note(s, "(1 min): rubric planning = 2 marks \u2014 show dates verbally; Review-II scope: hardening, live redirect expansion, packaging.")

# ── 11. Outcomes ─────────────────────────────────────────
s = new_slide()
title_block(s, "10 \u2014 Expected Outcomes", "Measured Results So Far")
bullets(s, [
    ("Ensemble accuracy 99.47%", "F1 0.993, ROC-AUC 1.000, 5-fold CV 0.9958 on held-out URLs"),
    ("Beats-or-matches baselines", "XGBoost 99.47%, Random Forest 100%, Logistic Regression 99.47% benchmarked"),
    ("Live demo verdicts", "Wikipedia \u2192 SAFE (1/100); PayPal spoof \u2192 MALICIOUS (71); UPI scam \u2192 FRAUD RISK (100)"),
    ("Review-II deliverables", "hardened dashboard, full audit PDFs, batch scanning, deployment-ready repo"),
])
note(s, "(1 min): numbers are from your trained models \u2014 keep test_system.py output handy if asked.")

# ── 12. Closing ──────────────────────────────────────────
s = new_slide()
b = s.shapes.add_textbox(I(0.7), I(1.6), I(11.9), I(1.0))
r = b.text_frame.paragraphs[0]
r.text = "Conclusion"
r.font.size = Pt(36); r.font.bold = True; r.font.color.rgb = WHITE
bullets(s, [
    ("Quishing exploits unreadable QR payloads", "our system judges every scan before the user acts"),
    ("Hybrid + explainable beats any single method", "rules catch known tricks, ML catches zero-days, intel confirms, XAI convinces"),
    ("Multi-type coverage is the differentiator", "payments and Wi-Fi fraud included, not just URLs"),
], top=2.7)
b = s.shapes.add_textbox(I(0.7), I(5.6), I(11.9), I(0.8))
r = b.text_frame.paragraphs[0]
r.text = "References: 5 surveyed papers (2022\u20132026) + URLhaus / APWG threat reports  \u2014  Thank you. Questions?"
r.font.size = Pt(15); r.font.bold = True; r.font.color.rgb = CYAN
note(s, "CLOSE: restate novelty in one sentence; invite questions. Total talk time \u2248 12\u201313 min.")

prs.save(r"C:\Users\Asus\OneDrive\Documents\qr_threat_analyzer\Review1_Presentation_Draft.pptx")
print("saved: Review1_Presentation_Draft.pptx,", len(prs.slides), "slides")
