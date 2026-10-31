"""Generate publication figures from verified experiment outputs (no fabricated data)."""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figures")
EXP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "experiments")
os.makedirs(FIG, exist_ok=True)

audit = json.load(open(os.path.join(EXP, "dataset_audit.json"), encoding="utf-8"))
case = json.load(open(os.path.join(EXP, "case_study.json"), encoding="utf-8"))
meta = json.load(open(os.path.join(BASE, "models", "model_metadata.json"), encoding="utf-8"))

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 9,
    "axes.edgecolor": "#4A5568", "axes.labelcolor": "#1A202C",
    "text.color": "#1A202C", "xtick.color": "#2D3748", "ytick.color": "#2D3748",
    "axes.grid": True, "grid.color": "#E2E8F0", "grid.linewidth": 0.7,
})

CYAN, GREEN, AMBER, RED, NAVY = "#0E7490", "#047857", "#B45309", "#B91C1C", "#1E293B"


# ── Figure 1: architecture ──────────────────────────────────────────────────
def box(ax, x, y, w, h, text, fc="#F1F5F9", ec="#475569", fs=8, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.015",
                                fc=fc, ec=ec, lw=1.0))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal", wrap=True)


def arrow(ax, p1, p2):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle="-|>", mutation_scale=10,
                                 lw=1.0, color="#475569", shrinkA=1, shrinkB=1))


fig, ax = plt.subplots(figsize=(7.2, 4.6))
ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off"); ax.grid(False)

box(ax, 0.02, 0.855, 0.26, 0.115, "Input\nimage · webcam ·\ntext · batch", fc="#E0F2FE", fs=8)
box(ax, 0.345, 0.855, 0.30, 0.115, "Decoder cascade\nOpenCV → pyzbar → CLAHE", fc="#E0F2FE", fs=8)
box(ax, 0.705, 0.855, 0.275, 0.115, "Payload classifier\nURL · UPI · Wi-Fi ·\nEmail · Phone · Text", fc="#E0F2FE", fs=8)
arrow(ax, (0.28, 0.912), (0.345, 0.912)); arrow(ax, (0.645, 0.912), (0.705, 0.912))

box(ax, 0.02, 0.585, 0.45, 0.165,
    "URL branch\n36 features · 16 rules · soft-voting ensemble\nXGB×3 : RF×2 : LR×1",
    fc="#ECFDF5", ec=GREEN, fs=7.8)
box(ax, 0.055, 0.497, 0.38, 0.062,
    "threat intel: URLhaus · SSL probe · VT/GSB (optional)",
    fc="#FEF2F2", ec=RED, fs=7.0)
box(ax, 0.53, 0.585, 0.45, 0.165,
    "Payload-specific branches\nUPI (7 checks) · Wi-Fi (6 checks)\nEmail (2 checks) · Phone (2 checks)",
    fc="#FFFBEB", ec=AMBER, fs=7.8)

arrow(ax, (0.84, 0.85), (0.245, 0.752))
arrow(ax, (0.84, 0.85), (0.755, 0.752))

box(ax, 0.06, 0.335, 0.88, 0.115,
    "Hybrid risk fusion\nR = 50·p_ML + 30·(S_rule/100) + 10·(S_intel/100) + 10·(S_ctx/100)\n"
    "floors: rule ≥ 50 → R ≥ 35; blacklisted → R ≥ 88; bands 0–30 / 31–60 / 61–100",
    fc="#EEF2FF", ec="#4338CA", fs=7.4)
arrow(ax, (0.245, 0.583), (0.245, 0.452))
arrow(ax, (0.755, 0.583), (0.755, 0.452))

box(ax, 0.06, 0.185, 0.88, 0.085,
    "Explanation layer  —  ranked rule/ML factors · triggered rules · actionable guidance",
    fc="#F5F3FF", ec="#6D28D9", fs=7.6)
arrow(ax, (0.50, 0.333), (0.50, 0.272))

box(ax, 0.02, 0.03, 0.29, 0.09, "Streamlit dashboard\nscan · history · reports", fc="#F8FAFC", fs=7.8)
box(ax, 0.355, 0.03, 0.29, 0.09, "PDF audit report\nSHA-256 payload hash", fc="#F8FAFC", fs=7.8)
box(ax, 0.69, 0.03, 0.29, 0.09, "CSV history export\nsession analytics", fc="#F8FAFC", fs=7.8)
arrow(ax, (0.17, 0.183), (0.17, 0.122))
arrow(ax, (0.50, 0.183), (0.50, 0.122))
arrow(ax, (0.835, 0.183), (0.835, 0.122))

fig.tight_layout(pad=0.2)
fig.savefig(os.path.join(FIG, "fig1_architecture.png"), dpi=300, facecolor="white")
plt.close(fig)

# ── Figure 2: dataset composition ───────────────────────────────────────────
fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.2, 2.9), gridspec_kw={"width_ratios": [1, 1.3]})
counts = audit["label_counts"]
bars = a1.bar(["Benign (0)", "Malicious (1)"], [counts["0"], counts["1"]],
              color=["#0F766E", "#B91C1C"], width=0.55)
a1.set_ylabel("URLs"); a1.set_title("(a) Class balance (n = 943)", fontsize=9.5)
a1.set_ylim(0, 700)
for b, v in zip(bars, [counts["0"], counts["1"]]):
    a1.text(b.get_x() + b.get_width() / 2, v + 12, str(v), ha="center", fontsize=9)

sch = audit["scheme_by_label"]
https = [sch["https"]["0"], sch["https"]["1"]]
http = [sch["http"]["0"], sch["http"]["1"]]
x = np.arange(2); w = 0.35
a2.bar(x - w / 2, https, w, label="https://", color="#0369A1")
a2.bar(x + w / 2, http, w, label="http://", color="#F59E0B")
a2.set_xticks(x); a2.set_xticklabels(["Benign", "Malicious"])
a2.set_ylabel("URLs"); a2.set_title("(b) Scheme distribution by class", fontsize=9.5)
a2.legend(frameon=False, fontsize=8)
a2.set_ylim(0, 700)
for xi, (h, p) in enumerate(zip(https, http)):
    a2.text(xi - w / 2, h + 12, str(h), ha="center", fontsize=8)
    a2.text(xi + w / 2, p + 12, str(p), ha="center", fontsize=8)
fig.tight_layout()
fig.savefig(os.path.join(FIG, "fig2_dataset.png"), dpi=300, facecolor="white")
plt.close(fig)

# ── Figure 3: feature importance ────────────────────────────────────────────
imps = meta["ensemble_metrics"]["feature_importances"]
top = sorted(imps.items(), key=lambda kv: kv[1], reverse=True)[:12][::-1]
fig, ax = plt.subplots(figsize=(6.4, 3.6))
labels = [k for k, _ in top]; vals = [v * 100 for _, v in top]
colors = [RED if k == "is_https" else "#475569" for k, _ in top]
ax.barh(labels, vals, color=colors, height=0.65)
ax.set_xlabel("XGBoost importance (% of total gain)")
ax.set_title("Top-12 features of the trained XGBoost base estimator", fontsize=9.5)
for i, v in enumerate(vals):
    ax.text(v + 0.8, i, f"{v:.1f}%", va="center", fontsize=8)
ax.set_xlim(0, max(vals) * 1.18)
ax.grid(axis="y", visible=False)
fig.tight_layout()
fig.savefig(os.path.join(FIG, "fig3_feature_importance.png"), dpi=300, facecolor="white")
plt.close(fig)

# ── Figure 4: confusion matrices ────────────────────────────────────────────
def cm_panel(ax, cm, title):
    cm = np.array(cm)
    ax.imshow(cm, cmap="Blues", vmin=0, vmax=cm.max() * 1.2)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]}", ha="center", va="center", fontsize=13,
                    color="white" if cm[i, j] > cm.max() * 0.6 else "#1A202C")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Pred. benign", "Pred. malicious"])
    ax.set_yticklabels(["True benign", "True malicious"])
    ax.set_title(title, fontsize=9.5)
    ax.grid(False)

fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.0, 3.0))
cm_panel(a1, audit["reproduction_random_split"]["ensemble"]["confusion_matrix"],
         "(a) Random split, ensemble (n = 189)")
ma = np.array(audit["reproduction_random_split"]["ensemble"]["confusion_matrix"]) + \
     np.array(audit["reproduction_random_split"]["xgboost"]["confusion_matrix"]) * 0
cm_panel(a2, audit["https_only_subset"]["xgboost"]["confusion_matrix"],
         "(b) HTTPS-only, XGBoost (n = 148)")
fig.tight_layout()
fig.savefig(os.path.join(FIG, "fig4_confusion.png"), dpi=300, facecolor="white")
plt.close(fig)

# ── Figure 5: diagnostic comparison ─────────────────────────────────────────
r = audit["reproduction_random_split"]["ensemble"]
d = audit["domain_disjoint_split"]["ensemble"]
ab = audit["ablation_no_https"]["ensemble"]
hs = audit["https_only_subset"]["xgboost"]
names = ["Random split\n(as reported)", "Domain-disjoint\nsplit", "No-HTTPS\nablation", "HTTPS-only\nsubset"]
accs = [r["accuracy"] * 100, d["accuracy"] * 100, ab["accuracy"] * 100, hs["accuracy"] * 100]
recs = [r["recall"] * 100, d["recall"] * 100, ab["recall"] * 100, hs["recall"] * 100]
x = np.arange(len(names)); w = 0.36
fig, ax = plt.subplots(figsize=(6.8, 3.1))
b1 = ax.bar(x - w / 2, accs, w, label="Accuracy", color="#0E7490")
b2 = ax.bar(x + w / 2, recs, w, label="Recall (malicious)", color="#B45309")
ax.set_xticks(x); ax.set_xticklabels(names, fontsize=8)
ax.set_ylim(0, 122); ax.set_ylabel("Percent")
ax.legend(frameon=False, fontsize=8, ncol=2, loc="upper right")
for bars in (b1, b2):
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.2,
                f"{b.get_height():.1f}", ha="center", fontsize=7.5)
ax.set_title("Reported versus diagnostic evaluation of the same pipeline", fontsize=9.5)
fig.tight_layout()
fig.savefig(os.path.join(FIG, "fig5_diagnostics.png"), dpi=300, facecolor="white")
plt.close(fig)

# ── Figure 6: case study ────────────────────────────────────────────────────
rows = [c for c in case if c.get("qr_type") in ("URL", "UPI", "WIFI", "EMAIL")]
friendly = {
    "1_safe_wikipedia": "Safe URL (Wikipedia)",
    "2_safe_github": "Safe URL (GitHub)",
    "3_suspicious_shortener": "URL shortener",
    "4_malicious_ip_phish": "IP-host phishing",
    "5_malicious_paypal_spoof": "Brand spoof",
    "6_malicious_dga_domain": "DGA-style domain",
    "7_upi_fraud": "UPI fraud",
    "8_rogue_wifi": "Open Wi-Fi",
    "9_phishing_email": "Phishing email",
}
labels = [friendly.get(c["file"].replace(".png", ""), c["file"]) for c in rows]
scores = [c.get("final_score", c.get("risk_score", 0)) for c in rows]
cols = [GREEN if s <= 30 else (AMBER if s <= 60 else RED) for s in scores]
fig, ax = plt.subplots(figsize=(6.8, 3.4))
bars = ax.barh(labels[::-1], scores[::-1], color=cols[::-1], height=0.62)
ax.set_xlim(0, 108); ax.set_xlabel("Final risk score (0–100)")
ax.axvline(30, color=AMBER, ls="--", lw=0.9)
ax.axvline(60, color=RED, ls="--", lw=0.9)
for b, v in zip(bars, scores[::-1]):
    ax.text(v + 1.5, b.get_y() + b.get_height() / 2, str(v), va="center", fontsize=8)
ax.grid(axis="y", visible=False)
ax.set_title("Demo QR verdicts across payload types", fontsize=9.5)
fig.tight_layout()
fig.savefig(os.path.join(FIG, "fig6_case_study.png"), dpi=300, facecolor="white")
plt.close(fig)

print("figures written to", FIG)
for f in sorted(os.listdir(FIG)):
    print(" -", f)
