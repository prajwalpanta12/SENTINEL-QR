"""Publication figures for the real-world evaluation. Reads only executed outputs:
results/r1_results.json, r1_results_scores.npz, subset_checks.json, rule_trigger_rates.json,
shipped_xgb_gain_importance.json, and the test split (for subset masks).
Writes PDF (vector, embedded TrueType), SVG (editable text) and 300-dpi PNG for each figure.
Usage: python make_paper_figures.py results /path/to/test.csv OUTDIR"""
import sys, os, json, numpy as np, pandas as pd, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from urllib.parse import urlsplit
from sklearn.metrics import roc_curve, precision_recall_curve, auc, average_precision_score

RES, TEST, OUT = sys.argv[1:4]; os.makedirs(OUT, exist_ok=True)
R = json.load(open(f"{RES}/r1_results.json")); Z = np.load(f"{RES}/r1_results_scores.npz")
D = pd.read_csv(TEST); y = Z["y_test"]; assert (D.label.values == y).all()
M = R["models"]

COL1, COL2 = 3.5, 7.16           # IEEE column / page width (in)
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 7.5, "axes.titlesize": 8, "axes.labelsize": 7.5,
    "legend.fontsize": 6.8, "xtick.labelsize": 7, "ytick.labelsize": 7,
    "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.6,
    "xtick.major.width": 0.6, "ytick.major.width": 0.6, "lines.linewidth": 1.4,
    "axes.grid": True, "grid.color": "#E3E3E3", "grid.linewidth": 0.5,
    "pdf.fonttype": 42, "svg.fonttype": "none", "savefig.dpi": 300})
# CVD-validated categorical slots; every series also has its own line style / marker / hatch
C = {"r4": "#3f7f6a", "shipped": "#2a78d6", "fused": "#eb6834", "xgb": "#1baf7a", "tfidf": "#eda100", "rule": "#8a8a8a", "lr": "#6b4fc9"}
LS = {"shipped": (0, (4, 2)), "fused": (0, (1, 1.5)), "xgb": (0, (5, 1.5, 1, 1.5)), "tfidf": "-", "rule": (0, (2, 2)), "lr": (0, (6, 2))}
NAME = {"shipped": "Shipped ensemble (synthetic-trained)", "fused": "Shipped fusion score",
        "rule": "Shipped rule engine", "lr": "Logistic regression (retrained)",
        "xgb": "XGBoost (retrained)", "tfidf": "TF-IDF char n-gram + LR"}
LOG = []
def save(fig, name, caption):
    for ext in ("pdf", "svg", "png"):
        fig.savefig(f"{OUT}/{name}.{ext}", bbox_inches="tight", pad_inches=0.02)
    plt.close(fig); LOG.append((name, caption))

root = D.url.map(lambda u: (urlsplit(u).path or "/") == "/").values
hp = (D.source == "crux").values | ((y == 1) & root)

# ---------- F1: ROC (full, homepage subset) + PR (full) ----------
ORDER = ("shipped", "fused", "rule", "lr", "xgb", "tfidf")
fig, ax = plt.subplots(1, 3, figsize=(COL2, 2.75))
def vals_box(a, vals, title):
    from matplotlib.lines import Line2D
    h = [Line2D([], [], color=C[k], ls=LS[k], lw=1.4) for k in ORDER]
    a.legend(h, [f"{v:.3f}" for v in vals], loc="lower right", fontsize=5.8, title=title, title_fontsize=5.8,
             handlelength=2.2, frameon=True, framealpha=0.92, edgecolor="#cccccc", borderpad=0.4, labelspacing=0.25)
for a, (m, title) in zip(ax[:2], [(np.ones_like(y, bool), f"(a) ROC, full test set (n = {len(y):,})"),
                                  (hp, f"(b) ROC, homepage subset (n = {hp.sum():,})")]):
    v = []
    for k in ORDER:
        f, t, _ = roc_curve(y[m], Z[k][m]); a.plot(f, t, color=C[k], ls=LS[k], label=NAME[k]); v.append(auc(f, t))
    a.plot([0, 1], [0, 1], color="#9a9a9a", lw=0.7)
    a.set(xlim=(0, 1), ylim=(0, 1.005), xlabel="False positive rate", ylabel="True positive rate", title=title)
    a.set_aspect("equal"); vals_box(a, v, "ROC-AUC")
base = y.mean(); v = []
for k in ORDER:
    p, r, _ = precision_recall_curve(y, Z[k]); ax[2].plot(r, p, color=C[k], ls=LS[k]); v.append(average_precision_score(y, Z[k]))
ax[2].axhline(base, color="#9a9a9a", lw=0.7); ax[2].text(0.30, base - 0.06, f"test prevalence {base:.3f}", fontsize=5.8, color="#555")
ax[2].set(xlim=(0, 1), ylim=(0, 1.005), xlabel="Recall", ylabel="Precision", title="(c) Precision-recall, full test set")
ax[2].set_aspect("equal"); vals_box(ax[2], v, "Avg. precision")
h, l = ax[0].get_legend_handles_labels()
fig.legend(h, l, loc="lower center", ncol=3, frameon=False, fontsize=6.4, handlelength=2.6, columnspacing=1.4)
fig.tight_layout(rect=(0, 0.13, 1, 1), w_pad=0.8)
save(fig, "F1_roc_pr", "ROC curves on (a) the full real-world test set (10 000 phishing URLs reported 2025-2026; 8 923 benign URLs from unseen domains) and (b) the contemporaneous homepage subset (CrUX origins vs. phishing URLs with an empty or root path; 2 935 phishing, 5 000 benign); (c) precision-recall curves on the full test set, with the class prevalence of the balanced test set as reference. Boxed values are ROC-AUC and average precision in legend order. The shipped ensemble ranks below chance; retrained models lose 0.04-0.05 ROC-AUC on the homepage subset.")

# ---------- F2: confusion matrices ----------
sel = [("S1_shipped_ensemble_thr0.5", "(a) Shipped ensemble"), ("R3_xgboost", "(b) XGBoost, retrained"), ("L1_tfidf_char_lr", "(c) TF-IDF + LR")]
fig, ax = plt.subplots(1, 3, figsize=(6.2, 2.0))
for a, (k, t) in zip(ax, sel):
    cm = np.array(M[k]["test"]["cm"]); thr = 0.5 if k.startswith("S1") else M[k]["val"]["threshold"]
    rowp = cm / cm.sum(1, keepdims=True)
    a.imshow(rowp, cmap="Greys", vmin=0, vmax=1.25)
    for i in range(2):
        for j in range(2):
            a.text(j, i, f"{cm[i, j]:,}\n({rowp[i, j]*100:.1f}%)", ha="center", va="center", fontsize=7,
                   color="white" if rowp[i, j] > 0.62 else "black")
    a.set_xticks([0, 1], ["Benign", "Phishing"]); a.set_yticks([0, 1], ["Benign", "Phishing"])
    a.set_xlabel("Predicted"); a.set_ylabel("Actual" if a is ax[0] else ""); a.grid(False)
    a.set_title(f"{t}\nthreshold {thr:.2f}"); [s.set_visible(False) for s in a.spines.values()]
fig.tight_layout(w_pad=1.2)
save(fig, "F2_confusion", "Confusion matrices on the real-world test set (8 923 benign, 10 000 phishing). Percentages are per actual class (row). Thresholds: 0.5 for the shipped ensemble, as deployed; validation-selected (best F1 on the 2024 validation set) for the retrained models.")

# ---------- F3: feature importance, shipped vs retrained ----------
shp = json.load(open(f"{RES}/shipped_xgb_gain_importance.json"))
real = R["audit"]["xgb_gain_importance_top10"]
fig, ax = plt.subplots(1, 2, figsize=(COL2, 2.25), sharex=True)
for a, (d, title, col) in zip(ax, [(dict(sorted(shp.items(), key=lambda kv: -kv[1])[:10]), "(a) Shipped model, synthetic training data (n = 754)", C["shipped"]),
                                   (real, "(b) Retrained on real data (n = 60,000), seed 42", C["xgb"])]):
    ks = list(d)[::-1]; vs = [d[k] for k in ks]
    a.barh(ks, vs, color=col, height=0.62, edgecolor="white", linewidth=0.6)
    for i, v in enumerate(vs): a.text(v + 0.8, i, f"{v:.1f}", va="center", fontsize=6.3)
    a.set_title(title, loc="left"); a.set_xlim(0, 75); a.grid(axis="y", visible=False); a.tick_params(axis="y", length=0)
    a.set_xlabel("Share of XGBoost gain (%)")
fig.tight_layout(w_pad=2.0)
save(fig, "F3_importance", "XGBoost gain importance (top 10 features, shared x-axis) for (a) the shipped base learner trained on the 943-URL synthetic benchmark and (b) the same learner retrained on the real-world training split. On synthetic data is_https carries 68.8% of the gain; on real data no feature exceeds 17%. Gain importance is not causal and is split among correlated features.")

# ---------- F4: ROC-AUC with 95% bootstrap CI, full vs homepage subset ----------
sc = json.load(open(f"{RES}/subset_checks.json"))
rows = [("B1r_https_scheme_rule", "HTTPS-scheme rule", None), ("B2_has_path_rule", "Has-path rule", None),
        ("S1_shipped_ensemble_thr0.5", "Shipped ensemble", "shipped"), ("S3_shipped_fusion_ge31_suspicious", "Shipped fusion", "fused"),
        ("S2_rule_engine_val_thr", "Shipped rule engine", "rule"), ("R1_logreg", "LR (retrained)", "lr"),
        ("R2_random_forest", "Random forest (retrained)", None), ("R4_softvote_321", "Soft vote 3:2:1 (retrained)", "r4"),
        ("A1_xgboost_without_is_https", "XGBoost without is_https", None), ("R3_xgboost", "XGBoost (retrained)", "xgb"),
        ("L1_tfidf_char_lr", "TF-IDF + LR", "tfidf")]
fig, a = plt.subplots(figsize=(COL1, 2.7))
for i, (k, lab, z) in enumerate(rows):
    v = M[k]["test"]["roc_auc"]; lo, hi = M[k]["test_ci95"]["roc_auc"]
    a.errorbar(v, i, xerr=[[v - lo], [hi - v]], fmt="o", ms=3.4, color="#222", capsize=1.6, lw=0.8)
    if z and z in sc["crux_vs_phish_root"]:
        a.plot(sc["crux_vs_phish_root"][z], i, marker="D", ms=3.2, mfc="white", mec=C.get(z, "#555"), mew=1.0, ls="none")
a.axvline(0.5, color="#9a9a9a", lw=0.7, ls=(0, (3, 2))); a.text(0.505, len(rows) - 0.4, "chance", fontsize=6, color="#555")
a.set_yticks(range(len(rows)), [r[1] for r in rows]); a.set_xlim(0.3, 1.0); a.set_ylim(-0.6, len(rows) - 0.2)
a.set_xlabel("ROC-AUC"); a.grid(axis="y", visible=False); a.tick_params(axis="y", length=0)
from matplotlib.lines import Line2D
a.legend(handles=[Line2D([], [], marker="o", color="#222", ls="none", ms=3.4, label="Full test set (95% bootstrap CI)"),
                  Line2D([], [], marker="D", mfc="white", mec="#555", ls="none", ms=3.2, label="Homepage subset")],
         loc="upper center", bbox_to_anchor=(0.35, -0.16), ncol=2, frameon=False, fontsize=6)
fig.tight_layout()
save(fig, "F4_auc_ci", "ROC-AUC of every system on the real-world test set with 95% bootstrap confidence intervals (1000 resamples; most intervals are narrower than the marker), and ROC-AUC on the contemporaneous homepage subset where stored scores were available. The axis starts at 0.3 to include the worst system; the dashed line marks chance.")

# ---------- F5: subgroup error rates ----------
sg = R["subgroups"]; keys = [("S1_shipped_ensemble_thr0.5", "Shipped ensemble", "shipped", ""), ("R3_xgboost", "XGBoost (retrained)", "xgb", "////"), ("L1_tfidf_char_lr", "TF-IDF + LR", "tfidf", "....")]
groups = [("benign_crux_fpr", "FPR\nCrUX\nhomepages"), ("benign_ebbu_fpr", "FPR\nEbbu2017\nURLs"), ("phish_https_recall", "Recall\nHTTPS\nphishing"), ("phish_http_recall", "Recall\nHTTP\nphishing")]
fig, a = plt.subplots(figsize=(COL1, 2.45)); w = 0.26; x = np.arange(len(groups))
for i, (k, lab, c, h) in enumerate(keys):
    v = [sg[k][g]["rate"] for g, _ in groups]
    a.bar(x + (i - 1) * w, v, w * 0.92, color=C[c], hatch=h, edgecolor="white", linewidth=0.4, label=lab)
    for xi, vi in zip(x + (i - 1) * w, v): a.text(xi, vi + 0.02, f"{vi:.2f}", ha="center", fontsize=5.4, rotation=90, va="bottom")
ns = [sg[keys[0][0]][g]["n"] for g, _ in groups]
a.set_xticks(x, [f"{g}\n(n = {n:,})" for (_, g), n in zip(groups, ns)], fontsize=6.2)
a.set_ylim(0, 1.12); a.set_yticks(np.arange(0, 1.01, 0.2)); a.set_ylabel("Rate"); a.grid(axis="x", visible=False)
a.legend(frameon=False, ncol=3, fontsize=5.8, loc="lower center", bbox_to_anchor=(0.5, 1.0), handlelength=1.4, columnspacing=0.8)
fig.tight_layout()
save(fig, "F5_subgroups", "False positive rate by benign source and recall by phishing scheme on the test set (thresholds as in Fig. 2). The shipped ensemble detects HTTP phishing and flags most Ebbu2017 URLs; the retrained models invert this pattern and flag 21-25% of popular CrUX homepages.")

# ---------- F6: temporal recall with Wilson 95% CI ----------
def wilson(p, n, z=1.96):
    c = (p + z*z/(2*n)) / (1 + z*z/n); h = z*np.sqrt(p*(1-p)/n + z*z/(4*n*n)) / (1 + z*z/n); return c - h, c + h
T = R["temporal"]; q = list(T); n = np.array([T[t]["n_phish"] for t in q])
fig, a = plt.subplots(figsize=(COL1, 2.1))
for key, lab, c, mk in [("recall_shipped", "Shipped ensemble (0.5)", C["shipped"], "o"), ("recall_R4", "Soft vote, retrained (val. thr.)", C["xgb"], "s"), ("recall_tfidf", "TF-IDF + LR (val. thr.)", C["tfidf"], "^")]:
    v = np.array([T[t][key] for t in q]); lo, hi = wilson(v, n)
    a.fill_between(range(len(q)), lo, hi, color=c, alpha=0.18, lw=0); a.plot(range(len(q)), v, color=c, marker=mk, ms=3.2, label=lab)
a.set_xticks(range(len(q)), [f"{t[:4]} Q{(int(t[5:])-1)//3+1}\nn={k:,}" for t, k in zip(q, n)], fontsize=5.6)
a.set_ylim(0, 1.0); a.set_ylabel("Phishing recall"); a.grid(axis="x", visible=False)
a.legend(frameon=False, fontsize=5.8, loc="center left", bbox_to_anchor=(0, 0.45))
fig.tight_layout()
save(fig, "F6_temporal", "Phishing recall per quarter of the JPCERT/CC report date in the test period, with 95% Wilson intervals (shaded); n is the number of test phishing URLs per quarter. Benign false positive rates cannot be resolved by time because benign URLs carry no report date.")

# ---------- F7: precision vs assumed prevalence ----------
fig, a = plt.subplots(figsize=(COL1, 2.9)); pi = np.logspace(-3, np.log10(0.5), 200)
for k, lab, c in [("R3_xgboost", "XGBoost", C["xgb"]), ("L1_tfidf_char_lr", "TF-IDF + LR", C["tfidf"])]:
    for op, ls, tag in [("test", "-", "best-F1 threshold"), ("test_at_val_fpr1pct", (0, (3, 1.5)), "FPR ≤ 1% threshold")]:
        tpr, fpr = M[k][op]["recall"], M[k][op]["fpr"]
        a.plot(pi, tpr*pi/(tpr*pi + fpr*(1-pi)), color=c, ls=ls, label=f"{lab}, {tag} (TPR {tpr:.2f}, FPR {fpr:.3f})")
a.axvline(0.01, color="#9a9a9a", lw=0.7, ls=(0, (3, 2))); a.text(0.0108, 0.015, "1%", fontsize=6, color="#555")
a.set_xscale("log"); a.set_xlim(1e-3, 0.5); a.set_ylim(0, 1); a.set_xlabel("Assumed phishing prevalence (log scale)"); a.set_ylabel("Expected precision")
a.legend(frameon=False, fontsize=5.6, loc="upper center", bbox_to_anchor=(0.42, -0.2), ncol=1)
fig.subplots_adjust(left=0.15, right=0.97, top=0.97, bottom=0.42)
save(fig, "F7_prevalence", "Expected precision as a function of assumed phishing prevalence, computed with Eq. (10) from the measured test TPR and FPR at two validation-selected operating points. Curves are extrapolations from a balanced test set, not measurements at the stated prevalence.")

# ---------- F8: calibration of the retrained soft vote ----------
p = Z["r4"]; bins = np.linspace(0, 1, 11); idx = np.clip(np.digitize(p, bins) - 1, 0, 9)
fig, (a, b) = plt.subplots(2, 1, figsize=(COL1, 2.6), sharex=True, gridspec_kw={"height_ratios": [3, 1]})
mp = [p[idx == i].mean() for i in range(10) if (idx == i).any()]; fr = [y[idx == i].mean() for i in range(10) if (idx == i).any()]
cnt = [int((idx == i).sum()) for i in range(10)]
a.plot([0, 1], [0, 1], color="#9a9a9a", lw=0.7); a.plot(mp, fr, marker="o", ms=3, color=C["xgb"])
cal = R["audit"]["calibration_R4"]
a.set(ylim=(0, 1), ylabel="Observed phishing fraction", title=f"Retrained soft vote: Brier {cal['test_brier_raw']:.3f}, ECE {cal['test_ece_raw']:.3f}")
b.bar((bins[:-1] + bins[1:]) / 2, cnt, width=0.09, color="#bdbdbd"); b.set(xlim=(0, 1), xlabel="Mean predicted probability (10 bins)", ylabel="URLs")
b.grid(axis="x", visible=False)
fig.tight_layout(h_pad=0.4)
save(fig, "F8_calibration", "Reliability diagram of the uncalibrated retrained soft-vote ensemble on the test set (18 923 URLs, 10 equal-width bins) with bin counts below. Isotonic recalibration fitted on the 2024 validation set slightly worsened Brier score and ECE on test (0.108 and 0.041).")

# ---------- F9: rule firing rates ----------
rt = json.load(open(f"{RES}/rule_trigger_rates.json")); rr = rt["rates"]
order = sorted(rr, key=lambda k: -(rr[k]["phish_rate"] + rr[k]["benign_rate"]))
fig, a = plt.subplots(figsize=(COL1, 3.0)); yy = np.arange(len(order)); h = 0.38
a.barh(yy - h/2, [rr[k]["phish_rate"]*100 for k in order], h, color=C["fused"], label=f"Phishing (n = {rt['n']['phish']:,})")
a.barh(yy + h/2, [rr[k]["benign_rate"]*100 for k in order], h, color=C["shipped"], hatch="////", edgecolor="white", linewidth=0.3, label=f"Benign (n = {rt['n']['benign']:,})")
a.set_yticks(yy, [k.replace("RULE_", "").replace("_", " ").lower() for k in order], fontsize=6.2); a.invert_yaxis()
a.set_xlabel("URLs on which the rule fires (%)"); a.set_xlim(0, 55); a.grid(axis="y", visible=False); a.tick_params(axis="y", length=0)
a.legend(frameon=False, fontsize=6, loc="lower right")
fig.tight_layout()
save(fig, "F9_rule_rates", "Firing rate of each of the 16 shipped URL rules on the real-world test set. The no-HTTPS rule fires mostly on benign URLs, and the four CRITICAL rules (IP host, executable download, embedded @, punycode) fire on at most 0.23% of phishing URLs.")

json.dump([{"file": n, "caption": c} for n, c in LOG], open(f"{OUT}/captions.json", "w"), indent=1)
print("\n".join(n for n, _ in LOG))
