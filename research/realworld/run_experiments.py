"""
SENTINEL-QR real-world evaluation (R1 benchmark).

All model selection (hyper-parameters, decision thresholds, calibration) uses the
train and validation splits only. The test split is scored once per final model.
Usage: python run_experiments.py DATA_DIR OUT_JSON
"""
import json, os, sys, time, warnings
from collections import defaultdict

import joblib
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, brier_score_loss,
                             confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from features import extract_url_features, FEATURE_COLUMNS  # noqa: E402
from rules import evaluate_rules  # noqa: E402
from explainability import calculate_hybrid_risk_score  # noqa: E402

DATA, OUT = sys.argv[1], sys.argv[2]
SEEDS = [42, 7, 13, 101, 2026]
B = 1000  # bootstrap resamples
rng_boot = np.random.default_rng(20261029)
R = {"protocol": {}, "models": {}, "audit": {}, "subgroups": {}, "temporal": {}, "runtime": {}}

# ---------------------------------------------------------------- data
D = {s: pd.read_csv(os.path.join(DATA, f"{s}.csv"), dtype=str, keep_default_na=False) for s in ("train", "val", "test")}
for s in D:
    D[s]["label"] = D[s]["label"].astype(int)
R["protocol"]["sizes"] = {s: {"n": len(d), "phishing": int(d.label.sum()), "benign": int((1 - d.label).sum())} for s, d in D.items()}

t0 = time.time()
FE = {}
for s, d in D.items():
    feats = [extract_url_features(u) for u in d.url]
    FE[s] = pd.DataFrame([[f[c] for c in FEATURE_COLUMNS] for f in feats], columns=FEATURE_COLUMNS).astype(float)
n_all = sum(len(d) for d in D.values())
R["runtime"]["feature_extraction_ms_per_url"] = round((time.time() - t0) * 1000 / n_all, 4)
X = {s: FE[s].values for s in FE}
y = {s: D[s].label.values for s in D}

const = [c for c in FEATURE_COLUMNS if FE["train"][c].nunique() == 1]
dup = []
cols = FEATURE_COLUMNS
for i in range(len(cols)):
    for j in range(i + 1, len(cols)):
        if (FE["train"][cols[i]] == FE["train"][cols[j]]).all():
            dup.append([cols[i], cols[j]])
R["audit"]["constant_features_train"] = const
R["audit"]["identical_pairs_train"] = dup
keep = [c for c in FEATURE_COLUMNS if c not in const and c != "count_subdomain_levels"]
R["protocol"]["features_used_by_retrained_models"] = keep
ki = [FEATURE_COLUMNS.index(c) for c in keep]


# ---------------------------------------------------------------- metrics
def metrics(yt, score, thr):
    yp = (score >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
    out = {"threshold": float(thr), "accuracy": accuracy_score(yt, yp), "precision": precision_score(yt, yp, zero_division=0),
           "recall": recall_score(yt, yp, zero_division=0), "f1": f1_score(yt, yp, zero_division=0),
           "fpr": fp / max(1, fp + tn), "fnr": fn / max(1, fn + tp), "cm": [[int(tn), int(fp)], [int(fn), int(tp)]]}
    if len(np.unique(score)) > 1:
        out["roc_auc"] = roc_auc_score(yt, score)
        out["pr_auc"] = average_precision_score(yt, score)
    # precision at a 1% phishing prevalence implied by TPR/FPR (deployment-relevant)
    tpr, fpr = out["recall"], out["fpr"]
    out["precision_at_1pct_prevalence"] = (tpr * 0.01) / max(1e-12, tpr * 0.01 + fpr * 0.99)
    return {k: (round(v, 4) if isinstance(v, float) else v) for k, v in out.items()}


def boot_ci(yt, score, thr):
    n = len(yt)
    vals = defaultdict(list)
    for _ in range(B):
        idx = rng_boot.integers(0, n, n)
        ys, ss = yt[idx], score[idx]
        yp = (ss >= thr).astype(int)
        vals["f1"].append(f1_score(ys, yp, zero_division=0))
        vals["recall"].append(recall_score(ys, yp, zero_division=0))
        tn, fp = ((ys == 0) & (yp == 0)).sum(), ((ys == 0) & (yp == 1)).sum()
        vals["fpr"].append(fp / max(1, fp + tn))
        if len(np.unique(ss)) > 1 and len(np.unique(ys)) == 2:
            vals["roc_auc"].append(roc_auc_score(ys, ss))
            vals["pr_auc"].append(average_precision_score(ys, ss))
    return {k: [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)] for k, v in vals.items()}


def best_f1_threshold(yv, sv):
    cands = np.unique(np.quantile(sv, np.linspace(0.01, 0.99, 197)))
    f = [f1_score(yv, (sv >= t).astype(int), zero_division=0) for t in cands]
    return float(cands[int(np.argmax(f))])


def fpr_threshold(yv, sv, target=0.01):
    neg = np.sort(sv[yv == 0])
    return float(neg[int(np.ceil((1 - target) * len(neg))) - 1] + 1e-9)


def ece(yt, p, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    e = 0.0
    for a, b in zip(edges[:-1], edges[1:]):
        m = (p >= a) & (p < b if b < 1 else p <= b)
        if m.any():
            e += m.mean() * abs(p[m].mean() - yt[m].mean())
    return round(float(e), 4)


def record(name, sv, st, thr_policy="val_best_f1", fixed_thr=None, extra=None, ci=True):
    if fixed_thr is not None:
        thr = fixed_thr
    else:
        thr = best_f1_threshold(y["val"], sv)
    entry = {"threshold_policy": thr_policy if fixed_thr is None else "fixed", "val": metrics(y["val"], sv, thr),
             "test": metrics(y["test"], st, thr)}
    if ci:
        entry["test_ci95"] = boot_ci(y["test"], st, thr)
    if fixed_thr is None and len(np.unique(sv)) > 2:
        t1 = fpr_threshold(y["val"], sv)
        entry["test_at_val_fpr1pct"] = metrics(y["test"], st, t1)
    if extra:
        entry.update(extra)
    R["models"][name] = entry
    return thr

# ---------------------------------------------------------------- trivial baselines
maj = int(np.bincount(y["train"]).argmax())
record("B0_majority", np.full(len(y["val"]), maj, float), np.full(len(y["test"]), maj, float), fixed_thr=0.5, ci=False)
https_i = FEATURE_COLUMNS.index("is_https")
record("B1_http_scheme_rule", 1 - X["val"][:, https_i], 1 - X["test"][:, https_i], fixed_thr=0.5)
# reversed scheme rule (diagnostic: on real data HTTPS is more common among phishing)
record("B1r_https_scheme_rule", X["val"][:, https_i], X["test"][:, https_i], fixed_thr=0.5)

# ---------------------------------------------------------------- shipped SENTINEL-QR (synthetic-trained, zero-shot)
ens = joblib.load(os.path.join(ROOT, "models", "ensemble_qr_model.joblib"))
t0 = time.time()
p_ship = {s: ens.predict_proba(pd.DataFrame(X[s], columns=FEATURE_COLUMNS))[:, 1] for s in ("val", "test")}
R["runtime"]["shipped_ensemble_inference_ms_per_url"] = round((time.time() - t0) * 1000 / (len(y["val"]) + len(y["test"])), 4)
record("S1_shipped_ensemble_thr0.5", p_ship["val"], p_ship["test"], fixed_thr=0.5)
record("S1b_shipped_ensemble_val_thr", p_ship["val"], p_ship["test"])

# rule engine + fusion (threat intelligence = 0, context = 0, as in all recorded runs)
def rule_scores(urls, feats_df):
    out = []
    for u, (_, row) in zip(urls, feats_df.iterrows()):
        out.append(evaluate_rules(u, row.to_dict())["rule_score"])
    return np.array(out, float)
t0 = time.time()
rs = {s: rule_scores(D[s].url, FE[s]) for s in ("val", "test")}
R["runtime"]["rule_engine_ms_per_url"] = round((time.time() - t0) * 1000 / (len(y["val"]) + len(y["test"])), 4)
record("S2_rule_engine_val_thr", rs["val"], rs["test"])
fused = {s: np.array([calculate_hybrid_risk_score(float(p), int(r), {"penalty_score": 0, "is_blacklisted": False}, 0)["final_score"]
                      for p, r in zip(p_ship[s], rs[s])], float) for s in ("val", "test")}
record("S3_shipped_fusion_ge31_suspicious", fused["val"], fused["test"], fixed_thr=31)
record("S3b_shipped_fusion_ge61_malicious", fused["val"], fused["test"], fixed_thr=61)

# ---------------------------------------------------------------- retrained models (train split only; tuned on val)
def fit_lr(Xtr, ytr, C, seed):
    return make_pipeline(StandardScaler(), LogisticRegression(C=C, max_iter=2000, random_state=seed)).fit(Xtr, ytr)

def fit_rf(Xtr, ytr, depth, seed):
    return RandomForestClassifier(n_estimators=300, max_depth=depth, min_samples_leaf=2, max_features="sqrt",
                                  n_jobs=-1, random_state=seed).fit(Xtr, ytr)

def fit_xgb(Xtr, ytr, depth, lr, seed):
    return XGBClassifier(n_estimators=400, max_depth=depth, learning_rate=lr, subsample=0.8, colsample_bytree=0.8,
                         eval_metric="logloss", random_state=seed, n_jobs=-1, verbosity=0).fit(Xtr, ytr)

Xtr, Xva, Xte = X["train"][:, ki], X["val"][:, ki], X["test"][:, ki]
grid = {}
grid["lr"] = {C: roc_auc_score(y["val"], fit_lr(Xtr, y["train"], C, 42).predict_proba(Xva)[:, 1]) for C in (0.01, 0.1, 1.0, 10.0)}
grid["rf"] = {str(d): roc_auc_score(y["val"], fit_rf(Xtr, y["train"], d, 42).predict_proba(Xva)[:, 1]) for d in (10, 20, None)}
grid["xgb"] = {f"{d}_{l}": roc_auc_score(y["val"], fit_xgb(Xtr, y["train"], d, l, 42).predict_proba(Xva)[:, 1])
               for d in (4, 6, 8) for l in (0.05, 0.1)}
bestC = max(grid["lr"], key=grid["lr"].get)
bestD = max(grid["rf"], key=grid["rf"].get)
bestX = max(grid["xgb"], key=grid["xgb"].get)
R["protocol"]["validation_grid_roc_auc"] = {k: {str(a): round(b, 4) for a, b in v.items()} for k, v in grid.items()}
R["protocol"]["selected"] = {"lr_C": bestC, "rf_max_depth": bestD, "xgb_depth_lr": bestX}
rf_depth = None if bestD == "None" else int(bestD)
xd, xl = int(bestX.split("_")[0]), float(bestX.split("_")[1])

seed_runs = defaultdict(list)
final_scores = {}
for seed in SEEDS:
    lr = fit_lr(Xtr, y["train"], bestC, seed)
    rf = fit_rf(Xtr, y["train"], rf_depth, seed)
    xg = fit_xgb(Xtr, y["train"], xd, xl, seed)
    sc = {}
    for name, m in (("R1_logreg", lr), ("R2_random_forest", rf), ("R3_xgboost", xg)):
        sc[name] = {s: m.predict_proba(Xs)[:, 1] for s, Xs in (("val", Xva), ("test", Xte))}
    sc["R4_softvote_321"] = {s: (3 * sc["R3_xgboost"][s] + 2 * sc["R2_random_forest"][s] + sc["R1_logreg"][s]) / 6 for s in ("val", "test")}
    for name, s2 in sc.items():
        thr = best_f1_threshold(y["val"], s2["val"])
        mt = metrics(y["test"], s2["test"], thr)
        seed_runs[name].append({"seed": seed, "test_f1": mt["f1"], "test_roc_auc": mt.get("roc_auc"), "test_fpr": mt["fpr"], "test_recall": mt["recall"]})
    if seed == 42:
        final_scores = sc
        models42 = {"lr": lr, "rf": rf, "xgb": xg}
for name, s2 in final_scores.items():
    runs = seed_runs[name]
    record(name, s2["val"], s2["test"], extra={"seed_variation": {
        k: [round(float(np.mean([r[k] for r in runs])), 4), round(float(np.std([r[k] for r in runs])), 4)] for k in ("test_f1", "test_roc_auc", "test_fpr", "test_recall")}})

# calibration of the soft-vote ensemble on validation (isotonic), evaluated on test
sv, st = final_scores["R4_softvote_321"]["val"], final_scores["R4_softvote_321"]["test"]
iso = IsotonicRegression(out_of_bounds="clip").fit(sv, y["val"])
R["audit"]["calibration_R4"] = {"test_brier_raw": round(brier_score_loss(y["test"], st), 4),
                                "test_brier_isotonic": round(brier_score_loss(y["test"], iso.predict(st)), 4),
                                "test_ece_raw": ece(y["test"], st), "test_ece_isotonic": ece(y["test"], iso.predict(st))}

# timing of retrained ensemble inference
t0 = time.time()
_ = (3 * models42["xgb"].predict_proba(Xte)[:, 1] + 2 * models42["rf"].predict_proba(Xte)[:, 1] + models42["lr"].predict_proba(Xte)[:, 1]) / 6
R["runtime"]["retrained_ensemble_inference_ms_per_url_batch"] = round((time.time() - t0) * 1000 / len(Xte), 4)

# ---------------------------------------------------------------- literature-style baseline: TF-IDF + LR (cf. Sanchez-Paniagua et al.)
tf_grid = {}
vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=200000, sublinear_tf=True)
Ttr = vec.fit_transform(D["train"].url.str.lower()); Tva = vec.transform(D["val"].url.str.lower()); Tte = vec.transform(D["test"].url.str.lower())
for C in (0.1, 1.0, 10.0):
    m = LogisticRegression(C=C, max_iter=3000).fit(Ttr, y["train"])
    tf_grid[C] = (roc_auc_score(y["val"], m.predict_proba(Tva)[:, 1]), m)
bestTC = max(tf_grid, key=lambda c: tf_grid[c][0])
mt = tf_grid[bestTC][1]
R["protocol"]["selected"]["tfidf_lr_C"] = bestTC
record("L1_tfidf_char_lr", mt.predict_proba(Tva)[:, 1], mt.predict_proba(Tte)[:, 1])
p_tfidf_test = mt.predict_proba(Tte)[:, 1]

# ---------------------------------------------------------------- shortcut / leakage audit on real data
single = {}
for c in keep:
    try:
        a = roc_auc_score(y["test"], X["test"][:, FEATURE_COLUMNS.index(c)])
        single[c] = round(max(a, 1 - a), 4)
    except ValueError:
        pass
R["audit"]["single_feature_test_auc_top10"] = dict(sorted(single.items(), key=lambda kv: -kv[1])[:10])
imp = models42["xgb"].feature_importances_
R["audit"]["xgb_gain_importance_top10"] = {keep[i]: round(float(imp[i]) * 100, 2) for i in np.argsort(-imp)[:10]}
# ablation without is_https
k2 = [i for i, c in enumerate(keep) if c != "is_https"]
xa = fit_xgb(Xtr[:, k2], y["train"], xd, xl, 42)
sa_v, sa_t = xa.predict_proba(Xva[:, k2])[:, 1], xa.predict_proba(Xte[:, k2])[:, 1]
record("A1_xgboost_without_is_https", sa_v, sa_t)
# path-presence baseline
pl = FEATURE_COLUMNS.index("path_length")
record("B2_has_path_rule", (X["val"][:, pl] > 1).astype(float), (X["test"][:, pl] > 1).astype(float), fixed_thr=0.5)
# source-identifiability: can features tell the two benign sources apart?
bmask = {s: (D[s].label.values == 0) for s in ("train", "test")}
src = {s: (D[s].source.values[bmask[s]] == "crux").astype(int) for s in ("train", "test")}
srcm = fit_xgb(X["train"][bmask["train"]][:, ki], src["train"], 4, 0.1, 42)
R["audit"]["benign_source_identifiability_test_auc"] = round(roc_auc_score(src["test"], srcm.predict_proba(X["test"][bmask["test"]][:, ki])[:, 1]), 4)

# ---------------------------------------------------------------- subgroup analyses (test) for main models
main = {"S1_shipped_ensemble_thr0.5": (p_ship["test"], 0.5),
        "S3_shipped_fusion_ge31_suspicious": (fused["test"], 31),
        "R4_softvote_321": (final_scores["R4_softvote_321"]["test"], R["models"]["R4_softvote_321"]["val"]["threshold"]),
        "R3_xgboost": (final_scores["R3_xgboost"]["test"], R["models"]["R3_xgboost"]["val"]["threshold"]),
        "L1_tfidf_char_lr": (p_tfidf_test, R["models"]["L1_tfidf_char_lr"]["val"]["threshold"])}
te = D["test"]
path_root = (X["test"][:, pl] <= 1)
groups = {
    "benign_crux_fpr": (te.label.values == 0) & (te.source.values == "crux"),
    "benign_ebbu_fpr": (te.label.values == 0) & (te.source.values == "ebbu2017"),
    "phish_2025_recall": (te.label.values == 1) & te.date.str.startswith("2025").values,
    "phish_2026_recall": (te.label.values == 1) & te.date.str.startswith("2026").values,
    "phish_https_recall": (te.label.values == 1) & (X["test"][:, https_i] == 1),
    "phish_http_recall": (te.label.values == 1) & (X["test"][:, https_i] == 0),
}
for name, (s, thr) in main.items():
    g = {}
    for gn, m in groups.items():
        rate = float((s[m] >= thr).mean()) if m.any() else None
        g[gn] = {"n": int(m.sum()), "rate": round(rate, 4) if rate is not None else None}
    # matched homepage-vs-homepage subset: root-path phishing vs CrUX origins
    mm = path_root & ((te.label.values == 1) | (te.source.values == "crux"))
    if len(np.unique(y["test"][mm])) == 2:
        g["root_path_matched"] = {"n": int(mm.sum()), "n_phish": int(y["test"][mm].sum()), **metrics(y["test"][mm], s[mm], thr)}
    R["subgroups"][name] = g

# ---------------------------------------------------------------- temporal decay of R4 (fixed val threshold)
thr4 = R["models"]["R4_softvote_321"]["val"]["threshold"]
for q in ("2025-01", "2025-04", "2025-07", "2025-10", "2026-01", "2026-04", "2026-07"):
    y0, m0 = int(q[:4]), int(q[5:])
    months = {f"{y0}-{m0 + i:02d}" if m0 + i <= 12 else f"{y0 + 1}-{m0 + i - 12:02d}" for i in range(3)}
    m = (te.label.values == 1) & te.date.str[:7].isin(months).values
    if m.any():
        R["temporal"][q] = {"n_phish": int(m.sum()), "recall_R4": round(float((final_scores["R4_softvote_321"]["test"][m] >= thr4).mean()), 4),
                            "recall_shipped": round(float((p_ship["test"][m] >= 0.5).mean()), 4),
                            "recall_tfidf": round(float((p_tfidf_test[m] >= R["models"]["L1_tfidf_char_lr"]["val"]["threshold"]).mean()), 4)}

json.dump(R, open(OUT, "w"), indent=1, default=lambda o: float(o) if isinstance(o, np.floating) else int(o))
# save scores for figures
np.savez_compressed(OUT.replace(".json", "_scores.npz"), y_test=y["test"], shipped=p_ship["test"], fused=fused["test"],
                    r4=final_scores["R4_softvote_321"]["test"], xgb=final_scores["R3_xgboost"]["test"], tfidf=p_tfidf_test,
                    lr=final_scores["R1_logreg"]["test"], rule=rs["test"])
print("done", OUT)
