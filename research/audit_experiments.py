"""
SENTINEL-QR — Reproducible evidence extraction for the research paper.
Read-only with respect to project artifacts; writes only to research/experiments/.
"""
import json
import os
import re
import sys
import time
import warnings
from collections import Counter

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from features import FEATURE_COLUMNS, extract_url_features  # noqa: E402
import tldextract  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "experiments")
os.makedirs(OUT, exist_ok=True)

df = pd.read_csv(os.path.join(BASE, "data", "dataset.csv"))
report = {}

# ── 1. Corpus composition ────────────────────────────────────────────────────
report["rows"] = int(len(df))
report["columns"] = list(df.columns)
report["label_counts"] = {str(k): int(v) for k, v in df["label"].value_counts().items()}
report["exact_duplicate_urls"] = int(df["url"].duplicated().sum())
report["unique_urls"] = int(df["url"].nunique())

domains = []
for u in df["url"]:
    ext = tldextract.extract(str(u))
    domains.append(ext.registered_domain.lower())
df["_domain"] = domains
df["_tld"] = [tldextract.extract(str(u)).suffix.lower() for u in df["url"]]
df["_scheme"] = [str(u).split("://")[0].lower() if "://" in str(u) else "" for u in df["url"]]

report["unique_registered_domains"] = int(df["_domain"].nunique())
report["scheme_by_label"] = {
    str(k): {str(kk): int(vv) for kk, vv in v.items()}
    for k, v in pd.crosstab(df["_scheme"], df["label"]).to_dict("index").items()
}
report["tld_top15"] = {str(k): int(v) for k, v in df["_tld"].value_counts().head(15).items()}
report["tld_by_label"] = {
    str(k): {str(kk): int(vv) for kk, vv in v.items()}
    for k, v in pd.crosstab(df["_tld"], df["label"]).to_dict("index").items()
}

# Synthetic template families: collapse digit runs / repeated tokens
def template(url: str) -> str:
    s = re.sub(r"\d+", "#", str(url))
    s = re.sub(r"[A-Za-z]{8,}", "<token>", s)
    return s

df["_template"] = [template(u) for u in df["url"]]
report["unique_templates"] = int(df["_template"].nunique())
report["synthetic_sample_urls"] = df["url"].head(6).tolist()

# Zero-variance / duplicated feature columns
fd = df[FEATURE_COLUMNS]
report["constant_features"] = [c for c in FEATURE_COLUMNS if fd[c].nunique() <= 1]
report["duplicate_feature_pairs"] = []
for i, a in enumerate(FEATURE_COLUMNS):
    for b in FEATURE_COLUMNS[i + 1:]:
        if fd[a].equals(fd[b]):
            report["duplicate_feature_pairs"].append([a, b])

# is_https separability
tab = pd.crosstab(fd["is_https"], df["label"])
report["https_crosstab"] = {str(k): {str(kk): int(vv) for kk, vv in v.items()} for k, v in tab.to_dict("index").items()}
acc_https = max((tab.loc[1, 0] + tab.loc[0, 1]) / len(df), (tab.loc[1, 1] + tab.loc[0, 0]) / len(df))
report["single_feature_is_https_accuracy"] = round(float(acc_https), 4)

# ── 2. Reproduce the documented random split ─────────────────────────────────
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

X = df[FEATURE_COLUMNS].fillna(0)
y = df["label"].astype(int)


def make_models():
    xgb = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.08,
                        subsample=0.8, colsample_bytree=0.8, eval_metric="logloss",
                        scale_pos_weight=1.0, random_state=42, n_jobs=-1, verbosity=0)
    rf = RandomForestClassifier(n_estimators=300, max_depth=20, min_samples_split=4,
                                min_samples_leaf=2, max_features="sqrt",
                                class_weight="balanced", random_state=42, n_jobs=-1)
    lr = LogisticRegression(C=1.0, max_iter=1000, solver="lbfgs",
                            class_weight="balanced", random_state=42)
    ens = VotingClassifier(estimators=[("xgb", xgb), ("rf", rf), ("lr", lr)],
                           voting="soft", weights=[3, 2, 1], n_jobs=-1)
    return xgb, rf, lr, ens


def metrics(model, Xte, yte):
    p = model.predict(Xte)
    pr = model.predict_proba(Xte)[:, 1]
    cm = confusion_matrix(yte, p)
    return {
        "accuracy": round(float(accuracy_score(yte, p)), 4),
        "precision": round(float(precision_score(yte, p, zero_division=0)), 4),
        "recall": round(float(recall_score(yte, p, zero_division=0)), 4),
        "f1": round(float(f1_score(yte, p, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(yte, pr)), 4),
        "confusion_matrix": cm.tolist(),
    }


Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
xgb, rf, lr, ens = make_models()
for m in (xgb, rf, lr, ens):
    m.fit(Xtr, ytr)
report["reproduction_random_split"] = {
    "train": int(len(Xtr)), "test": int(len(Xte)),
    "test_safe": int((yte == 0).sum()), "test_malicious": int((yte == 1).sum()),
    "xgboost": metrics(xgb, Xte, yte),
    "random_forest": metrics(rf, Xte, yte),
    "logistic_regression": metrics(lr, Xte, yte),
    "ensemble": metrics(ens, Xte, yte),
}

# ── 3. Diagnostic split A: domain-disjoint ───────────────────────────────────
groups = df["_domain"].fillna("unknown")
uniq = sorted(groups.unique())
rng = np.random.RandomState(7)
rng.shuffle(uniq)
test_groups = set(uniq[: max(1, int(0.2 * len(uniq)))])
mask_test = groups.isin(test_groups)
Xtr_d, Xte_d = X[~mask_test], X[mask_test]
ytr_d, yte_d = y[~mask_test], y[mask_test]
if yte_d.nunique() == 2 and len(Xte_d) >= 10:
    xgb_d, rf_d, lr_d, ens_d = make_models()
    for m in (xgb_d, rf_d, lr_d, ens_d):
        m.fit(Xtr_d, ytr_d)
    report["domain_disjoint_split"] = {
        "test_domains": len(test_groups), "train": int(len(Xtr_d)), "test": int(len(Xte_d)),
        "xgboost": metrics(xgb_d, Xte_d, yte_d),
        "random_forest": metrics(rf_d, Xte_d, yte_d),
        "ensemble": metrics(ens_d, Xte_d, yte_d),
    }
else:
    report["domain_disjoint_split"] = {"error": "degenerate split"}

# ── 4. Diagnostic split B: ablation without is_https (+ duplicate col) ──────
ABLATE = [c for c in FEATURE_COLUMNS if c not in ("is_https", "count_subdomain_levels")]
Xa = df[ABLATE].fillna(0)
Xtr_a, Xte_a, ytr_a, yte_a = train_test_split(Xa, y, test_size=0.2, random_state=42, stratify=y)
xgb_a, rf_a, lr_a, ens_a = make_models()
for m in (xgb_a, rf_a, lr_a, ens_a):
    m.fit(Xtr_a, ytr_a)
report["ablation_no_https"] = {
    "features": len(ABLATE),
    "xgboost": metrics(xgb_a, Xte_a, yte_a),
    "random_forest": metrics(rf_a, Xte_a, yte_a),
    "ensemble": metrics(ens_a, Xte_a, yte_a),
}

# ── 5. Diagnostic split C: scheme-balanced subset ───────────────────────────
# Keep only malicious URLs that use https, plus all http legit URLs (if any).
sub = df[(df["_scheme"] == "https")]
if sub["label"].nunique() == 2:
    Xs, ys = sub[FEATURE_COLUMNS].fillna(0), sub["label"].astype(int)
    Xtr_s, Xte_s, ytr_s, yte_s = train_test_split(Xs, ys, test_size=0.25, random_state=42, stratify=ys)
    xgb_s = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.08,
                          subsample=0.8, colsample_bytree=0.8, eval_metric="logloss",
                          random_state=42, n_jobs=-1, verbosity=0)
    xgb_s.fit(Xtr_s, ytr_s)
    probs_s = xgb_s.predict_proba(Xte_s)[:, 1]
    report["https_only_subset"] = {
        "rows": int(len(sub)), "test": int(len(Xte_s)),
        "xgboost": metrics(xgb_s, Xte_s, yte_s),
        "malicious_probabilities": [round(float(p), 4) for p, t in zip(probs_s, yte_s) if t == 1],
        "max_benign_probability": round(float(probs_s[yte_s == 0].max()), 4),
    }

# ── 6. Cross-validation as configured (on full data) ────────────────────────
xgb_cv, rf_cv, lr_cv, ens_cv = make_models()
cv = cross_val_score(ens_cv, X, y, cv=StratifiedKFold(5), scoring="accuracy", n_jobs=-1)
report["cv_full_data"] = {"mean": round(float(cv.mean()), 4), "std": round(float(cv.std()), 4),
                          "folds": [round(float(v), 4) for v in cv]}

# ── 7. Latency (offline stages only) ────────────────────────────────────────
from rules import evaluate_rules  # noqa: E402
from model import predict_threat  # noqa: E402
from explainability import calculate_hybrid_risk_score  # noqa: E402

sample = df["url"].head(60).tolist()
# warm-up
for u in sample[:5]:
    f = extract_url_features(u)
lat = []
for u in sample:
    t0 = time.perf_counter()
    f = extract_url_features(u)
    r = evaluate_rules(u, f)
    m = predict_threat(u)
    calculate_hybrid_risk_score(m["malicious_prob"], r["rule_score"],
                                {"penalty_score": 0, "is_blacklisted": False}, 0)
    lat.append((time.perf_counter() - t0) * 1000)
report["latency_ms_offline_pipeline"] = {
    "n": len(lat),
    "mean": round(float(np.mean(lat)), 2),
    "median": round(float(np.median(lat)), 2),
    "p95": round(float(np.percentile(lat, 95)), 2),
    "min": round(float(np.min(lat)), 2),
    "max": round(float(np.max(lat)), 2),
    "note": "features + 16 rules + ensemble inference + hybrid scoring; excludes QR decode and network threat-intel",
}

with open(os.path.join(OUT, "dataset_audit.json"), "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)

print(json.dumps({k: report[k] for k in ["rows", "label_counts", "exact_duplicate_urls",
                                         "unique_registered_domains", "unique_templates",
                                         "constant_features", "duplicate_feature_pairs",
                                         "single_feature_is_https_accuracy"]}, indent=2))
print("\nreproduction:", json.dumps(report["reproduction_random_split"], indent=2))
print("\ndomain-disjoint:", json.dumps(report.get("domain_disjoint_split"), indent=2))
print("\nablation:", json.dumps(report["ablation_no_https"], indent=2))
print("\nhttps-only:", json.dumps(report.get("https_only_subset"), indent=2))
print("\ncv:", report["cv_full_data"])
print("\nlatency:", report["latency_ms_offline_pipeline"])
