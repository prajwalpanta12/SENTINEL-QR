"""Post-hoc: 95% CIs by registered-domain cluster bootstrap (B=1000, seed 20261031) on stored test scores,
compared with the per-URL bootstrap reported in r1_results.json. No retraining."""
import sys, json, numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score
d = pd.read_csv(sys.argv[1]); z = np.load(sys.argv[2]); R = json.load(open(sys.argv[3]))
y = z["y_test"]; assert (d.label.values == y).all()
codes, uniq = pd.factorize(d.domain)
groups = [np.where(codes == g)[0] for g in range(len(uniq))]
rng = np.random.default_rng(20261031); B = 1000
thr = {"xgb": R["models"]["R3_xgboost"]["val"]["threshold"], "tfidf": R["models"]["L1_tfidf_char_lr"]["val"]["threshold"], "shipped": 0.5}
keys = {"shipped": "S1_shipped_ensemble_thr0.5", "xgb": "R3_xgboost", "tfidf": "L1_tfidf_char_lr"}
res = {"n_urls": int(len(y)), "n_domains": int(len(uniq)), "phish_domains": int(d[d.label == 1].domain.nunique()),
       "benign_domains": int(d[d.label == 0].domain.nunique()), "max_urls_per_domain": int(d.domain.value_counts().max()), "models": {}}
for k, mk in keys.items():
    aucs, f1s = [], []
    for _ in range(B):
        idx = np.concatenate([groups[g] for g in rng.integers(0, len(groups), len(groups))])
        yy, ss = y[idx], z[k][idx]
        if yy.min() == yy.max(): continue
        aucs.append(roc_auc_score(yy, ss)); p = ss >= thr[k]
        tp = (p & (yy == 1)).sum(); fp = (p & (yy == 0)).sum(); fn = (~p & (yy == 1)).sum()
        f1s.append(2 * tp / (2 * tp + fp + fn))
    res["models"][k] = {"roc_auc_cluster_ci": [round(float(np.percentile(aucs, 2.5)), 4), round(float(np.percentile(aucs, 97.5)), 4)],
                        "f1_cluster_ci": [round(float(np.percentile(f1s, 2.5)), 4), round(float(np.percentile(f1s, 97.5)), 4)],
                        "roc_auc_url_ci": R["models"][mk]["test_ci95"]["roc_auc"], "f1_url_ci": R["models"][mk]["test_ci95"]["f1"]}
json.dump(res, open(sys.argv[4], "w"), indent=1); print(json.dumps(res, indent=1))
