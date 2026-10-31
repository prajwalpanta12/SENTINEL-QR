"""Post-hoc: phishing recall and benign FPR by URL type on the real test set,
using stored scores and the validation-selected thresholds in r1_results.json (no retraining)."""
import sys, re, json, numpy as np, pandas as pd
from urllib.parse import urlsplit
sys.path.insert(0, "../..")
from features import SHORTENER_DOMAINS
d = pd.read_csv(sys.argv[1]); z = np.load(sys.argv[2]); R = json.load(open(sys.argv[3]))
assert (d.label.values == z["y_test"]).all()
thr = {"shipped": 0.5, "xgb": R["models"]["R3_xgboost"]["val"]["threshold"], "tfidf": R["models"]["L1_tfidf_char_lr"]["val"]["threshold"]}
sp = d.url.map(urlsplit)
host = sp.map(lambda s: (s.hostname or ""))
types = {
    "HTTP scheme": d.url.str.lower().str.startswith("http://"),
    "Raw IP host": host.str.fullmatch(r"\d{1,3}(\.\d{1,3}){3}"),
    "URL shortener": d.domain.isin(SHORTENER_DOMAINS) | host.isin(SHORTENER_DOMAINS),
    "Root path only": sp.map(lambda s: (s.path or "/") == "/" and not s.query),
    "Has query string": sp.map(lambda s: bool(s.query)),
    "Length > 75 chars": d.url.str.len() > 75,
    "Punycode (xn--)": host.str.contains("xn--", regex=False),
    "Non-standard port": sp.map(lambda s: s.port not in (None, 80, 443)),
}
out = {}
for name, m in types.items():
    m = m.fillna(False).values.astype(bool)
    row = {}
    for lab, key in ((1, "phish"), (0, "benign")):
        mm = m & (d.label.values == lab)
        row[f"n_{key}"] = int(mm.sum())
        for s in ("shipped", "xgb", "tfidf"):
            row[f"{'recall' if lab else 'fpr'}_{s}"] = round(float((z[s][mm] >= thr[s]).mean()), 4) if mm.sum() else None
    out[name] = row
json.dump({"thresholds": thr, "by_type": out}, open(sys.argv[4], "w"), indent=1)
for k, v in out.items(): print(k.ljust(20), v)
