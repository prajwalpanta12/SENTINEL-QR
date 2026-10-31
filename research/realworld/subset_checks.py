"""Post-hoc source-artifact subsets computed from stored test scores (no retraining)."""
import sys, json, numpy as np, pandas as pd
from urllib.parse import urlsplit
from sklearn.metrics import roc_auc_score
d = pd.read_csv(sys.argv[1]); z = np.load(sys.argv[2])
assert (d.label.values == z['y_test']).all()
path = d.url.map(lambda u: urlsplit(u).path or "/")
root = path.isin(["/", ""])
out = {}
for name, mask in {
  "ebbu_vs_phish_with_path": ((d.source=="ebbu2017") | ((d.label==1) & ~root)),
  "crux_vs_phish_root": ((d.source=="crux") | ((d.label==1) & root)),
  "https_only_all": d.url.str.startswith("https://"),
}.items():
    m = mask.values; y = d.label.values[m]
    out[name] = {"n": int(m.sum()), "n_phish": int(y.sum()),
                 **{k: round(float(roc_auc_score(y, z[k][m])),4) for k in ("shipped","fused","rule","lr","xgb","r4","tfidf")}}
json.dump(out, open(sys.argv[3],"w"), indent=1); print(json.dumps(out, indent=1))
