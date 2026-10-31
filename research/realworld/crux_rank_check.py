"""FPR on CrUX test benign by rank bucket, at the validation-selected thresholds stored in r1_results.json."""
import sys, json, numpy as np, pandas as pd
d = pd.read_csv(sys.argv[1]); z = np.load(sys.argv[2]); R = json.load(open(sys.argv[3]))
out = {}
for key, mk in (("xgb", "R3_xgboost"), ("tfidf", "L1_tfidf_char_lr")):
    thr = R["models"][mk]["val"]["threshold"]
    for b, g in d[d.source == "crux"].groupby("rank_bucket"):
        idx = g.index.values
        out.setdefault(str(int(b)), {"n": int(len(idx))})[key + "_fpr"] = round(float((z[key][idx] >= thr).mean()), 4)
json.dump(out, open(sys.argv[4], "w"), indent=1); print(out)
