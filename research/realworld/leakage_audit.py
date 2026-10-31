"""Post-hoc leakage audit of the R1 benchmark (no model involved).
Checks exact duplicates, cross-split URL / registered-domain / template overlap,
host-level overlap, near-duplicates (same host+path ignoring query), class balance,
and label conflicts. Writes results/leakage_audit.json."""
import sys, re, json, pandas as pd
from urllib.parse import urlsplit
D = {s: pd.read_csv(f"{sys.argv[1]}/{s}.csv") for s in ("train", "val", "test")}
tmpl = lambda u: re.sub(r"\d+", "0", u.lower())
host = lambda u: (urlsplit(u).hostname or "").lower()
hp = lambda u: (lambda s: (s.hostname or "").lower() + (s.path or "/").rstrip("/"))(urlsplit(u.lower()))
out = {"sizes": {}, "within_split": {}, "cross_split": {}}
for s, d in D.items():
    out["sizes"][s] = {"n": len(d), "phish": int(d.label.sum()), "benign": int((d.label == 0).sum())}
    out["within_split"][s] = {"exact_duplicate_urls": int(d.url.duplicated().sum()),
                              "label_conflicting_domains": int((d.groupby("domain").label.nunique() > 1).sum())}
def keys(d, f): return set(d.url.map(f))
for a, b in (("train", "val"), ("train", "test"), ("val", "test")):
    A, B = D[a], D[b]
    out["cross_split"][f"{a}-{b}"] = {
        "url": len(set(A.url) & set(B.url)),
        "registered_domain": len(set(A.domain) & set(B.domain)),
        "hostname": len(keys(A, host) & keys(B, host)),
        "digit_collapsed_template": len(keys(A, tmpl) & keys(B, tmpl)),
        "host_plus_path_ignoring_query": len(keys(A, hp) & keys(B, hp)),
    }
json.dump(out, open(sys.argv[2], "w"), indent=1); print(json.dumps(out, indent=1))
