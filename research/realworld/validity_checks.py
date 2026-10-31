"""Additional validity checks for the R1 benchmark (added in the second audit).

Usage: python validity_checks.py /path/to/r1 results/validity_checks.json

1. Normalized-URL duplication within and across splits. Normalization: lower-case scheme
   and host, drop the scheme, a leading "www.", default ports, the fragment, a trailing "/",
   and sort the query parameters.
2. Temporal ordering: phishing report dates and benign list dates per split; checks that
   no training or validation phishing URL is dated on or after the first test date.
3. Class balance per split and per source.
URLs are handled as strings only; nothing is resolved or fetched.
"""
import json
import sys
from urllib.parse import urlsplit, parse_qsl, urlencode

import pandas as pd


def norm(u: str) -> str:
    try:
        p = urlsplit(u.strip())
        host = (p.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        port = p.port
        if port and not ((p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)):
            host = f"{host}:{port}"
        path = p.path.rstrip("/")
        q = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
        return host + path + ("?" + q if q else "")
    except ValueError:
        return u.strip().lower()


def main(r1_dir, out_path):
    D = {s: pd.read_csv(f"{r1_dir}/{s}.csv") for s in ("train", "val", "test")}
    out = {"normalized_duplicates": {}, "temporal": {}, "balance": {}}
    N = {s: set(d.url.map(norm)) for s, d in D.items()}
    for s, d in D.items():
        n = d.url.map(norm)
        conflict = d.assign(n=n).groupby("n").label.nunique()
        out["normalized_duplicates"][s] = {
            "rows": int(len(d)), "unique_normalized": int(n.nunique()),
            "within_split_duplicates": int(len(d) - n.nunique()),
            "normalized_urls_with_both_labels": int((conflict > 1).sum())}
    for a, b in (("train", "val"), ("train", "test"), ("val", "test")):
        out["normalized_duplicates"][f"{a}-{b}_overlap"] = len(N[a] & N[b])

    ph = {s: pd.to_datetime(d[d.label == 1].date, errors="coerce") for s, d in D.items()}
    first_test = ph["test"].min()
    out["temporal"] = {
        s: {"phish_min": str(ph[s].min().date()), "phish_max": str(ph[s].max().date()),
            "benign_dates": sorted(D[s][D[s].label == 0].date.astype(str).unique().tolist())[:10]}
        for s in D}
    out["temporal"]["train_or_val_phish_on_or_after_first_test_date"] = int(
        (ph["train"] >= first_test).sum() + (ph["val"] >= first_test).sum())
    for s, d in D.items():
        out["balance"][s] = {"phish": int((d.label == 1).sum()), "benign": int((d.label == 0).sum()),
                             "by_source": {k: int(v) for k, v in d.source.value_counts().items()}}
    json.dump(out, open(out_path, "w"), indent=1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
