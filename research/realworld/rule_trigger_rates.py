"""Post-hoc: firing rate of each of the 16 shipped URL rules on the real test set, by class.
URLs are processed as strings only (resolve_redirects disabled inside evaluate_rules)."""
import sys, json, collections, pandas as pd
sys.path.insert(0, "../..")
from rules import evaluate_rules
import rules as R
d = pd.read_csv(sys.argv[1])
ids = [r["id"] for r in R.RULES_SPEC] if hasattr(R, "RULES_SPEC") else None
cnt = {0: collections.Counter(), 1: collections.Counter()}; n = collections.Counter()
for u, y in zip(d.url, d.label):
    n[y] += 1
    for t in evaluate_rules(u)["triggered_rules"]:
        cnt[y][t["id"]] += 1
allids = sorted(set(cnt[0]) | set(cnt[1]) | set(ids or []))
out = {i: {"phish_rate": round(cnt[1][i] / n[1], 4), "benign_rate": round(cnt[0][i] / n[0], 4)} for i in allids}
json.dump({"n": {"phish": n[1], "benign": n[0]}, "rates": out}, open(sys.argv[2], "w"), indent=1)
for i, v in sorted(out.items(), key=lambda kv: -kv[1]["phish_rate"]): print(i.ljust(28), v)
