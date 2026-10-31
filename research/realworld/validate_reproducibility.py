"""Validate the SENTINEL-QR real-world reproducibility package.

Usage (from research/realworld/):
    python validate_reproducibility.py                 # checks that need only released files
    python validate_reproducibility.py /path/to/r1     # also checks rebuilt split files

/path/to/r1 is the output directory of build_dataset.py (train.csv, val.csv, test.csv).
Each check prints PASS, FAIL, or NOT VERIFIABLE; the script exits with 1 if any check FAILS.
Nothing is downloaded, and no URL is resolved or opened.
"""
import csv
import glob
import hashlib
import json
import os
import sys
from decimal import Decimal, ROUND_HALF_UP

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
R1 = sys.argv[1] if len(sys.argv) > 1 else None
results = []


def report(name, status, detail=""):
    results.append((name, status, detail))
    print(f"[{status:<14}] {name}" + (f" - {detail}" if detail else ""))


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(rel):
    return json.load(open(os.path.join(HERE, rel)))


def half_up(v, nd):
    return str(Decimal(str(v)).quantize(Decimal(1).scaleb(-nd), rounding=ROUND_HALF_UP))


# 1. Required files ------------------------------------------------------------
required = ["README.md", "DATA_PROVENANCE.md", "build_dataset.py", "run_experiments.py", "fetch_sources.sh",
            "experiment_config.json", "split_hashes.json", "environment.txt", "manuscript_claims_audit.csv",
            "data_manifest/manifest.json", "data_manifest/train_hashes.csv", "data_manifest/val_hashes.csv",
            "data_manifest/test_hashes.csv", "results/r1_results.json", "results/r1_results_scores.npz",
            "results/subset_checks.json", "results/cluster_bootstrap.json", "results/leakage_audit.json",
            "results/validity_checks.json"]
missing = [f for f in required if not os.path.exists(os.path.join(HERE, f))]
report("Required files exist", "FAIL" if missing else "PASS", ", ".join(missing))

M = load("data_manifest/manifest.json"); SH = load("split_hashes.json"); CFG = load("experiment_config.json")
RES = load("results/r1_results.json")

# 2. Split hashes: manifest vs split_hashes.json vs rebuilt files ---------------
same = all(SH[s]["sha256"] == M["splits"][s]["file_sha256"] for s in ("train", "val", "test"))
report("split_hashes.json agrees with manifest.json", "PASS" if same else "FAIL")
if R1:
    bad = [s for s in ("train", "val", "test") if sha_file(os.path.join(R1, f"{s}.csv")) != SH[s]["sha256"]]
    report("Rebuilt split files match released split hashes", "FAIL" if bad else "PASS", ", ".join(bad))
else:
    report("Rebuilt split files match released split hashes", "NOT VERIFIABLE",
           "pass the build_dataset.py output directory to check")

# 3. Per-URL hash records, counts and class distribution ------------------------
H = {}
for s in ("train", "val", "test"):
    with open(os.path.join(HERE, f"data_manifest/{s}_hashes.csv")) as fh:
        H[s] = list(csv.DictReader(fh))
ok_counts = all(len(H[s]) == M["splits"][s]["n"] == SH[s]["rows"] for s in H)
report("Sample counts: hash records = manifest = split_hashes.json", "PASS" if ok_counts else "FAIL",
       ", ".join(f"{s}={len(H[s])}" for s in H))
sizes = CFG["benchmark"]["split_sizes"]
ok_cls = all(sum(r["label"] == "1" for r in H[s]) == sizes[s]["phishing"] and
             sum(r["label"] == "0" for r in H[s]) == sizes[s]["benign"] for s in H)
report("Class distribution matches experiment_config.json", "PASS" if ok_cls else "FAIL",
       ", ".join(f"{s}: {sizes[s]['phishing']} phishing / {sizes[s]['benign']} benign" for s in H))
if R1:
    bad = []
    for s in ("train", "val", "test"):
        with open(os.path.join(R1, f"{s}.csv"), encoding="utf-8", newline="") as fh:
            urls = [r["url"] for r in csv.DictReader(fh)]
        if [hashlib.sha256(u.encode("utf-8")).hexdigest() for u in urls] != [r["url_sha256"] for r in H[s]]:
            bad.append(s)
    report("Per-URL SHA-256 records recompute from rebuilt splits", "FAIL" if bad else "PASS", ", ".join(bad))
else:
    report("Per-URL SHA-256 records recompute from rebuilt splits", "NOT VERIFIABLE", "needs rebuilt splits")

# 4. Leakage --------------------------------------------------------------------
sets = {s: {r["url_sha256"] for r in H[s]} for s in H}
ov = {f"{a}-{b}": len(sets[a] & sets[b]) for a, b in (("train", "val"), ("train", "test"), ("val", "test"))}
report("No exact URL shared across splits (from hash records)", "PASS" if not any(ov.values()) else "FAIL", str(ov))
dup = {s: len(H[s]) - len(sets[s]) for s in H}
report("No exact duplicate URL within a split", "PASS" if not any(dup.values()) else "FAIL", str(dup))
LA = load("results/leakage_audit.json")["cross_split"]
dom = {k: v["registered_domain"] for k, v in LA.items()}
if R1:
    doms = {}
    for s in ("train", "val", "test"):
        with open(os.path.join(R1, f"{s}.csv"), encoding="utf-8", newline="") as fh:
            doms[s] = {r["domain"] for r in csv.DictReader(fh)}
    dov = {f"{a}-{b}": len(doms[a] & doms[b]) for a, b in (("train", "val"), ("train", "test"), ("val", "test"))}
    report("No registered domain shared across splits (rebuilt splits)", "PASS" if not any(dov.values()) else "FAIL", str(dov))
else:
    report("No registered domain shared across splits", "PASS" if not any(dom.values()) else "FAIL",
           f"from results/leakage_audit.json {dom}; rerun with rebuilt splits for an independent check")
tmp = load("results/validity_checks.json")["temporal"]["train_or_val_phish_on_or_after_first_test_date"]
report("Temporal order: no train/val phishing on or after first test date", "PASS" if tmp == 0 else "FAIL", f"count={tmp}")

# 5. Configuration and model versions -------------------------------------------
exp = CFG["experiment"]
ok_cfg = exp.get("seeds") and exp.get("bootstrap_resamples") and exp.get("hyperparameter_grids") and exp.get("selected")
report("Seeds, grids, bootstrap size, and selections documented", "PASS" if ok_cfg else "FAIL",
       f"seeds={exp.get('seeds')}, B={exp.get('bootstrap_resamples')}")
ok_sel = exp.get("selected") == RES["protocol"]["selected"]
report("Selected hyperparameters match results/r1_results.json", "PASS" if ok_sel else "FAIL")
mbad = [n for n, h in CFG["shipped_models"].items()
        if not os.path.exists(os.path.join(ROOT, "models", n)) or sha_file(os.path.join(ROOT, "models", n)) != h]
report("Shipped model files match the evaluated versions", "FAIL" if mbad else "PASS", ", ".join(mbad))
cbad = [f for f, h in CFG["code_under_test_sha256"].items() if sha_file(os.path.join(ROOT, f)) != h]
report("Evaluated code modules (features, rules, explainability, model) unchanged", "FAIL" if cbad else "PASS",
       ", ".join(cbad))

# 6. Manuscript claims vs result files -------------------------------------------
with open(os.path.join(HERE, "manuscript_claims_audit.csv"), newline="") as fh:
    claims = list(csv.DictReader(fh))
fails, unsupported = [], []
for c in claims:
    art = c["supporting_artifact"]
    path = os.path.join(ROOT, art) if not art.startswith("research/realworld/") else os.path.join(HERE, art[len("research/realworld/"):])
    if not os.path.exists(path):
        unsupported.append(c["claim"]); continue
    d = json.load(open(path))
    for k in c["json_path"].split("/"):
        d = d[int(k)] if isinstance(d, list) else d[k]
    if c["json_path"].startswith("models/") and c["json_path"].split("/")[2] == "test" and \
            c["json_path"].split("/")[-1] in ("accuracy", "precision", "recall", "f1", "fpr", "precision_at_1pct_prevalence"):
        mdl = c["json_path"].split("/")[1]
        (tn, fp), (fn, tp) = RES["models"][mdl]["test"]["cm"]
        col = c["json_path"].split("/")[-1]
        pr = tp / (tp + fp) if tp + fp else 0; rc = tp / (tp + fn) if tp + fn else 0; fr = fp / (fp + tn) if fp + tn else 0
        d = {"accuracy": (tp + tn) / (tp + tn + fp + fn), "precision": pr, "recall": rc, "fpr": fr,
             "f1": 2 * pr * rc / (pr + rc) if pr + rc else 0,
             "precision_at_1pct_prevalence": 0.01 * rc / (0.01 * rc + 0.99 * fr) if rc or fr else 0}[col]
    fmt = c["format"].split()[0]
    mv = c["manuscript_value"]
    got = {"f3": lambda v: half_up(v, 3), "f4": lambda v: half_up(v, 4), "int": lambda v: str(int(v)),
           "intsp": lambda v: f"{int(v):,}".replace(",", " "), "pct1": lambda v: half_up(v * 100, 1) + "%",
           "pct2": lambda v: half_up(v * 100, 2) + "%"}[fmt](d)
    if got != mv:
        fails.append(f"{c['claim']}: manuscript {mv}, result {got}")
report(f"Manuscript numeric claims match result files ({len(claims)} claims)",
       "FAIL" if fails else "PASS", "; ".join(fails[:5]))
report("Every audited claim has a supporting artifact", "FAIL" if unsupported else "PASS", "; ".join(unsupported[:5]))

# Summary -------------------------------------------------------------------------
from collections import Counter
cnt = Counter(s for _, s, _ in results)
print("\nSummary:", dict(cnt))
json.dump([{"check": n, "status": s, "detail": d} for n, s, d in results],
          open(os.path.join(HERE, "results", "validation_report.json"), "w"), indent=1)
sys.exit(1 if cnt.get("FAIL") else 0)
