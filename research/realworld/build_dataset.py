"""
SENTINEL-QR real-world benchmark builder (R1).

Builds temporally and domain-disjoint train/validation/test splits from three
public GitHub-hosted sources (see fetch_sources.sh for exact commits):

  * JPCERT/CC phishurl-list   -> phishing URLs with confirmation dates
  * zakird/crux-top-lists     -> popular origins (benign, homepage URLs), monthly
  * ebubekirbbr/pdd (Ebbu2017)-> legitimate URLs with paths (Sahingoz et al., 2019)

Design was fixed before any model was evaluated on validation or test data.

Split policy
  phishing : confirmed <= 2023-12-31 -> train; 2024 -> validation; >= 2025-01-01 -> test
  CrUX     : registered domains in 2023-01 list -> train; new in 2024-01 -> validation;
             new in 2026-09 (absent from 2023-01 and 2024-01) -> test
  Ebbu2017 : no dates; split by SHA-1 of registered domain (70/15/15)
Leakage controls
  * exact-duplicate URLs removed (earliest confirmation kept)
  * registered domains (PSL incl. private suffixes) never shared across splits
  * any domain that occurs in both classes is dropped from the benign side
  * validation/test URLs whose digit-collapsed form occurs in train are dropped
Usage: python build_dataset.py RAW_DIR OUT_DIR
"""
import csv, glob, gzip, hashlib, json, os, random, re, sys
from collections import Counter, defaultdict

import tldextract

RAW, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
SEED = 20261029
EXT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)  # offline snapshot

TRAIN_END, VAL_END = "2023-12-31", "2024-12-31"
SIZES = {  # target sample sizes per split (taken as min(target, available))
    "train": {"phish": 30000, "crux": 15000, "ebbu": 15000},
    "val":   {"phish": 8000,  "crux": 4000,  "ebbu": 4000},
    "test":  {"phish": 10000, "crux": 5000,  "ebbu": 5000},
}


def reg_domain(url):
    try:
        host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url).split("/")[0].split("?")[0].split("#")[0]
        host = host.split("@")[-1].split(":")[0].lower().strip(".")
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            return host
        e = EXT(host)
        return e.top_domain_under_public_suffix if hasattr(e, "top_domain_under_public_suffix") else e.registered_domain
    except Exception:
        return ""


def template(url):
    return re.sub(r"\d+", "0", url.lower())


def h(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


log = {"seed": SEED, "train_end": TRAIN_END, "val_end": VAL_END, "steps": []}

# ---------------- phishing: JPCERT/CC ----------------
phish = {}
bad = 0
for f in sorted(glob.glob(os.path.join(RAW, "phishurl-list", "20*", "*.csv"))):
    with open(f, encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            u, d = (row.get("URL") or "").strip(), (row.get("date") or "").strip()
            if not re.match(r"^https?://", u, re.I) or not re.match(r"^\d{4}/\d{2}/\d{2}", d):
                bad += 1
                continue
            day = d[:10].replace("/", "-")
            if u not in phish or day < phish[u]["date"]:
                phish[u] = {"date": day, "brand": row.get("description", "")}
log["steps"].append({"jpcert_unique_urls": len(phish), "jpcert_rows_skipped": bad})

P = defaultdict(list)
for u, m in phish.items():
    split = "train" if m["date"] <= TRAIN_END else ("val" if m["date"] <= VAL_END else "test")
    P[split].append({"url": u, "label": 1, "source": "jpcert", "date": m["date"], "brand": m["brand"], "domain": reg_domain(u)})

# ---------------- benign: CrUX ----------------
def crux(month):
    with gzip.open(os.path.join(RAW, "crux-top-lists", "data", "global", f"{month}.csv.gz"), "rt") as fh:
        r = csv.DictReader(fh)
        return [(x["origin"].strip(), int(x["rank"])) for x in r]

c23, c24, c26 = crux("202301"), crux("202401"), crux("202609")
d23 = {reg_domain(o) for o, _ in c23}
d24 = {reg_domain(o) for o, _ in c24}
def crux_rows(lst, month, exclude):
    seen, rows = set(), []
    for o, rank in lst:
        d = reg_domain(o)
        if not d or d in exclude or d in seen:
            continue
        seen.add(d)
        rows.append({"url": o.rstrip("/") + "/", "label": 0, "source": "crux", "date": month, "rank_bucket": rank, "domain": d})
    return rows
C = {"train": crux_rows(c23, "2023-01", set()),
     "val": crux_rows(c24, "2024-01", d23),
     "test": crux_rows(c26, "2026-09", d23 | d24)}
log["steps"].append({"crux_candidates": {k: len(v) for k, v in C.items()}})

# ---------------- benign: Ebbu2017 ----------------
with open(os.path.join(RAW, "pdd", "input", "data_legitimate_36400.json")) as fh:
    ebbu_urls = list(dict.fromkeys(u.strip() for u in json.load(fh) if re.match(r"^https?://", u.strip(), re.I)))
E = defaultdict(list)
for u in ebbu_urls:
    d = reg_domain(u)
    if not d:
        continue
    b = int(hashlib.sha1(d.encode()).hexdigest(), 16) % 100
    split = "train" if b < 70 else ("val" if b < 85 else "test")
    E[split].append({"url": u, "label": 0, "source": "ebbu2017", "date": "2017", "domain": d})
log["steps"].append({"ebbu_candidates": {k: len(v) for k, v in E.items()}})

# ---------------- label-conflict removal ----------------
phish_domains = {r["domain"] for s in P.values() for r in s}
conf = Counter()
for S, name in ((C, "crux"), (E, "ebbu")):
    for k in S:
        before = len(S[k])
        S[k] = [r for r in S[k] if r["domain"] not in phish_domains]
        conf[name] += before - len(S[k])
log["steps"].append({"benign_dropped_domain_also_phishing": dict(conf)})

# ---------------- sampling + domain/template disjointness ----------------
rng = random.Random(SEED)
final, used_domains, train_templates = {}, set(), set()
drops = defaultdict(Counter)
for split in ("train", "val", "test"):
    pools = {"phish": P[split], "crux": C[split], "ebbu": E[split]}
    chosen = []
    for key, pool in pools.items():
        pool = pool[:]
        rng.shuffle(pool)
        keep = []
        for r in pool:
            if r["domain"] in used_domains:
                drops[split][key + "_domain_seen_earlier"] += 1
                continue
            if split != "train" and template(r["url"]) in train_templates:
                drops[split][key + "_template_in_train"] += 1
                continue
            keep.append(r)
            if len(keep) >= SIZES[split][key]:
                break
        chosen += keep
    # register domains after the whole split is chosen (domains may repeat within a split)
    for r in chosen:
        if split == "train":
            train_templates.add(template(r["url"]))
    used_domains |= {r["domain"] for r in chosen}
    rng.shuffle(chosen)
    final[split] = chosen
log["steps"].append({"drops": {k: dict(v) for k, v in drops.items()}})

# within-split cross-class domain check
for split, rows in final.items():
    dom_lab = defaultdict(set)
    for r in rows:
        dom_lab[r["domain"]].add(r["label"])
    both = [d for d, l in dom_lab.items() if len(l) == 2]
    assert not both, (split, both[:5])

# ---------------- write ----------------
manifest = {"sources": open(os.path.join(os.path.dirname(RAW.rstrip('/')), "source_commits.txt")).read().split("\n")
            if os.path.exists(os.path.join(os.path.dirname(RAW.rstrip('/')), "source_commits.txt")) else [],
            "splits": {}, "build_log": log}
fields = ["url", "label", "source", "date", "domain", "brand", "rank_bucket"]
for split, rows in final.items():
    path = os.path.join(OUT, f"{split}.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    with open(os.path.join(OUT, f"{split}_hashes.csv"), "w") as fh:
        fh.write("url_sha256,label,source,date\n")
        for r in rows:
            fh.write(f"{h(r['url'])},{r['label']},{r['source']},{r['date']}\n")
    dates = sorted(r["date"] for r in rows if r["source"] == "jpcert")
    manifest["splits"][split] = {
        "n": len(rows), "by_source": dict(Counter(r["source"] for r in rows)),
        "phishing_date_range": [dates[0], dates[-1]] if dates else None,
        "unique_domains": len({r["domain"] for r in rows}),
        "https_share_by_label": {str(l): round(sum(r["url"].lower().startswith("https") for r in rows if r["label"] == l) /
                                              max(1, sum(r["label"] == l for r in rows)), 4) for l in (0, 1)},
        "file_sha256": hashlib.sha256(open(path, "rb").read()).hexdigest(),
    }
json.dump(manifest, open(os.path.join(OUT, "manifest.json"), "w"), indent=2)
print(json.dumps(manifest["splits"], indent=2))
print(json.dumps(log["steps"], indent=1))
