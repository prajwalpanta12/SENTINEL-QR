# SENTINEL-QR: Reproduction Instructions

These steps reproduce every number in the manuscript "Synthetic Benchmarks Overstate QR Phishing Detection: A Leakage Audit and Temporally Held-Out Real-World Evaluation of SENTINEL-QR".

On 31 October 2026, the procedure below was run twice:
- once in the original environment;
- once in a clean virtual environment with no cached data.

Both runs reproduced all 1,155 real-world result values and all 277 synthetic-audit values exactly. A third run, from a fresh clone of this repository commit and a fresh download of the sources, reproduced 1,281 result values (including the audit scripts) and all nine figure captions exactly. Timing fields were excluded from the comparison.

## 0. Requirements

- **Python:** 3.11 or newer. The reported runs used Python 3.13.18 on Linux.
- **git:** needed to download the three source datasets.
- **Network access:** to github.com, for the sources only.
- **Disk:** about 1 GB for the raw sources.

```bash
git clone https://github.com/prajwalpanta12/SENTINEL-QR.git
cd SENTINEL-QR
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt matplotlib
# exact versions used: research/realworld/environment.txt
```

## 1. Synthetic benchmark (RQ1)

```bash
python research/audit_experiments.py
```

This writes `research/experiments/dataset_audit.json`. The values to expect:
- ensemble accuracy 0.9947;
- `is_https`-only accuracy 0.9915;
- 352 of the 360 malicious URLs use HTTP, and all 583 benign URLs use HTTPS.

## 2. Real-world benchmark (R1)

```bash
cd research/realworld
bash fetch_sources.sh            # JPCERT/CC e19b194, CrUX 35ba243, Ebbu2017 90b394d -> ./raw
python build_dataset.py raw r1   # seed 20261029; writes r1/{train,val,test}.csv and hash files
python validate_reproducibility.py r1
```

**Expected split SHA-256 hashes:**

| Split | SHA-256 |
|---|---|
| train | `243dffc4bd700a3e14b329b109b01f3370c289430993af7f518ba7256f0d69c1` |
| val | `fe436039c7c8c6f31b58057dea01120c29063b9f16e1879c018b25bfd0de7270` |
| test | `ed9891c503e19b6d9b456d2d866912579eaca1f6b3cc5f203b8e6e9939f54596` |

**Expected validator output:** 16 PASS.

**Data handling:**
- The raw files contain live phishing URLs. Do not open or render them.
- Do not redistribute the raw files.

## 3. Experiments

```bash
python run_experiments.py r1 results/r1_results.json
python subset_checks.py      r1/test.csv results/r1_results_scores.npz results/subset_checks.json
python crux_rank_check.py    r1/test.csv results/r1_results_scores.npz results/r1_results.json results/crux_rank_check.json
python url_type_breakdown.py r1/test.csv results/r1_results_scores.npz results/r1_results.json results/url_type_breakdown.json
python rule_trigger_rates.py r1/test.csv results/rule_trigger_rates.json
python leakage_audit.py      r1 results/leakage_audit.json
python cluster_bootstrap.py  r1/test.csv results/r1_results_scores.npz results/r1_results.json results/cluster_bootstrap.json
python validity_checks.py    r1 results/validity_checks.json
python dedup_sensitivity.py  r1/test.csv results/r1_results_scores.npz results/dedup_sensitivity.json
python shipped_importance.py results/shipped_xgb_gain_importance.json   # gain importance of the shipped XGBoost
python make_paper_figures.py results r1/test.csv figures_out
python validate_reproducibility.py r1     # checks all 134 manuscript numbers against the new results
```

**Runtime:** about 10–15 minutes on a laptop-class CPU (measured: about 11 minutes in the cloud workspace, including the build). Bootstrap B is 1000; there are five seeds.

**Key values to expect (test ROC-AUC):**

| Model | ROC-AUC |
|---|---|
| Shipped ensemble | 0.437 |
| Fusion | 0.531 |
| Rule engine | 0.629 |
| Retrained XGBoost | 0.938 |
| TF-IDF | 0.966 |
| Homepage subset, XGBoost | 0.892 |
| Homepage subset, TF-IDF | 0.924 |
| Benign-source separability | 0.996 |

## 4. Application tests

```bash
cd ../..
python test_system.py    # 52 checks
python test_fixes.py     # 20 checks
streamlit run app.py     # optional: the interface
```

## Notes

- **Code versions.** The application code that was evaluated is the commit tagged `v1.0-evaluated`. The `main` branch adds interface fixes only. `features.py`, `rules.py`, `explainability.py` and `model.py` are unchanged, which `validate_reproducibility.py` verifies by hash.
- **Floating-point differences.** Multithreaded summation can change raw scores by around 1e-16. This does not change any reported value.
- **Public-suffix list.** `features.py` may try to download the live public-suffix list and fall back to the bundled one if it can't. On this dataset, both give identical results.
