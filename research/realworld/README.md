# Real-world evaluation of SENTINEL-QR (temporal, domain- and template-disjoint)

This directory reproduces every real-data number in the revised manuscript.
**Raw URLs are not redistributed.** You rebuild the benchmark from the public
sources at the pinned commits. `manifest.json` and `*_hashes.csv` let you verify
that your rebuild matches ours byte for byte.

> Safety: the phishing data are live, malicious URLs. The scripts treat them as
> strings only. Do **not** open, fetch, render, or submit them to third-party services.

## 1. Environment
- Python 3.11+ (the reported runs used Python 3.13.18 on Linux; full package list in `environment.txt`).
- scikit-learn 1.9.1, xgboost 3.4.1, numpy 2.5.4, pandas 3.1.0, tldextract 5.4.0, opencv-python 5.0.0 (needed only to import the app's `features.py`), matplotlib 3.11.2 (figures only).
- From the project root: `pip install -r requirements.txt matplotlib`.

## 2. Fetch the sources (pinned commits)
```
cd /path/to/workdir && bash /path/to/fetch_sources.sh   # creates ./raw and source_commits.txt; checks out:
# JPCERTCC/phishurl-list   e19b194b2d23f6c6ab532cf880c99b306992473e
# zakird/crux-top-lists    35ba243941defcd21882b134d9dd354824922482
# ebubekirbbr/pdd          90b394d8f9fb5d5dc48400e8bf46b001ce42999f
```

## 3. Build the benchmark (seed 20261029)
```
python build_dataset.py /path/to/workdir/raw /path/to/r1
sha256sum /path/to/r1/{train,val,test}.csv   # compare with manifest.json -> splits.*.file_sha256
```
Expected hashes:
- train `243dffc4bd700a3e14b329b109b01f3370c289430993af7f518ba7256f0d69c1`
- val   `fe436039c7c8c6f31b58057dea01120c29063b9f16e1879c018b25bfd0de7270`
- test  `ed9891c503e19b6d9b456d2d866912579eaca1f6b3cc5f203b8e6e9939f54596`

The benchmark was rebuilt four times, the last time from a fresh download of the pinned sources, and the files were identical each time.

Split rules, fixed before any test result was inspected:
- Phishing by JPCERT/CC confirmation date: ≤2023-12-31 train; 2024 validation; ≥2025-01-01 test.
- CrUX: 2023-01 list for train; origins new in 2024-01 for validation; 2026-09 origins absent from both earlier lists for test.
- Ebbu2017: 70/15/15 by SHA-1 of the registered domain.
- Benign rows whose registered domain appears anywhere in the phishing list are removed.
- No registered domain appears in two splits. No validation or test URL shares its digit-collapsed template with a training URL.

## 4. Run the experiments
```
python run_experiments.py /path/to/r1 results/r1_results.json
python subset_checks.py   /path/to/r1/test.csv results/r1_results_scores.npz results/subset_checks.json
python crux_rank_check.py /path/to/r1/test.csv results/r1_results_scores.npz results/r1_results.json results/crux_rank_check.json
python url_type_breakdown.py /path/to/r1/test.csv results/r1_results_scores.npz results/r1_results.json results/url_type_breakdown.json
python rule_trigger_rates.py /path/to/r1/test.csv results/rule_trigger_rates.json      # run from this directory
python leakage_audit.py      /path/to/r1 results/leakage_audit.json
python cluster_bootstrap.py  /path/to/r1/test.csv results/r1_results_scores.npz results/r1_results.json results/cluster_bootstrap.json
python validity_checks.py    /path/to/r1 results/validity_checks.json
python dedup_sensitivity.py  /path/to/r1/test.csv results/r1_results_scores.npz results/dedup_sensitivity.json
python shipped_importance.py results/shipped_xgb_gain_importance.json   # gain importance of the shipped XGBoost
python make_paper_figures.py results /path/to/r1/test.csv figures_out   # paper figures F1-F9
```
`run_experiments.py` loads the *shipped* models from `models/` unchanged (S1-S3). It retrains R1-R4, L1, and A1 on the train split, selects hyperparameters and thresholds on validation, and scores the test split once. Seeds: 42 (reported), plus 7, 13, 101, and 2026 for seed variation. Bootstrap: B = 1000.

All scripts after `run_experiments.py` are post-hoc analyses. They were written after the main run and only re-read the split files or its stored test scores; none retrains or retunes a model. `leakage_audit.py`, `cluster_bootstrap.py`, `validity_checks.py`, and `dedup_sensitivity.py` were added during the pre-submission audits.

## 5. Validate the package
```
python validate_reproducibility.py              # released files only
python validate_reproducibility.py /path/to/r1  # also checks your rebuilt split files
```
It checks file presence, split and per-URL hashes, sample counts, class balance, cross-split URL and domain
leakage, temporal order, documented seeds and grids, the shipped model and code hashes, and all 134 audited
manuscript numbers in `manuscript_claims_audit.csv`. Each check reports PASS, FAIL, or NOT VERIFIABLE; the
last run is saved to `results/validation_report.json`.

## 6. Outputs (included)
| File | Content |
|---|---|
| `results/r1_results.json` | All metrics: val and test, CIs, seeds, subgroups, audit, temporal, runtime |
| `results/r1_results_scores.npz` | Test labels and scores per system (no URLs) |
| `results/subset_checks.json` | ROC-AUC on the homepage, path, and HTTPS subsets |
| `results/crux_rank_check.json` | CrUX FPR by rank bucket |
| `results/url_type_breakdown.json` | Recall and FPR by URL type |
| `results/rule_trigger_rates.json` | Firing rate of each shipped rule per class |
| `results/leakage_audit.json` | Exact duplicates, label conflicts, cross-split URL/host/domain/template overlap |
| `results/cluster_bootstrap.json` | Domain-cluster bootstrap CIs (B = 1000) |
| `results/validity_checks.json` | Normalized-URL duplicates, temporal ordering, class balance |
| `results/dedup_sensitivity.json` | Test ROC-AUC with within-split near-duplicates removed |
| `results/shipped_xgb_gain_importance.json` | Gain importance of the shipped XGBoost model (`shipped_importance.py`) |
| `results/number_checks.json`, `results/repro_comparison.json`, `results/ngram_overlap.json` | Pre-submission audit records (manuscript numbers vs results; re-run comparison; text overlap with nine reference papers). The scripts that produced them read the unpublished manuscript source and are not included. |
| `results/repro_comparison_clean_env.json` | Comparison of a re-run in a clean, offline-PSL environment with the published results |
| `results/repro_comparison_fresh_download.json` | Comparison of a full re-run from freshly downloaded sources with the published results |
| `results/run_log.txt` | Completion log of the main run |
| `experiment_config.json` | Seeds, grids, selected hyperparameters, split rules, source commits, shipped model and code hashes |
| `split_hashes.json` | SHA-256 of each split CSV |
| `environment.txt` | Exact Python package versions used |
| `manuscript_claims_audit.csv` | 134 manuscript numbers linked to the result field that supports each |
| `results/validation_report.json` | Last output of `validate_reproducibility.py` |
| `results/synthetic_rerun_comparison.json` | Re-run of the synthetic-benchmark audit (277 values, 0 differences) |
| `logs/` | Logs of the 2026-10-31 fresh-download rebuild and re-run, and of the synthetic re-run |
| `data_manifest/manifest.json` | Source commits, split sizes, date ranges, file hashes, build log |
| `data_manifest/*_hashes.csv` | Per-row SHA-256(url), label, source, date |

## 7. Known non-determinism and network dependence
`build_dataset.py` parses domains with tldextract's bundled public-suffix snapshot and never goes online.
The application's `features.py` calls `tldextract.extract()` with its defaults, which first try to download the
live public-suffix list and fall back to the bundled snapshot if that fails (a logged warning, not an error).
On 2026-10-31 a run in a clean environment with no network access to publicsuffix.org reproduced all
1,155 real-world result values and the 277 synthetic-audit values exactly, so the suffix-list source did not
affect any reported number; a future suffix list could still change individual features.

XGBoost and random forest results vary slightly by seed (SD of test ROC-AUC ≤ 0.0007). Threaded floating-point arithmetic can shift the fourth decimal across platforms. On the same platform, a full re-run from a fresh download reproduced every metric exactly; two stored score arrays differed by at most 3.3e-16 (`results/repro_comparison_fresh_download.json`).
