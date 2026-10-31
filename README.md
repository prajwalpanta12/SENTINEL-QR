# SENTINEL-QR: AI-Based QR Code Threat Analyzer

SENTINEL-QR is an **academic research prototype** for inspecting QR-code payloads. It
decodes QR images, classifies the payload (URL, UPI, Wi-Fi, e-mail, telephone, or plain
text), and applies a type-specific analysis path. URL payloads use 36 lexical and
structural features, 16 transparent heuristics, a weighted soft-voting ensemble
(XGBoost + Random Forest + Logistic Regression), optional threat intelligence, and a
documented fusion formula.

> **Status:** research prototype, not a production security product. The reported
> random-split accuracy is reproducible, but the corpus is synthetic and
> template-generated. The result is a controlled prototype evaluation, not evidence of
> field accuracy. See `research/realworld/` for the real-world evaluation.


> **Reproducing the paper:** see [`REPRODUCE.md`](REPRODUCE.md). The real-world benchmark is rebuilt from
> three public repositories pinned to fixed commits (`research/realworld/fetch_sources.sh`); raw URLs are
> not redistributed. `research/realworld/validate_reproducibility.py` checks hashes, splits, leakage, and
> every audited manuscript number. The code version evaluated in the paper is tagged `v1.0-evaluated`.

## Architecture

```
QR image / direct payload
        |
        v
Dual decoder: OpenCV -> pyzbar -> CLAHE retry
        |
        v
Payload classifier and URL validator
        |
        +--> URL branch: 36 features -> 16 rules -> 3-model ensemble -> threat intel
        |                         \___________________________/
        |                                      |
        |                                      v
        |                         Hybrid score + explanation
        |
        +--> UPI / Wi-Fi / e-mail / telephone branch: type-specific rules
        |
        v
Dashboard, session history, batch scan, and optional PDF report
```

The URL fusion formula is:

```
R_raw = 50*p_ML + 30*(S_rule/100) + 10*(S_intel/100) + 10*(S_context/100)
```

`S_context` is currently always zero in the URL workflow. A monotone rule floor and an
88-point blacklist floor are then applied:

```
R' = max(R_raw, 35 + 0.3*(S_rule - 50))   if S_rule >= 50
R  = round(clamp(max(R', 88 if blacklisted else 0), 0, 100))
```

Verdict bands are SAFE (0-30), SUSPICIOUS (31-60), and MALICIOUS (61-100).

## Feature set

There are **36 features** in `features.py`, grouped as lexical counts and ratios,
domain/host properties, query-string properties, security indicators, and structural
properties. Examples include URL/domain/path length, digit and special-character ratios,
subdomain depth, raw-IP host, HTTPS, shortener membership, suspicious TLD, punycode,
brand impersonation, redirect count, query entropy, sensitive file extension, and
vowel/consonant ratio.

Five features are constant and twelve pairs are exactly duplicated in the shipped
corpus. `redirect_count` and `has_redirect` are always zero because redirect expansion
is disabled. These are documented limitations, not hidden preprocessing steps.

## Heuristic rules (16)

The rule engine is in `rules.py`. Points are hand-assigned; the raw maximum is 305 and
the score is clipped at 100.

| Rule ID | Name | Severity | Points |
| :--- | :--- | :---: | ---: |
| `RULE_IP_HOST` | Raw IP address as host | CRITICAL | 25 |
| `RULE_DANGEROUS_DOWNLOAD` | Executable / malware download target | CRITICAL | 30 |
| `RULE_AT_SYMBOL` | Embedded `@` authentication evasion | CRITICAL | 25 |
| `RULE_PUNYCODE` | Punycode / IDN homograph | CRITICAL | 25 |
| `RULE_BRAND_SPOOFING` | Brand impersonation | HIGH | 25 |
| `RULE_URL_SHORTENER` | URL shortener | HIGH | 20 |
| `RULE_REDIRECT_CHAIN` | Multi-hop redirect chain | HIGH | 20 |
| `RULE_SUSPICIOUS_KEYWORD` | Credential-lure keywords | HIGH | up to 25 |
| `RULE_NO_HTTPS` | Cleartext HTTP | MEDIUM | 15 |
| `RULE_HIGH_ENTROPY` | High character entropy | MEDIUM | 15 |
| `RULE_DGA_VOWEL_ANOMALY` | DGA-like vowel/consonant pattern | MEDIUM | 15 |
| `RULE_SUSPICIOUS_TLD` | High-abuse TLD | MEDIUM | 15 |
| `RULE_EXCESSIVE_SUBDOMAINS` | Deeply nested subdomains | MEDIUM | 15 |
| `RULE_NON_STANDARD_PORT` | Non-standard port | MEDIUM | 15 |
| `RULE_PARAMETER_SMUGGLING` | Query parameter smuggling | LOW | 10 |
| `RULE_EXCESSIVE_LENGTH` | URL longer than 75 characters | LOW | 10 |

`RULE_REDIRECT_CHAIN` cannot fire in the deployed workflow because redirects are not
resolved. `RULE_SUSPICIOUS_KEYWORD` replaces its 20-point base with
`min(25, 15 + 5*(k-1))` when multiple lure terms are present.

## Model and benchmark

- Shipped corpus: **943 rows** (583 benign, 360 malicious).
- Features: **36**.
- Split: stratified 80/20, seed 42 (754 train / 189 test).
- Ensemble: weighted soft voting with weights **3:2:1**. There is no meta-learner and
  no probability calibration; the shipped JSON and joblib metadata now describe it as a weighted soft-voting ensemble.

Reproduced random-split metrics (189 test URLs):

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Weighted soft-voting ensemble | 0.9947 | 1.0000 | 0.9861 | 0.9930 | 1.0000 |
| XGBoost | 0.9947 | 1.0000 | 0.9861 | 0.9930 | 1.0000 |
| Random Forest | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Logistic Regression | 0.9947 | 1.0000 | 0.9861 | 0.9930 | 1.0000 |

**Do not read this table as field performance.** All 583 benign URLs use HTTPS while
352 of 360 malicious URLs use HTTP; the single feature `is_https` alone reaches 99.15%.
Removing HTTPS features still gives 98.94%. A domain-disjoint split reaches 100% because
templates cross the split. The HTTPS-only subset has only two malicious test URLs, and
recall falls to 50% (1 of 2).

### Real-world benchmark (independent of the table above)

On a temporally, domain-, and template-disjoint benchmark (JPCERT/CC phishing URLs reported in
2025-2026 vs. CrUX and Ebbu2017 benign URLs; 18 923 test URLs) the shipped ensemble reached a
ROC-AUC of 0.437 and a phishing recall of 3.3%. Scripts, hashes, and results are in
`research/realworld/` (see its README and `DATA_PROVENANCE.md`). These are the figures to quote.

## Threat intelligence

URLhaus requires a free abuse.ch Auth-Key (sidebar field or the `URLHAUS_AUTH_KEY`
environment variable); without one it is reported as not configured and no request is
sent. VirusTotal and Google Safe Browsing are optional and require user-supplied API keys. The aggregate status distinguishes:

- a confirmed or suspicious match;
- a clean result in an available feed;
- an unavailable feed;
- a feed that was not configured.

An outage or missing key is not reported as a clean result. A confirmed malicious hit
sets the blacklist floor. No live-feed evaluation is claimed in the paper.

## Reports and security

The PDF report includes the payload, verdict, score, component values, triggered rules,
guidance, and an optional QR image. It displays the **full SHA-256 checksum** of the
payload and states that the checksum is an integrity check, **not a digital signature**.
Decoded payloads are escaped before HTML and PDF rendering. Manual reports carry a note
that the URL, score, and verdict were entered by the user.

The application has no authentication, access control, database, or persistent history.
Scanning a URL may contact the destination (TLS probe) and threat-intelligence providers.
Do not scan sensitive or internal URLs without authorization. Redirect expansion is
disabled; a safe SSRF-resistant resolver is not implemented.

## Quick start

```powershell
cd path\to\SENTINEL-QR
.\.venv\Scripts\Activate.ps1
streamlit run app.py
```

The dashboard opens at `http://localhost:8501`.

## Tests and reproduction

```powershell
# System test suite (52 wiring/behaviour checks)
$env:PYTHONIOENCODING="utf-8"
.\.venv\Scripts\python.exe test_system.py

# Regression tests for the post-evaluation fixes (20 checks)
.\.venv\Scripts\python.exe test_fixes.py

# Dataset audit, splits, ablations, HTTPS-only diagnostic, latency
.\.venv\Scripts\python.exe research\audit_experiments.py

# Case-study pipeline over the nine demonstration QR images
.\.venv\Scripts\python.exe research\case_study.py
```

Outputs are written to `research/experiments/` (figures to `research/figures/`, created on demand). The test suite is
an engineering check, not a measure of detection accuracy.

## Paper

The manuscript "Synthetic Benchmarks Overstate QR Phishing Detection: A Leakage Audit and Temporally
Held-Out Real-World Evaluation of SENTINEL-QR" is under preparation and is not included here. Every
real-data number in it can be regenerated with the scripts in `research/realworld/` (see its README).
The exact code version evaluated in the paper is tagged `v1.0-evaluated`; `main` adds the
post-evaluation interface fixes listed below, which do not change URL scores.

## Limitations

The corpus is synthetic and template-generated; labels come from the generator lists,
not from verified campaigns. Benign examples contain no login pages or account
dashboards, so the model separates authoring styles rather than phishing from legitimate
use. No temporal split, adversarial perturbation, mobile latency measurement, or
independent non-URL corpus was used. The UPI blacklist is a ten-entry mock, and the
Wi-Fi, e-mail, and phone rules are unvalidated heuristics. The explanation layer is a
rule-derived factor ranking, not SHAP or model attribution.


## Post-evaluation fixes (this copy)

All published results were produced with the previous version. After the evaluation, four
interface defects were corrected; `features.py`, `rules.py`, `model.py`, `explainability.py`,
and `threat_intel.py` are byte-identical to the evaluated version, so URL scores are unchanged.

1. SSL card: a certificate-verification failure is now shown as "Cert invalid" instead of "No TLS"
   (`utils.check_ssl_certificate` returns a `status` field).
2. PDF report: the Rule ID column now reads the `id` key used by URL rules instead of printing "RULE".
3. UPI analyzer: plain mobile-number handles (10 digits starting 6-9, optional 91 prefix) no
   longer trigger HIGH_ENTROPY_VPA.
4. Benchmark and dashboard views now warn that their metrics come from the synthetic dataset.
5. Decoder: pyzbar is restricted to QR symbols (1-D product barcodes are no longer analysed as
   QR payloads); the CLAHE retry creates its own detector; decoder failures are logged.
6. Unreadable uploaded or webcam images produce an error message instead of a crash.
7. The sidebar shows URLhaus as inactive when no Auth-Key is configured.
8. A failed Google Safe Browsing request no longer shows the API key: the error text, which
   contains the request URL with the key, is replaced by the exception type.
9. If `models/model_metadata.json` is missing, the dashboard and benchmark views show N/A instead of 0.

`test_fixes.py` covers all nine changes (20 checks). Known design limitations that were
deliberately not changed, because changing them would alter the evaluated model or scores:
`count_subdomain_levels` duplicates `count_subdomains`; five features are constant on the
shipped data; redirect resolution is never called, so `RULE_REDIRECT_CHAIN` cannot fire; the
context-risk term is always 0; the UPI blacklist is a ten-entry mock.

## Licensing

This repository does not yet contain a LICENSE file; the author must choose one before
public release. All Python dependencies use permissive licences (MIT, BSD, Apache-2.0,
MIT-CMU). The optional pyzbar decoder loads the system ZBar library, which is LGPL-2.1
and is linked dynamically, not distributed here. The real-world data are not redistributed;
obtain them from the original repositories under their terms (CrUX lists: CC BY 4.0).
