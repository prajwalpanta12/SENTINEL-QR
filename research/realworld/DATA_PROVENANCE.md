# Dataset provenance, licensing, and ethics

## Sources actually used
| Source | Commit (date) | What was taken | License / terms | Label meaning |
|---|---|---|---|---|
| JPCERTCC/phishurl-list | e19b194b2d23f6c6ab532cf880c99b306992473e (2026-10-16) | 290,692 rows (2019-2026); 279,758 unique http(s) URLs; 33 malformed rows skipped. Columns: date confirmed by JPCERT/CC, URL, spoofed brand | No LICENSE file in the repository. Published publicly by JPCERT/CC. Treated as research-use-only and **not redistributed** | Phishing (confirmed by JPCERT/CC) |
| zakird/crux-top-lists | 35ba243941defcd21882b134d9dd354824922482 (2026-10-13) | Global lists 202301, 202401, 202609 (origin, rank bucket). 202201 and 202501 were fetched but not used | CC BY 4.0 (attribution: Chrome UX Report via Z. Durumeric's cache; see Ruth et al., IMC 2022) | Benign **proxy** (popularity) |
| ebubekirbbr/pdd | 90b394d8f9fb5d5dc48400e8bf46b001ce42999f (2019-05-30) | data_legitimate_36400.json (Ebbu2017 legitimate URLs) | No LICENSE file. Associated publication: Sahingoz et al., ESWA 2019. Not redistributed | Benign **proxy** |

## Sources requested but not used, and why
PhishTank, OpenPhish, URLhaus, Tranco, Kaggle, Zenodo, UCI, Hugging Face, Mendeley, and the PILU-90K archive could not be reached from the isolated execution environment; URLhaus also requires an Auth-Key. No access control was circumvented, and no mirrors or caches of blocked content were used.

## Labeling caveats (do not ignore)
- CrUX popularity does **not** mean benign. Benign rows were filtered only by removing registered domains that also appear in the phishing list (370 CrUX, 429 Ebbu2017). No live blocklist check was possible. Residual benign label noise is **unquantified**.
- CrUX supplies origins only, so every CrUX URL is a homepage (`scheme://host/`).
- Ebbu2017 dates from around 2017 and is easy to tell apart from 2025-2026 phishing (path-subset ROC-AUC up to 0.995). Treat it as a confounded source.
- The JPCERT/CC brand mix is Japan-focused.
- None of these URLs is known to have been delivered via a QR code.

## What is released
Build and experiment scripts, pinned commits, per-row SHA-256 of each URL with its label, source, and date, split-file hashes, and results JSON. No raw URL appears in any released file, manuscript, or figure.

## Hashing procedure
`data_manifest/{train,val,test}_hashes.csv` contain one row per URL, in split-file order:
`url_sha256,label,source,date`, where `url_sha256 = SHA-256(url.encode("utf-8"))` in lower-case hex.
The URL string is hashed exactly as it appears in the split file. Leading and trailing whitespace is
stripped when the source files are read; no other normalization (case, scheme, trailing slash) is applied.
`split_hashes.json` gives the SHA-256 of each complete split CSV file as written by `build_dataset.py`.

These hashes are **integrity and identity records, not anonymization**. The URLs come from public lists,
so anyone holding those lists can recompute the hashes and recover which URL each row refers to.

## Handling
URLs were processed as strings only. Nothing was resolved, fetched, rendered, or submitted to any service. The SENTINEL-QR redirect resolver stayed disabled, and the threat-intelligence layer was unconfigured.
