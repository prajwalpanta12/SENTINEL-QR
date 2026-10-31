# FINAL AUDIT REPORT — SENTINEL-QR

**Audit date:** 2026-10-21  
**Repository:** `C:\Users\Asus\OneDrive\Documents\qr_threat_analyzer`  
**Final deliverables:** `paper/research_paper_final.docx` and
`paper/research_paper_final.pdf`

---

## 1. Bottom line

The final manuscript is a corrected version of the latest Word-saved upload, not
a generic replacement. The current artifact is **22 pages** with **11 numbered
tables (I–XI) plus Algorithm 1**, **6 figures**, and **17 references**. The title
is on page 1, the running draft header is absent, references begin on page 21 and
end on page 22, and no page is blank.

This pass corrected two prior-work defects that were present in the previous
final:

- The PILU-90K **69.50%** figure is the **accuracy** of the most resilient
  homepage-trained baseline on 30,000 legitimate login URLs, not recall. The
  proposed TF-IDF + logistic-regression model reports **96.50% accuracy**.
- The Quishing paper reports a **130,239-item evaluation table** (Table 1) and a
  **1,582,927-item unseen evaluation table** (Table 3). The earlier "130K and
  1.58M URL tables from four public sources" wording was an imprecise
  paraphrase.

The empirical result of this paper is unchanged: **99.47% random-split
accuracy**, but `is_https` alone reaches **99.15%**, the no-HTTPS ablation still
reaches **98.94%**, and XGBoost's HTTPS-only recall is **50% (1 of 2)**. The paper
remains an engineering baseline and dataset-leakage audit, not a validated field
detector.

The manuscript is **not yet submission-ready** because the author identity,
declarations, and institutional template are still missing. The current layout is
a preliminary single-column IEEE-style format; **no claim of official IEEE
compliance is made**.

---

## 2. Final files, provenance, and hashes

| File | Bytes | SHA-256 |
|---|---:|---|
| `paper/research_paper_final.docx` | 741,503 | `3e5c73575f9182836f56bc6ed0df2cfc198c8e4037db18fdadebbfa2b8cc191b` |
| `paper/research_paper_final.pdf` | 882,037 | `ab1c206fb6f1e4ddcd3f3cdfa2e5df64ea2accebac82865c12f2d90a3eb6cbf1` |

Provenance:

| File | Bytes | SHA-256 |
|---|---:|---|
| Author's Word-saved upload, preserved as `backups/manuscript_pilu_quishing_20261021_175521/research_paper_final 12.docx` | 808,541 | `ff4a3f6c24f34eec65356d66a57d0f95a8f26809e44bbedb3b873113c484f584` |
| Original copy in `C:\Users\Asus\Downloads\research_paper_final 12.docx` | 808,541 | `ff4a3f6c24f34eec65356d66a57d0f95a8f26809e44bbedb3b873113c484f584` |
| `paper/research_paper_draft.docx` | 729,333 | `be1a57d5929ae47e5039ee576ab876d2e79c96b9f438145b5cab054e042420c2` |
| `paper/research_paper_draft.pdf` | 884,416 | `96999ff6a7b400c70635c402e77c68932783ff80f477332c93cdd37271590926` |

The current DOCX was corrected **directly in the Word-saved upload** so that the
corrected prior-work text and the saved layout would not be reverted. The PDF
was then exported from that DOCX with Microsoft Word read-only automation.

The superseded pre-correction final remains preserved at
`backups/manuscript_pilu_quishing_20261021_175521/research_paper_final.pre_correction.docx`
(SHA-256 `f7c34ba9e5a913c0f8d6d963e9dcf4e646e4d70426229aa249472302c06de98b`) and
its PDF
(`61d983acc2cfd2a69033729b13e81a14d380a2b45cf1bc81cc38e12e56ce4802`). It was not
overwritten.

The manuscript backup is
`backups/manuscript_pilu_quishing_20261021_175521/` (10 files: the upload,
pre-correction DOCX/PDF, six pre-correction audit documents, and the prior hash
manifest).

---

## 3. Work completed in this pass

| Item | Before | After | Evidence |
|---|---|---|---|
| PILU 69.50% label | Table I said "69.50% recall" | Body and Table I say **69.50% accuracy** for the most resilient homepage-trained baseline; all models misclassified more than 30% of login URLs | `research/literature/p5_loginurl.txt`, Fig. 4 and conclusion; `paper/evidence_and_claims_audit.md` L4 |
| PILU proposed model | 96.50% was omitted | Body and Table I report **96.50% accuracy** for TF-IDF + logistic regression on PILU-90K | `research/literature/p5_loginurl.txt`; `paper/references_audit.md` |
| Quishing evaluation sets | Table I said "130K and 1.58M URL tables from four public sources" | Body and Table I distinguish **130,239 items** (Table 1) from **1,582,927 items** (Table 3) | `research/literature/p3_quishing.txt`, Tables 1 and 3 |
| Quishing sources | Earlier draft called them "aggregated Kaggle URL corpora" | ISCX-URL2016, Hugging Face, PhiUSIIL, and the Machine Learning Lab dataset | `research/literature/p3_quishing.txt`; `paper/references_audit.md` |
| Quishing Random Forest accuracy | 0.97 | **0.97, unchanged** | Same source |
| PDF/page count | 23 pages | **22 pages** after the final Word edit | PDF inspection and previews |
| Reference-to-claim audit | Incomplete | **17 of 17 verified; unverified entries: none** | `paper/references_audit.md` |
| In-text citation reconciliation | Not re-run | Every `[1]`–`[17]` is cited; no missing, duplicate, or out-of-range citation | DOCX extraction |

The corrected strings appear in the body on PDF page 3 and in Table I on page 4.
The old strings `69.50% recall`, `130K and 1.58M`, and the older "aggregated
Kaggle URL corpora" phrasing are absent from the final PDF text.

---

## 4. Citation and bibliography reconciliation

- `paper/references.bib` contains **17 entries**.
- The DOCX contains **17 reference entries** after the References heading.
- The body cites every number from **1 through 17** at least once.
- There are **no missing citations, no out-of-range citations, and no duplicate
  reference lines**.
- References remain in first-appearance order.

All 17 entries are verified in `paper/references_audit.md`:

- **7 DOI-bearing papers** checked against Crossref records.
- **7 patent records** checked against the first page of official patent PDFs.
- **3 non-DOI works** checked against the NeurIPS proceedings page, OpenCV's
  official citation guidance plus the CiNii record, and the JMLR article page.

**Unverified entries: none.**

The recorded caveats are:

- [15] The NeurIPS page does not print a page range; the entry keeps the commonly
  used pp. 4765–4774 convention.
- [16] The original Dr. Dobb's URL is no longer reachable and the article has no
  DOI; the citation was checked against OpenCV's guidance and the CiNii record.
- The patent entries were checked for bibliographic identity and dates, not for
  the technical validity of their claims.

No live network recheck was completed after the network outage. The archived
verification evidence is in `paper/evidence/reference_verification.txt`.

---

## 5. Table, figure, and manuscript checks

| Check | Result |
|---|---|
| DOCX opens in Word and exports to PDF | Yes; Microsoft Word 2019 export completed without error |
| PDF page count | **22** |
| Blank pages | None; every page has substantive extracted text |
| Running header | Absent: no `word/header*.xml` parts and no `w:headerReference` |
| Footer page numbers | Two footer parts, both containing a `PAGE` field; rendered previews show page numbers 1–22 |
| First-page title | `SENTINEL-QR: An AI-Based QR Code Threat Analyzer` |
| Sections | Abstract, I–VII, Declarations, References |
| Tables | 12 table objects: 11 numbered tables (I–XI) plus Algorithm 1 |
| Figures | 6 inline figures |
| References | [1]–[17]; References heading on page 21, final entry [17] on page 22 |
| Corrected PILU text | Page 3 body; page 4 Table I |
| Corrected Quishing text | Page 3 body; page 4 Table I |
| Old PILU/Quishing strings | Absent |
| PDF metadata | Title, author placeholder, subject, keywords, producer Microsoft Word 2019 |
| Page previews | `paper/evidence/page_previews_final22/contact_sheet.png` and selected full-page renders |

All six embedded DOCX images are byte-identical to their source files:

| DOCX part | Source | SHA-256 prefix |
|---|---|---|
| `word/media/image1.png` | `research/figures/fig1_architecture.png` | `c97110cb…` |
| `word/media/image2.png` | `research/figures/fig2_dataset.png` | `8bc9c1f8…` |
| `word/media/image3.png` | `research/figures/fig3_feature_importance.png` | `e4616766…` |
| `word/media/image4.png` | `research/figures/fig4_confusion.png` | `f59c0843…` |
| `word/media/image5.png` | `research/figures/fig5_diagnostics.png` | `4f78e6d9…` |
| `word/media/image6.png` | `research/figures/fig6_case_study.png` | `184cb15a…` |

The quantitative tables were checked against the archived evidence:

- **Table VII** against `dataset_audit.json`.
- **Table IX** and **Table X** against `dataset_audit.json`.
- **Table XI** against `case_study.json`.
- **Table VI** against `paper/evidence/environment.txt`.
- **Table V** against `train_model.py`.
- **Tables II–IV** against the shipped code and dataset specification.
- **Table I** against the local full-text extracts for [1]–[3] and [5].

No table or figure was regenerated for this pass; the manuscript-only edit did
not touch the experiments, models, dataset, or figures.

---

## 6. Empirical results and test status

The numbers in the paper are unchanged and remain supported by
`research/experiments/dataset_audit.json`, `research/experiments/case_study.json`,
and `paper/experiment_summary.json`:

- **943 rows**: 583 benign, 360 malicious.
- Random split: **99.47% accuracy**, 1.0000 precision, 0.9861 recall, 0.9930 F1,
  1.0000 ROC-AUC on 189 held-out URLs.
- `is_https` alone: **99.15%**.
- No-HTTPS ablation: **98.94%**; ROC-AUC 0.9994.
- Domain-disjoint split: **100%** because templates cross the split.
- HTTPS-only subset: 148 test URLs (146 benign, 2 malicious); **99.32%**
  accuracy and **50%** recall for XGBoost.
- Five-fold CV: **99.58% ± 0.40 points**; folds are not independent.
- Offline latency: mean **64.64 ms**, median **62.28 ms**, p95 **69.40 ms**;
  load-dependent.
- Case-study URL scores: **1, 5, 36, 78, 71, 74**; all nine demo images decoded.

The last full test run recorded **48 passed, 0 failed, 0 warnings**
(`paper/evidence/test_run_final.txt`). Tests were **not rerun after this
manuscript-only text edit**, because no application, model, dataset, or test file
was changed. The earlier test evidence remains the applicable code audit.

The synthetic-data, template-leakage, HTTPS-only, tiny-positive-set,
feature-dependence, and generalization caveats remain in the manuscript.

---

## 7. Reproducibility and build warning

The experiment, case-study, figure, and test commands are documented in
`paper/reproducibility_checklist.md`; they regenerate evidence without changing
the final DOCX. The PDF export command is also documented there.

**Do not run `research/papergen/build.py` to rebuild the final manuscript.** That
build source is historical and still contains the pre-correction PILU/Quishing
front matter. Rebuilding would overwrite the corrected Word-edited final. The
current DOCX is the authoritative artifact; the papergen path would require
reconciliation and re-verification before it could be used again.

The final hash manifest is `paper/evidence/SHA256SUMS.txt`. The machine-readable
verification record is `paper/evidence/final_verification.json`.

---

## 8. Unresolved limitations

These are stated in the manuscript and are not hidden:

1. The corpus is synthetic and template-generated; labels come from generator
   lists, not verified campaigns.
2. All benign URLs use HTTPS while almost all malicious URLs use HTTP; the model
   learns a corpus shortcut.
3. Domain-disjoint evaluation still shares templates and does not estimate field
   generalization.
4. The HTTPS-only subset has only two malicious test URLs; XGBoost recall is 50%.
5. The fusion context term is always zero; 10% of the formula is inert.
6. Redirect features are dormant because redirect expansion is disabled.
7. The UPI blacklist is a ten-entry mock; Wi-Fi, e-mail, and phone rules are
   unvalidated heuristics.
8. The explanation layer covers 11 of 16 rules and is not SHAP.
9. The PDF is hash-stamped but unsigned.
10. No probability calibration was performed.
11. No live threat-feed evaluation was performed; URLhaus was unavailable in the
    final run.
12. Latency is load-dependent and measured on one desktop.
13. There is no authentication, persistence, or access control.
14. The layout is a preliminary single-column IEEE-style format, not a verified
    institutional template.

---

## 9. Items still required from the author

The following are genuine submission blockers, not evidence defects. They are
organized by category for clarity.

### 9.1 Author identity and declarations (must be supplied by you)

| Item | Placeholder in manuscript | Status |
|---|---|---|
| Full name | `[Student Name]` | ☐ Not supplied |
| Registration number | `[Registration Number]` | ☐ Not supplied |
| Department | `[Department]` | ☐ Not supplied |
| Institution | `[Institution]` | ☐ Not supplied |
| Email address | `[Email Address]` | ☐ Not supplied |
| Author contributions | `[to be completed]` in Declarations | ☐ Not supplied |
| Acknowledgements | `[to be completed]` in Declarations | ☐ Not supplied |
| Supervisor name & title | `[to be completed]` in Declarations | ☐ Not supplied |
| Funding statement (or "none") | `[to be completed]` in Declarations | ☐ Not supplied |
| Competing interests (or "none") | `[to be completed]` in Declarations | ☐ Not supplied |

### 9.2 Institutional template and formatting (must be obtained from your university/department)

| Item | Current state | Action required |
|---|---|---|
| Official template (margins, title block, declaration page, certificate, acknowledgements, font, heading numbering) | Preliminary single-column IEEE-style format; note on page 1 states this | Obtain template from department office / website; apply it; confirm the preliminary-format note can be removed |
| Required citation style (IEEE, APA, or institutional) | IEEE-style numbered citations in first-appearance order | Confirm with department; renumber if a different style is mandated |
| Page limit, abstract limit, keyword count, table/figure limits | Current final is 22 pages | Confirm limits from examination notification / department guidelines; trim only if required |

### 9.3 Institutional similarity / plagiarism check (must be run by you on the university portal)

| Item | Details |
|---|---|
| Portal | University-specific: commonly **Turnitin** (via LMS or direct), **Urkund/Ouriginal**, or **iThenticate**. You must log in with your university credentials. |
| Input | Final PDF (`paper/research_paper_final.pdf`). |
| Output | Similarity report PDF. Archive this report with your submission package. |
| Score | No score is recorded here. Do not fabricate a similarity percentage. |
| Timing | Run after all text is finalized, close to the submission deadline. |

### 9.4 Final live DOI/URL check (must be performed by you near the submission date)

| Item | Details |
|---|---|
| Scope | All 17 references in `paper/references.bib`. |
| Method | Open each DOI (e.g., `https://doi.org/10.xxxx`) and each URL in a browser; confirm the record resolves to the correct title, authors, venue, and year. |
| Archival status | As of 2026-10-21, all 17 entries were verified against archived Crossref records, official patent PDFs, and proceedings pages (see `paper/references_audit.md` and `paper/evidence/reference_verification.txt`). No live network recheck was performed after the network outage. |
| Timing | Perform within 24–48 hours of submission. Do not claim a live check was done without actually doing it. |

---

The author block still contains `[Student Name]`, `[Registration Number]`,
`[Department]`, `[Institution]`, and `[Email Address]`. The preliminary-format
note remains on page 1 because no official template was supplied.

---

## 10. Verdict

**The evidence, citation, table, figure, and manuscript audit is complete for the
current text. The administrative submission package is not complete.**

The paper can be defended as a reproducible engineering baseline and a
demonstration that a flattering benchmark can be an artifact of corpus
construction. It should not be described as production-ready, calibrated,
SHAP-based, cryptographically tamper-evident, state-of-the-art, or as evidence of
field accuracy. It should not be called officially IEEE-formatted until the
institutional template and formatting requirements are confirmed.

Do not declare the manuscript submission-ready until the author details,
declarations, template, and similarity check in Section 9 are supplied.
