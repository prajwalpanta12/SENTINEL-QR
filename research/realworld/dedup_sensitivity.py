"""Sensitivity of test ROC-AUC to within-split near-duplicate URLs (second audit).

Usage: python dedup_sensitivity.py /path/to/r1/test.csv results/r1_results_scores.npz results/dedup_sensitivity.json
Keeps the first occurrence of each normalized URL (normalization as in validity_checks.py)
and recomputes ROC-AUC from the stored test scores. No model is retrained.
"""
import json
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from validity_checks import norm  # noqa: E402  (same normalization)

t = pd.read_csv(sys.argv[1]); z = np.load(sys.argv[2]); y = t.label.values
keep = ~t.url.map(norm).duplicated().values
out = {"test_rows": int(len(t)), "kept_after_normalized_dedup": int(keep.sum()),
       "removed_by_label": {str(k): int(v) for k, v in t[~keep].label.value_counts().items()},
       "roc_auc_full_vs_dedup": {k: [round(roc_auc_score(y, z[k]), 4), round(roc_auc_score(y[keep], z[k][keep]), 4)]
                                 for k in z.files if k != "y_test" and len(z[k]) == len(t)}}
json.dump(out, open(sys.argv[3], "w"), indent=1); print(json.dumps(out, indent=1))
