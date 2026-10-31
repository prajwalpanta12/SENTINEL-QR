"""Gain importance of the shipped XGBoost base learner (models/xgb_qr_model.joblib), in percent.

Usage (from research/realworld/): python shipped_importance.py results/shipped_xgb_gain_importance.json
Reads only the shipped model; no data are needed. Values are rounded to two decimals.
"""
import json
import os
import sys

import joblib

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
from features import FEATURE_COLUMNS  # noqa: E402

xgb = joblib.load(os.path.join(ROOT, "models", "xgb_qr_model.joblib"))
gain = xgb.get_booster().get_score(importance_type="gain")
names = list(xgb.get_booster().feature_names or [f"f{i}" for i in range(len(FEATURE_COLUMNS))])
total = sum(gain.values())
out = {}
for i, col in enumerate(FEATURE_COLUMNS):
    key = names[i] if i < len(names) else f"f{i}"
    out[col] = round(100 * gain.get(key, 0.0) / total, 2)
json.dump(out, open(sys.argv[1], "w"), indent=1)
print(json.dumps(dict(sorted(out.items(), key=lambda kv: -kv[1])[:5]), indent=1))
