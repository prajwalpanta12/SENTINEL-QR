"""
SENTINEL-QR — Model Trainer v2.5
Trains weighted soft-voting ensemble (XGBoost + RF + LR) on 36-feature dataset.
Run: python train_model.py
"""

import os
import sys
import time
import warnings
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                              f1_score, roc_auc_score, classification_report,
                              confusion_matrix)
from sklearn.preprocessing import label_binarize
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "dataset.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

sys.path.insert(0, BASE_DIR)
from features import FEATURE_COLUMNS


def evaluate_model(model, X_test, y_test, name: str) -> dict:
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_prob)
    print(f"\n  ── {name} ──────────────────────────────────────")
    print(f"  Accuracy  : {acc:.4f}  |  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}  |  F1 Score  : {f1:.4f}")
    print(f"  ROC-AUC   : {auc:.4f}")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  Confusion Matrix:\n{cm}")
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "roc_auc": auc}


def train_and_evaluate_models():
    # ── Load Dataset ──────────────────────────────────────────────────────────
    print("\n" + "="*62)
    print("  SENTINEL-QR — Model Training Pipeline v2.5")
    print("="*62)

    if not os.path.exists(DATA_PATH):
        print(f"\n  ❌ Dataset not found: {DATA_PATH}")
        print("  Run: python data/create_dataset.py  first.\n")
        sys.exit(1)

    df = pd.read_csv(DATA_PATH)
    print(f"\n  📊 Dataset loaded: {len(df)} rows, {len(df.columns)} columns")

    # Ensure all required features present
    missing_cols = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing_cols:
        print(f"\n  ❌ Missing features in dataset: {missing_cols}")
        print("  Delete data/dataset.csv and run: python data/create_dataset.py")
        sys.exit(1)

    X = df[FEATURE_COLUMNS].fillna(0)
    y = df["label"]

    print(f"  📊 Features : {X.shape[1]} (expect 36)")
    print(f"  📊 Class 0 (Legitimate): {(y==0).sum()}")
    print(f"  📊 Class 1 (Malicious) : {(y==1).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n  Train: {len(X_train)} | Test: {len(X_test)}")

    # ── Individual Classifiers ─────────────────────────────────────────────────
    print("\n  [1/4] Training XGBoost Classifier...")
    t0 = time.time()
    xgb_clf = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.08,
        subsample=0.8, colsample_bytree=0.8,
        use_label_encoder=False, eval_metric="logloss",
        scale_pos_weight=1.0, random_state=42, n_jobs=-1,
        verbosity=0
    )
    xgb_clf.fit(X_train, y_train)
    print(f"  ✅ XGBoost trained in {time.time()-t0:.1f}s")

    print("\n  [2/4] Training Random Forest Classifier...")
    t0 = time.time()
    rf_clf = RandomForestClassifier(
        n_estimators=300, max_depth=20, min_samples_split=4,
        min_samples_leaf=2, max_features="sqrt",
        class_weight="balanced", random_state=42, n_jobs=-1
    )
    rf_clf.fit(X_train, y_train)
    print(f"  ✅ Random Forest trained in {time.time()-t0:.1f}s")

    print("\n  [3/4] Training Logistic Regression Classifier...")
    t0 = time.time()
    lr_clf = LogisticRegression(
        C=1.0, max_iter=1000, solver="lbfgs",
        class_weight="balanced", random_state=42, n_jobs=-1
    )
    lr_clf.fit(X_train, y_train)
    print(f"  ✅ Logistic Regression trained in {time.time()-t0:.1f}s")

    # ── Voting Ensemble ───────────────────────────────────────────────────────
    print("\n  [4/4] Training Weighted Soft-Voting Ensemble (XGB×3 + RF×2 + LR×1)...")
    t0 = time.time()
    ensemble = VotingClassifier(
        estimators=[("xgb", xgb_clf), ("rf", rf_clf), ("lr", lr_clf)],
        voting="soft",
        weights=[3, 2, 1],
        flatten_transform=True,
        n_jobs=-1
    )
    ensemble.fit(X_train, y_train)
    print(f"  ✅ Ensemble trained in {time.time()-t0:.1f}s")

    # ── Evaluate All ──────────────────────────────────────────────────────────
    print("\n" + "="*62)
    print("  EVALUATION RESULTS")
    print("="*62)

    xgb_metrics = evaluate_model(xgb_clf, X_test, y_test, "XGBoost")
    rf_metrics = evaluate_model(rf_clf, X_test, y_test, "Random Forest")
    lr_metrics = evaluate_model(lr_clf, X_test, y_test, "Logistic Regression")
    ens_metrics = evaluate_model(ensemble, X_test, y_test, "Voting Ensemble (Primary)")

    # Feature importances (from XGBoost)
    feat_importances = dict(zip(FEATURE_COLUMNS,
                                [float(x) for x in xgb_clf.feature_importances_]))
    top_feats = sorted(feat_importances.items(), key=lambda x: x[1], reverse=True)[:10]
    print("\n  Top 10 Feature Importances (XGBoost):")
    for f, v in top_feats:
        bar = "█" * int(v * 40)
        print(f"  {f:<35} {bar} {v:.4f}")

    ens_metrics["feature_importances"] = feat_importances

    # Cross-validation check (5-fold on ensemble)
    print("\n  Running 5-fold cross-validation on Ensemble...")
    cv_scores = cross_val_score(ensemble, X, y, cv=StratifiedKFold(5), scoring="accuracy", n_jobs=-1)
    print(f"  CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # ── Save Models ───────────────────────────────────────────────────────────
    print("\n" + "="*62)
    print("  SAVING MODELS")
    print("="*62)

    metadata = {
        "n_features": len(FEATURE_COLUMNS),
        "feature_count": len(FEATURE_COLUMNS),
        "feature_columns": FEATURE_COLUMNS,
        "features": FEATURE_COLUMNS,
        "dataset_size": len(df),
        "dataset_samples": len(df),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "primary_model": "Weighted Soft-Voting Ensemble (XGBoost + RF + Logistic Regression)",
        "calibration_status": "not calibrated; weighted soft voting only",
        "ensemble_metrics": ens_metrics,
        "xgboost_metrics": xgb_metrics,
        "random_forest_metrics": rf_metrics,
        "logistic_regression_metrics": lr_metrics,
        "cv_accuracy_mean": float(cv_scores.mean()),
        "cv_accuracy_std": float(cv_scores.std()),
    }

    model_files = {
        "ensemble_qr_model.joblib": ensemble,
        "xgb_qr_model.joblib": xgb_clf,
        "rf_qr_model.joblib": rf_clf,
        "lr_qr_model.joblib": lr_clf,
        "model_metadata.joblib": metadata,
    }

    for fname, obj in model_files.items():
        path = os.path.join(MODELS_DIR, fname)
        joblib.dump(obj, path, compress=3)
        size_kb = os.path.getsize(path) / 1024
        print(f"  ✅ Saved: {fname:<38} ({size_kb:7.1f} KB)")

    # ── JSON mirror for app.py / model.py get_model_metadata() ──────────
    import json as _json
    json_path = os.path.join(MODELS_DIR, "model_metadata.json")
    serializable = {}
    for k, v in metadata.items():
        try:
            _json.dumps({k: v})
            serializable[k] = v
        except Exception:
            serializable[k] = str(v)
    with open(json_path, "w") as jf:
        _json.dump(serializable, jf, indent=2)
    print(f"  ✅ Saved: model_metadata.json (mirror for dashboard)")

    print("\n" + "="*62)
    print(f"  TRAINING COMPLETE")
    print(f"  Ensemble Accuracy  : {ens_metrics['accuracy']*100:.2f}%")
    print(f"  Ensemble F1 Score  : {ens_metrics['f1']:.4f}")
    print(f"  Ensemble ROC-AUC   : {ens_metrics['roc_auc']:.4f}")
    print(f"  Feature Dimensions : {len(FEATURE_COLUMNS)}")
    print("="*62 + "\n")

    return metadata


if __name__ == "__main__":
    train_and_evaluate_models()
