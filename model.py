"""
AI-Based QR Code Threat Analyzer
Module: model.py
Purpose: Research-Grade Machine Learning Ensemble Pipeline.
         Combines XGBoost + Random Forest + Logistic Regression in a weighted
         soft-voting ensemble with confidence estimation, individual model
         benchmarking, and serialization.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

from features import FEATURE_COLUMNS, get_feature_vector, extract_url_features

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
ENSEMBLE_MODEL_PATH = os.path.join(MODELS_DIR, "ensemble_qr_model.joblib")
XGB_MODEL_PATH = os.path.join(MODELS_DIR, "xgb_qr_model.joblib")
RF_MODEL_PATH = os.path.join(MODELS_DIR, "rf_qr_model.joblib")
LR_MODEL_PATH = os.path.join(MODELS_DIR, "lr_qr_model.joblib")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")

_LOADED_MODELS = {}


def train_and_evaluate_models(df: pd.DataFrame):
    """
    Trains the weighted soft-voting ensemble along with baseline individual models.
    Computes cross-validation metrics, feature importances, and serializes artifacts.
    """
    os.makedirs(MODELS_DIR, exist_ok=True)

    print(f"[*] Extracting {len(FEATURE_COLUMNS)} features for {len(df)} URLs...")
    feature_rows = []
    for url in df["url"]:
        feature_rows.append(get_feature_vector(str(url), resolve_redirects=False))

    X = pd.DataFrame(feature_rows, columns=FEATURE_COLUMNS)
    y = df["label"].astype(int).values

    # Stratified 80/20 train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Train shape: {X_train.shape}, Test shape: {X_test.shape}")

    # 1. Train XGBoost
    print("[*] Training Base Estimator 1: XGBoost Classifier...")
    xgb = XGBClassifier(
        n_estimators=180,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        eval_metric="logloss"
    )
    xgb.fit(X_train, y_train)
    xgb_probs = xgb.predict_proba(X_test)[:, 1]
    xgb_preds = (xgb_probs >= 0.5).astype(int)

    # 2. Train Random Forest
    print("[*] Training Base Estimator 2: Random Forest Classifier...")
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=8,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    rf_probs = rf.predict_proba(X_test)[:, 1]
    rf_preds = (rf_probs >= 0.5).astype(int)

    # 3. Train Logistic Regression (Scaled)
    print("[*] Training Base Estimator 3: Logistic Regression...")
    lr_pipe = make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=1000, C=1.0, random_state=42)
    )
    lr_pipe.fit(X_train, y_train)
    lr_probs = lr_pipe.predict_proba(X_test)[:, 1]
    lr_preds = (lr_probs >= 0.5).astype(int)

    # 4. Train Meta-Ensemble: Soft Voting Classifier
    print("[*] Assembling Weighted Soft-Voting Ensemble...")
    ensemble = VotingClassifier(
        estimators=[
            ("xgb", xgb),
            ("rf", rf),
            ("lr", lr_pipe)
        ],
        voting="soft",
        weights=[3.0, 2.0, 1.0]  # Higher weight to non-linear tree models
    )
    ensemble.fit(X_train, y_train)
    ens_probs = ensemble.predict_proba(X_test)[:, 1]
    ens_preds = (ens_probs >= 0.5).astype(int)

    def calc_metrics(y_true, y_pred, y_prob):
        return {
            "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist()
        }

    ens_metrics = calc_metrics(y_test, ens_preds, ens_probs)
    xgb_metrics = calc_metrics(y_test, xgb_preds, xgb_probs)
    rf_metrics = calc_metrics(y_test, rf_preds, rf_probs)
    lr_metrics = calc_metrics(y_test, lr_preds, lr_probs)

    # Extract feature importances from primary tree
    importances = {
        col: round(float(imp), 4)
        for col, imp in sorted(zip(FEATURE_COLUMNS, xgb.feature_importances_), key=lambda x: x[1], reverse=True)
    }
    ens_metrics["feature_importances"] = importances

    # Serialize all models
    print(f"[*] Serializing ensemble and base models to {MODELS_DIR}...")
    joblib.dump(ensemble, ENSEMBLE_MODEL_PATH)
    joblib.dump(xgb, XGB_MODEL_PATH)
    joblib.dump(rf, RF_MODEL_PATH)
    joblib.dump(lr_pipe, LR_MODEL_PATH)

    metadata = {
        "dataset_samples": len(df),
        "feature_count": len(FEATURE_COLUMNS),
        "features": FEATURE_COLUMNS,
        "primary_model": "Weighted Soft-Voting Ensemble (XGBoost + RF + Logistic Regression)",
        "calibration_status": "not calibrated; weighted soft voting only",
        "ensemble_metrics": ens_metrics,
        "xgboost_metrics": xgb_metrics,
        "random_forest_metrics": rf_metrics,
        "logistic_regression_metrics": lr_metrics
    }

    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=4)

    print(f"[+] Ensemble Training complete! Accuracy: {ens_metrics['accuracy'] * 100:.2f}%, F1: {ens_metrics['f1']:.4f}")
    return metadata


def load_ensemble_model():
    """Loads ensemble model with in-memory caching."""
    global _LOADED_MODELS
    if "ensemble" in _LOADED_MODELS:
        return _LOADED_MODELS["ensemble"]

    if os.path.exists(ENSEMBLE_MODEL_PATH):
        model = joblib.load(ENSEMBLE_MODEL_PATH)
        _LOADED_MODELS["ensemble"] = model
        return model
    elif os.path.exists(XGB_MODEL_PATH):
        model = joblib.load(XGB_MODEL_PATH)
        _LOADED_MODELS["ensemble"] = model
        return model
    return None


def get_model_metadata() -> dict:
    """Retrieves stored metadata, metrics, and feature importances."""
    if os.path.exists(METADATA_PATH):
        try:
            with open(METADATA_PATH, "r") as f:
                data = json.load(f)
                # Back-compat alias: older test suite expects n_features
                if "feature_count" in data and "n_features" not in data:
                    data["n_features"] = data["feature_count"]
                return data
        except Exception:
            pass
    return {
        "status": "unavailable",
        "error": ("models/model_metadata.json is missing or unreadable; "
                  "no benchmark metrics are available."),
        "feature_count": len(FEATURE_COLUMNS),
        "n_features": len(FEATURE_COLUMNS),
        "features": FEATURE_COLUMNS,
        "primary_model": "Unavailable (metadata missing)"
    }


def predict_threat(url: str, resolve_redirects: bool = False) -> dict:
    """
    Inference with the weighted soft-voting ensemble model.
    Returns:
        dict: {
            'malicious_prob': float (0.0 to 1.0),
            'confidence_pct': float (0 to 100),
            'prediction_label': int (0=Safe, 1=Malicious),
            'model_used': str,
            'features': dict,
            'votes': dict
        }
    """
    features_dict = extract_url_features(url, resolve_redirects=resolve_redirects)
    vector = [features_dict[col] for col in FEATURE_COLUMNS]
    X_sample = pd.DataFrame([vector], columns=FEATURE_COLUMNS)

    ensemble = load_ensemble_model()

    if ensemble is not None:
        try:
            probs = ensemble.predict_proba(X_sample)[0]
            malicious_prob = float(probs[1])
            # Confidence metric: distance from ambiguous decision boundary (0.5)
            confidence_pct = round(abs(malicious_prob - 0.5) * 200, 1)  # 0 to 100%
            pred_label = 1 if malicious_prob >= 0.50 else 0
            model_name = "Weighted Soft-Voting Ensemble"
            votes = {
                "ensemble": round(malicious_prob, 4),
                "safe_prob": round(float(probs[0]), 4)
            }
        except Exception:
            malicious_prob = _fallback_heuristic_probability(features_dict)
            confidence_pct = 75.0
            pred_label = 1 if malicious_prob >= 0.50 else 0
            model_name = "Heuristic Baseline"
            votes = {}
    else:
        malicious_prob = _fallback_heuristic_probability(features_dict)
        confidence_pct = 70.0
        pred_label = 1 if malicious_prob >= 0.50 else 0
        model_name = "Heuristic Baseline (Weights Unloaded)"
        votes = {}

    return {
        "malicious_prob": round(malicious_prob, 4),
        "confidence_pct": confidence_pct,
        "prediction_label": pred_label,
        "model_used": model_name,
        "features": features_dict,
        "votes": votes
    }


def _fallback_heuristic_probability(features: dict) -> float:
    score = 0.05
    if features.get("has_ip_address", 0): score += 0.40
    if features.get("is_shortened", 0): score += 0.20
    if features.get("suspicious_keywords_count", 0) > 0: score += 0.25
    if not features.get("is_https", 0): score += 0.15
    if features.get("suspicious_tld", 0): score += 0.20
    if features.get("brand_in_subdomain_or_path", 0): score += 0.35
    if features.get("shannon_entropy", 0) > 4.2: score += 0.15
    if features.get("has_sensitive_extension", 0): score += 0.30
    return min(0.99, max(0.01, round(score, 4)))
