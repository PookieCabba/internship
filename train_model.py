"""
============================================================
train_model.py — Model Training Pipeline
============================================================
This script orchestrates the full training workflow:

  1. Load the dataset (CSV with 'url' and 'label' columns)
  2. Extract 27 lexical features using the shared features module
  3. Split into stratified train/test sets (80/20)
  4. Train an XGBoost classifier with tuned hyperparameters
  5. Evaluate with accuracy, classification report, confusion
     matrix, and ROC-AUC
  6. Serialize the trained model + scaler to disk via joblib

Usage:
    python train_model.py

Outputs:
    models/phishing_model.joblib    — Trained XGBoost model
    models/feature_scaler.joblib    — Fitted StandardScaler
    models/training_report.txt      — Evaluation metrics

Author:  Senior AI & Cybersecurity Engineer
Version: 1.0.0
============================================================
"""

import json
import logging
import os
import time
from datetime import datetime

# pyrefly: ignore[missing-import]
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler

# Import the shared feature extraction module
from features import FEATURE_NAMES, extract_features_batch

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────
DATASET_PATH = "data/phishing_dataset.csv"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "feature_scaler.joblib")
REPORT_PATH = os.path.join(MODEL_DIR, "training_report.txt")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")

TEST_SIZE = 0.20           # 20% held out for testing
RANDOM_STATE = 42          # Reproducibility seed
CV_FOLDS = 5              # Cross-validation folds

# Random Forest hyperparameters (tuned for URL phishing detection)
RF_PARAMS = {
    "n_estimators": 300,           # Number of trees in the forest
    "max_depth": 20,               # Maximum tree depth
    "min_samples_split": 5,        # Min samples required to split a node
    "min_samples_leaf": 2,         # Min samples required at a leaf node
    "max_features": "sqrt",        # Features considered at each split
    "class_weight": "balanced",    # Automatically handle class imbalance
    "criterion": "gini",           # Split quality metric
    "bootstrap": True,             # Bootstrap samples for building trees
    "oob_score": True,             # Enable out-of-bag score estimation
    "random_state": RANDOM_STATE,
    "n_jobs": -1,                  # Use all CPU cores
    "verbose": 0,                  # Suppress training logs
}

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────

def load_dataset(path: str) -> pd.DataFrame:
    """
    Load and validate the dataset from a CSV file.

    Expected format:
        url,label
        https://google.com,0
        http://192.168.1.1/login,1

    Args:
        path: Path to the CSV file.

    Returns:
        Validated DataFrame with 'url' and 'label' columns.

    Raises:
        FileNotFoundError: If the dataset file doesn't exist.
        ValueError: If required columns are missing.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Dataset not found at '{path}'. "
            "Run `python generate_dataset.py` first to create it."
        )

    logger.info(f"Loading dataset from: {path}")
    df = pd.read_csv(path)

    # Validate required columns
    required_cols = {"url", "label"}
    if not required_cols.issubset(df.columns):
        missing = required_cols - set(df.columns)
        raise ValueError(f"Dataset is missing columns: {missing}")

    # Drop rows with missing URLs
    initial_len = len(df)
    df = df.dropna(subset=["url"]).reset_index(drop=True)
    dropped = initial_len - len(df)
    if dropped > 0:
        logger.warning(f"Dropped {dropped} rows with missing URLs.")

    # Validate labels are binary
    unique_labels = set(df["label"].unique())
    if not unique_labels.issubset({0, 1}):
        raise ValueError(
            f"Labels must be binary (0 or 1). Found: {unique_labels}"
        )

    logger.info(f"Dataset loaded: {len(df):,} samples")
    logger.info("  Class distribution:")
    logger.info(f"    Legitimate (0): {(df['label'] == 0).sum():,}")
    logger.info(f"    Phishing   (1): {(df['label'] == 1).sum():,}")

    return df


def train_and_evaluate(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
) -> tuple:
    """
    Train a Random Forest classifier and compute evaluation metrics.

    Steps:
        1. Train the model with balanced class weights
        2. Perform 5-fold cross-validation
        3. Generate predictions on the test set
        4. Compute accuracy, classification report, confusion
           matrix, and ROC-AUC

    Args:
        X_train: Training feature matrix.
        X_test:  Test feature matrix.
        y_train: Training labels.
        y_test:  Test labels.

    Returns:
        Tuple of (trained_model, metrics_dict)
    """
    # ── Initialize and train the model ──
    logger.info("Training Random Forest classifier...")
    model = RandomForestClassifier(**RF_PARAMS)

    start_time = time.time()
    model.fit(X_train, y_train)
    training_time = time.time() - start_time
    logger.info(f"Training completed in {training_time:.1f}s")

    # ── Cross-validation ──
    logger.info(f"Running {CV_FOLDS}-fold cross-validation...")
    cv_scores = cross_val_score(
        model, X_train, y_train,
        cv=CV_FOLDS, scoring="accuracy", n_jobs=-1
    )
    logger.info(
        f"  CV Accuracy: {cv_scores.mean():.4f} "
        f"(± {cv_scores.std():.4f})"
    )

    # ── Test set evaluation ──
    y_pred = model.predict(X_test)
    proba = np.asarray(model.predict_proba(X_test))
    y_pred_proba = proba[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(
        y_test, y_pred,
        target_names=["Legitimate", "Phishing"],
    )
    cm = confusion_matrix(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    avg_precision = average_precision_score(y_test, y_pred_proba)

    # ── Print results ──
    print("\n" + "=" * 60)
    print("           MODEL EVALUATION RESULTS")
    print("=" * 60)
    print(f"\n  Test Accuracy:     {accuracy:.4f}  ({accuracy*100:.2f}%)")
    print(f"  ROC-AUC Score:     {roc_auc:.4f}")
    print(f"  Avg Precision:     {avg_precision:.4f}")
    print(f"  Training Time:     {training_time:.1f}s")
    print(f"\n  Cross-Validation ({CV_FOLDS}-fold):")
    print(f"    Mean Accuracy:   {cv_scores.mean():.4f}")
    print(f"    Std Deviation:   {cv_scores.std():.4f}")
    print("\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]:,}  FP={cm[0][1]:,}")
    print(f"    FN={cm[1][0]:,}  TP={cm[1][1]:,}")
    print("\n  Classification Report:")
    print(report)
    print("=" * 60)

    # ── Feature importance ──
    importances = model.feature_importances_
    importance_df = pd.DataFrame({
        "feature": FEATURE_NAMES,
        "importance": importances,
    }).sort_values("importance", ascending=False)

    print("\n  Top 10 Most Important Features:")
    print("  " + "-" * 40)
    for _, row in importance_df.head(10).iterrows():
        bar = "█" * int(row["importance"] * 50)
        print(f"  {row['feature']:.<30} {row['importance']:.4f} {bar}")
    print()

    # ── Compile metrics ──
    metrics = {
        "accuracy": float(accuracy),
        "roc_auc": float(roc_auc),
        "avg_precision": float(avg_precision),
        "cv_mean_accuracy": float(cv_scores.mean()),
        "cv_std_accuracy": float(cv_scores.std()),
        "training_time_seconds": float(training_time),
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        "feature_importances": importance_df.to_dict(orient="records"),
    }

    return model, metrics


# ──────────────────────────────────────────────────────────────
# Main pipeline
# ──────────────────────────────────────────────────────────────

def main():
    """Execute the full training pipeline."""
    logger.info("=" * 60)
    logger.info("  PHISHING URL DETECTION — TRAINING PIPELINE")
    logger.info("=" * 60)

    # ── Step 1: Load dataset ──
    df = load_dataset(DATASET_PATH)

    # ── Step 2: Extract features ──
    logger.info("Step 2: Extracting features...")
    X = extract_features_batch(pd.Series(df["url"]))
    y = np.asarray(df["label"].values)

    logger.info(f"  Feature matrix shape: {X.shape}")
    logger.info(f"  Features: {list(X.columns)}")

    # ── Step 3: Scale features ──
    logger.info("Step 3: Scaling features with StandardScaler...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Step 4: Train-test split ──
    logger.info(
        f"Step 4: Splitting data ({1-TEST_SIZE:.0%} train / "
        f"{TEST_SIZE:.0%} test)..."
    )
    X_train_split, X_test_split, y_train_split, y_test_split = train_test_split(
        X_scaled, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,  # Maintain class proportions
    )
    X_train = np.asarray(X_train_split)
    X_test = np.asarray(X_test_split)
    y_train = np.asarray(y_train_split)
    y_test = np.asarray(y_test_split)
    logger.info(f"  Train set: {X_train.shape[0]:,} samples")
    logger.info(f"  Test  set: {X_test.shape[0]:,} samples")

    # ── Step 5: Train and evaluate ──
    logger.info("Step 5: Training and evaluating model...")
    model, metrics = train_and_evaluate(X_train, X_test, y_train, y_test)

    # ── Step 6: Save artifacts ──
    logger.info("Step 6: Saving model artifacts...")
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save the trained model
    joblib.dump(model, MODEL_PATH)
    logger.info(f"  Model saved to: {MODEL_PATH}")

    # Save the fitted scaler
    joblib.dump(scaler, SCALER_PATH)
    logger.info(f"  Scaler saved to: {SCALER_PATH}")

    # Save the training report
    with open(REPORT_PATH, "w") as f:
        f.write("PHISHING URL DETECTION — TRAINING REPORT\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Dataset:        {DATASET_PATH}\n")
        f.write(f"Total samples:  {len(df):,}\n")
        f.write(f"Test split:     {TEST_SIZE:.0%}\n")
        f.write(f"CV Folds:       {CV_FOLDS}\n\n")
        f.write(f"Accuracy:       {metrics['accuracy']:.4f}\n")
        f.write(f"ROC-AUC:        {metrics['roc_auc']:.4f}\n")
        f.write(f"Avg Precision:  {metrics['avg_precision']:.4f}\n")
        f.write(f"CV Accuracy:    {metrics['cv_mean_accuracy']:.4f} "
                f"(± {metrics['cv_std_accuracy']:.4f})\n\n")
        f.write("Classification Report:\n")
        f.write(metrics["classification_report"])
    logger.info(f"  Report saved to: {REPORT_PATH}")

    # Save model metadata (for the API to load)
    metadata = {
        "model_version": "1.0.0",
        "trained_at": datetime.now().isoformat(),
        "dataset": DATASET_PATH,
        "num_samples": len(df),
        "num_features": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "algorithm": "Random Forest",
        "hyperparameters": {
            k: v for k, v in RF_PARAMS.items()
            if not callable(v)
        },
        "metrics": {
            "accuracy": metrics["accuracy"],
            "roc_auc": metrics["roc_auc"],
            "avg_precision": metrics["avg_precision"],
            "cv_mean_accuracy": metrics["cv_mean_accuracy"],
        },
    }
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"  Metadata saved to: {METADATA_PATH}")

    logger.info("=" * 60)
    logger.info("  TRAINING PIPELINE COMPLETE ✓")
    logger.info("=" * 60)

    return model, scaler, metrics


if __name__ == "__main__":
    main()
