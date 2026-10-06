"""
Train Random Forest Model v2 on the expanded AWID3 training dataset.

Training:
    NetShield_AWID3_ML_expanded/train.csv

Evaluation:
    NetShield_AWID3_ML_v2/validation.csv
    NetShield_AWID3_ML_v2/test.csv

The original validation and test sets are intentionally kept unchanged
for a fair comparison with the original Model v2.
"""

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from backend.ml.ml_feature_schema import ML_FEATURE_NAMES, ML_FEATURE_COUNT


# ---------------------------------------------------------------------------
# Dataset paths
# ---------------------------------------------------------------------------

EXPANDED_DATASET_DIR = Path("backend/ml/data/awid3_expanded")

ORIGINAL_DATASET_DIR = Path("backend/ml/data/awid3_expanded")
TRAIN_PATH = EXPANDED_DATASET_DIR / "train.csv"
VALIDATION_PATH = ORIGINAL_DATASET_DIR / "validation.csv"
TEST_PATH = ORIGINAL_DATASET_DIR / "test.csv"

MODEL_PATH = Path("backend/ml/models/random_forest_awid3_v2_expanded.joblib")


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def load_dataset(path: Path):
    df = pd.read_csv(path)

    expected_columns = ML_FEATURE_NAMES + ["label"]

    if list(df.columns) != expected_columns:
        raise ValueError(
            f"Unexpected columns in {path}.\n"
            f"Expected {len(expected_columns)} columns:\n"
            f"{expected_columns}\n\n"
            f"Found {len(df.columns)} columns:\n"
            f"{list(df.columns)}"
        )

    X = df[ML_FEATURE_NAMES]
    y = df["label"]

    if X.shape[1] != ML_FEATURE_COUNT:
        raise ValueError(
            f"Expected {ML_FEATURE_COUNT} ML features, "
            f"but found {X.shape[1]}."
        )

    return X, y


# ---------------------------------------------------------------------------
# Main training
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("NetShield AWID3 Model v2 - Expanded Training Experiment")
    print("=" * 70)

    print("\nLoading datasets...")

    X_train, y_train = load_dataset(TRAIN_PATH)
    X_validation, y_validation = load_dataset(VALIDATION_PATH)
    X_test, y_test = load_dataset(TEST_PATH)

    print(f"\nTraining dataset:")
    print(f"  Rows: {len(X_train)}")
    print(f"  Features: {X_train.shape[1]}")
    print(f"  Labels: {y_train.value_counts().sort_index().to_dict()}")

    print(f"\nOriginal validation dataset:")
    print(f"  Rows: {len(X_validation)}")
    print(f"  Features: {X_validation.shape[1]}")
    print(
        f"  Labels: "
        f"{y_validation.value_counts().sort_index().to_dict()}"
    )

    print(f"\nOriginal test dataset:")
    print(f"  Rows: {len(X_test)}")
    print(f"  Features: {X_test.shape[1]}")
    print(f"  Labels: {y_test.value_counts().sort_index().to_dict()}")

    # -----------------------------------------------------------------------
    # Random Forest configuration
    # -----------------------------------------------------------------------

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    print("\nTraining Random Forest...")
    model.fit(X_train, y_train)

    print("Training complete.")

    # -----------------------------------------------------------------------
    # Validation
    # -----------------------------------------------------------------------

    print("\n" + "=" * 70)
    print("VALIDATION RESULTS")
    print("=" * 70)

    validation_predictions = model.predict(X_validation)

    validation_accuracy = accuracy_score(
        y_validation,
        validation_predictions,
    )

    print(f"\nValidation accuracy: {validation_accuracy:.4f}")

    print("\nValidation confusion matrix:")
    print(confusion_matrix(y_validation, validation_predictions))

    print("\nValidation classification report:")
    print(
        classification_report(
            y_validation,
            validation_predictions,
            target_names=["Normal", "Attack"],
            digits=4,
            zero_division=0,
        )
    )

    # -----------------------------------------------------------------------
    # Test
    # -----------------------------------------------------------------------

    print("\n" + "=" * 70)
    print("TEST RESULTS")
    print("=" * 70)

    test_predictions = model.predict(X_test)

    test_accuracy = accuracy_score(
        y_test,
        test_predictions,
    )

    print(f"\nTest accuracy: {test_accuracy:.4f}")

    print("\nTest confusion matrix:")
    print(confusion_matrix(y_test, test_predictions))

    print("\nTest classification report:")
    print(
        classification_report(
            y_test,
            test_predictions,
            target_names=["Normal", "Attack"],
            digits=4,
            zero_division=0,
        )
    )

    # -----------------------------------------------------------------------
    # Feature importance
    # -----------------------------------------------------------------------

    print("\n" + "=" * 70)
    print("FEATURE IMPORTANCE")
    print("=" * 70)

    feature_importance = pd.Series(
        model.feature_importances_,
        index=ML_FEATURE_NAMES,
    ).sort_values(ascending=False)

    for feature, importance in feature_importance.items():
        print(f"{feature:30s} {importance:.4f}")

    # -----------------------------------------------------------------------
    # Save model
    # -----------------------------------------------------------------------

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    print("\n" + "=" * 70)
    print("MODEL SAVED")
    print("=" * 70)
    print(f"\nSaved to:")
    print(MODEL_PATH)

    print("\nExperiment summary:")
    print(f"  Training rows:    {len(X_train)}")
    print(f"  Validation rows:  {len(X_validation)}")
    print(f"  Test rows:        {len(X_test)}")
    print(f"  ML features:      {ML_FEATURE_COUNT}")
    print(f"  Validation acc:   {validation_accuracy:.4f}")
    print(f"  Test acc:         {test_accuracy:.4f}")


if __name__ == "__main__":
    main()
