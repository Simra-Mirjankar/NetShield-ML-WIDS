from pathlib import Path
import pandas as pd
import joblib

from backend.ml.ml_feature_schema import ML_FEATURE_NAMES

MODEL_PATH = Path("backend/ml/models/random_forest_awid3_v2_expanded.joblib")
TEST_PATH = Path("backend/ml/data/awid3_expanded/test.csv")

df = pd.read_csv(TEST_PATH)

X = df[ML_FEATURE_NAMES]
y = df["label"].astype(int)

model = joblib.load(MODEL_PATH)
predictions = model.predict(X)
probabilities = model.predict_proba(X)

df["prediction"] = predictions
df["correct"] = df["label"] == df["prediction"]

misclassified = df[~df["correct"]]

print("=" * 70)
print("NetShield AWID3 Model v2 - Expanded Misclassification Analysis")
print("=" * 70)

print(f"\nTest rows: {len(df)}")
print(f"Correct: {df['correct'].sum()}")
print(f"Misclassified: {len(misclassified)}")

print("\nConfusion matrix:")
print(pd.crosstab(
    df["label"],
    df["prediction"],
    rownames=["Actual"],
    colnames=["Predicted"],
    dropna=False
))

print("\n" + "=" * 70)
print("MISCLASSIFIED WINDOWS")
print("=" * 70)

if misclassified.empty:
    print("\nNo misclassified windows.")
else:
    for idx, row in misclassified.iterrows():
        print(f"\nTest row: {idx}")
        print(f"  Actual label:    {int(row['label'])}")
        print(f"  Predicted label: {int(row['prediction'])}")
        print(f"  Normal probability: {probabilities[idx][0]:.4f}")
        print(f"  Attack probability: {probabilities[idx][1]:.4f}")

        for feature in ML_FEATURE_NAMES:
            print(f"  {feature}: {row[feature]}")

print("\n" + "=" * 70)
