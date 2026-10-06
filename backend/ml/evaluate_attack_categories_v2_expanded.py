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

df["prediction"] = predictions

categories = [
    ("Normal", 0, 37),
    ("Deauth", 38, 39),
    ("Disassociation", 40, 41),
    ("Reassociation", 42, 45),
    ("Rogue AP", 46, 49),
    ("Evil Twin", 50, 53),
]

print("=" * 70)
print("NetShield AWID3 Model v2 - Expanded Per-Category Evaluation")
print("=" * 70)

for category, start, end in categories:
    subset = df.iloc[start:end + 1]

    correct = (subset["label"] == subset["prediction"]).sum()
    total = len(subset)
    accuracy = correct / total if total else 0.0

    print(f"\n{category}")
    print("-" * 30)
    print(f"Rows:     {start}-{end}")
    print(f"Windows:  {total}")
    print(f"Correct:  {correct}")
    print(f"Wrong:    {total - correct}")
    print(f"Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")

    print("Predictions:")
    for idx, row in subset.iterrows():
        actual = "Attack" if row["label"] == 1 else "Normal"
        predicted = "Attack" if row["prediction"] == 1 else "Normal"
        status = "CORRECT" if actual == predicted else "WRONG"
        print(f"  Row {idx}: Actual={actual}, Predicted={predicted} -> {status}")

print("\n" + "=" * 70)
