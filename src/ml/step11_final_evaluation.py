import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             classification_report, confusion_matrix, balanced_accuracy_score)
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
import joblib
import matplotlib.pyplot as plt
from imblearn.over_sampling import SMOTE

# ------------------------------------------------------------
# STEP 11: FINAL MODEL SELECTION & DETAILED EVALUATION
# ------------------------------------------------------------

# ==== 11.1 Load data and preprocessing configuration ====
DATASET_PATH = r"D:\\7th sem project\\cleaned_dataset.csv"
if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")

df = pd.read_csv(DATASET_PATH)
X = df.drop(columns=["Label"]).values
y = df["Label"].values

# Encode target with the same LabelEncoder
le = LabelEncoder()
y_encoded = le.fit_transform(y)

# Train/test split (identical to previous steps)
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.20, random_state=42, stratify=y_encoded
)

# SMOTE target counts (only on training data)
smote_target_counts = {
    1: 5000,
    2: 120000,
    3: 10000,
    4: 150000,
    5: 10000,
    6: 10000,
    7: 10000,
    10: 100000,
    11: 5000,
    12: 5000,
    14: 5000,
}

# Build sampling_strategy dict for SMOTE
sampling_strategy = {}
unique, counts = np.unique(y_train, return_counts=True)
for cls, cnt in zip(unique, counts):
    if cls in smote_target_counts:
        target = smote_target_counts[cls]
        if cnt < target:
            sampling_strategy[cls] = target

if sampling_strategy:
    smote = SMOTE(sampling_strategy=sampling_strategy, random_state=42)
    X_train_res, y_train_res = smote.fit_resample(X_train, y_train)
else:
    X_train_res, y_train_res = X_train, y_train

# Standard scaling – fit on resampled training data only
scaler = StandardScaler()
X_train_res_scaled = scaler.fit_transform(X_train_res)
X_test_scaled = scaler.transform(X_test)

# Verify test set shape
print("X_test.shape:", X_test_scaled.shape)
print("y_test.shape:", y_test.shape)

# ==== 11.1 Load existing models ====
rf_path = r"D:\\7th sem project\\random_forest_model.pkl"
et_path = r"D:\\7th sem project\\extra_trees_model.pkl"
if not os.path.exists(rf_path):
    raise FileNotFoundError(f"Random Forest model not found at {rf_path}")
if not os.path.exists(et_path):
    raise FileNotFoundError(f"Extra Trees model not found at {et_path}")

random_forest = joblib.load(rf_path)
extra_trees = joblib.load(et_path)

# ==== 11.2 Generate predictions ====
rf_predictions = random_forest.predict(X_test_scaled)
et_predictions = extra_trees.predict(X_test_scaled)

print("\n========================================")
print("PREDICTION VALIDATION")
print("========================================")
print(f"Random Forest predictions: {len(rf_predictions)}")
print(f"Extra Trees predictions: {len(et_predictions)}")

# ==== 11.3 Detailed classification reports (per class) ====
rf_report_dict = classification_report(y_test, rf_predictions, output_dict=True, zero_division=0)
et_report_dict = classification_report(y_test, et_predictions, output_dict=True, zero_division=0)

# Convert to DataFrames for easier handling
rf_report_df = pd.DataFrame(rf_report_dict).transpose()
et_report_df = pd.DataFrame(et_report_dict).transpose()

# Print full reports (excluding accuracy/avg rows for brevity)
print("\n--- Random Forest Classification Report (per class) ---")
print(rf_report_df.loc[[str(i) for i in range(15)]].to_string())
print("\n--- Extra Trees Classification Report (per class) ---")
print(et_report_df.loc[[str(i) for i in range(15)]].to_string())

# ==== 11.4 Overall metrics comparison ====

def overall_metrics(y_true, y_pred):
    return {
        "Accuracy": accuracy_score(y_true, y_pred),
        "Precision Weighted": precision_score(y_true, y_pred, average='weighted', zero_division=0),
        "Recall Weighted": recall_score(y_true, y_pred, average='weighted', zero_division=0),
        "F1 Weighted": f1_score(y_true, y_pred, average='weighted', zero_division=0),
        "Precision Macro": precision_score(y_true, y_pred, average='macro', zero_division=0),
        "Recall Macro": recall_score(y_true, y_pred, average='macro', zero_division=0),
        "F1 Macro": f1_score(y_true, y_pred, average='macro', zero_division=0),
        "Balanced Accuracy": balanced_accuracy_score(y_true, y_pred)
    }

rf_overall = overall_metrics(y_test, rf_predictions)
et_overall = overall_metrics(y_test, et_predictions)

comparison_df = pd.DataFrame({
    "Model": ["Random Forest", "Extra Trees"],
    "Accuracy": [rf_overall["Accuracy"], et_overall["Accuracy"]],
    "Precision Weighted": [rf_overall["Precision Weighted"], et_overall["Precision Weighted"]],
    "Recall Weighted": [rf_overall["Recall Weighted"], et_overall["Recall Weighted"]],
    "F1 Weighted": [rf_overall["F1 Weighted"], et_overall["F1 Weighted"]],
    "Precision Macro": [rf_overall["Precision Macro"], et_overall["Precision Macro"]],
    "Recall Macro": [rf_overall["Recall Macro"], et_overall["Recall Macro"]],
    "F1 Macro": [rf_overall["F1 Macro"], et_overall["F1 Macro"]],
    "Balanced Accuracy": [rf_overall["Balanced Accuracy"], et_overall["Balanced Accuracy"]]
})

print("\n=== Overall Metrics Comparison ===")
print(comparison_df.to_string(index=False))

# Save overall comparison CSV
results_dir = r"D:\\7th sem project\\results"
os.makedirs(results_dir, exist_ok=True)
final_cmp_path = os.path.join(results_dir, "final_model_comparison.csv")
comparison_df.to_csv(final_cmp_path, index=False)

# ==== 11.5 Confusion matrices (matplotlib) ====
rf_cm = confusion_matrix(y_test, rf_predictions)
et_cm = confusion_matrix(y_test, et_predictions)
class_names = le.classes_.astype(str)

def plot_confusion(cm, title, path):
    plt.figure(figsize=(9, 7))
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(class_names))
    plt.xticks(tick_marks, class_names, rotation=45, ha='right')
    plt.yticks(tick_marks, class_names)
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.tight_layout()
    plt.savefig(path, dpi=300)
    plt.close()

rf_cm_path = os.path.join(results_dir, "random_forest_final_confusion_matrix.png")
et_cm_path = os.path.join(results_dir, "extra_trees_final_confusion_matrix.png")
plot_confusion(rf_cm, "Random Forest Confusion Matrix", rf_cm_path)
plot_confusion(et_cm, "Extra Trees Confusion Matrix", et_cm_path)

# ==== 11.6 Per‑class performance CSV ====
per_class_rows = []
for cls in range(15):
    cls_str = str(cls)
    row = {
        "Class": class_names[cls],
        "RF Precision": rf_report_df.at[cls_str, "precision"],
        "RF Recall": rf_report_df.at[cls_str, "recall"],
        "RF F1": rf_report_df.at[cls_str, "f1-score"],
        "RF Support": int(rf_report_df.at[cls_str, "support"]),
        "ET Precision": et_report_df.at[cls_str, "precision"],
        "ET Recall": et_report_df.at[cls_str, "recall"],
        "ET F1": et_report_df.at[cls_str, "f1-score"],
        "ET Support": int(et_report_df.at[cls_str, "support"])
    }
    per_class_rows.append(row)

per_class_df = pd.DataFrame(per_class_rows)
per_class_path = os.path.join(results_dir, "per_class_model_comparison.csv")
per_class_df.to_csv(per_class_path, index=False)

# ==== 11.7 Identify weak classes (F1 < 0.5) ====
weak_rows = []
for _, r in per_class_df.iterrows():
    if r["RF F1"] < 0.5 or r["ET F1"] < 0.5:
        weak_rows.append(r)

print("\n========================================")
print("WEAK CLASS DETECTION")
print("========================================")
if weak_rows:
    for w in weak_rows:
        print(f"Class: {w['Class']}")
        print(f"  Random Forest F1: {w['RF F1']:.4f}")
        print(f"  Extra Trees   F1: {w['ET F1']:.4f}")
        print(f"  Support: {w['RF Support']} (same for both)\n")
else:
    print("No weak classes detected (F1 >= 0.5 for both models).")

# ==== 11.8 Model selection based on priority ====
# Priority: macro F1, then balanced accuracy, then weighted F1
if (et_overall["F1 Macro"] > rf_overall["F1 Macro"]):
    selected = "Extra Trees"
elif (et_overall["F1 Macro"] < rf_overall["F1 Macro"]):
    selected = "Random Forest"
else:  # macro equal, compare balanced accuracy
    if et_overall["Balanced Accuracy"] > rf_overall["Balanced Accuracy"]:
        selected = "Extra Trees"
    elif et_overall["Balanced Accuracy"] < rf_overall["Balanced Accuracy"]:
        selected = "Random Forest"
    else:  # balanced equal, compare weighted F1
        selected = "Extra Trees" if et_overall["F1 Weighted"] > rf_overall["F1 Weighted"] else "Random Forest"

# Save selected model name
final_model_txt_path = os.path.join(results_dir, "final_model.txt")
with open(final_model_txt_path, "w") as f:
    f.write(selected)

# ==== 11.10 Verify files ====
files_to_check = {
    "final_model_comparison.csv": final_cmp_path,
    "per_class_model_comparison.csv": per_class_path,
    "random_forest_final_confusion_matrix.png": rf_cm_path,
    "extra_trees_final_confusion_matrix.png": et_cm_path,
    "final_model.txt": final_model_txt_path
}

def exists(path):
    return os.path.exists(path)

print("\n========================================")
print("STEP 11 COMPLETED")
print("========================================")
print(f"Final model: {selected}")
print("Final metrics (selected model):")
selected_metrics = et_overall if selected == "Extra Trees" else rf_overall
print(f"  Accuracy: {selected_metrics['Accuracy']:.6f}")
print(f"  Weighted F1: {selected_metrics['F1 Weighted']:.6f}")
print(f"  Macro F1: {selected_metrics['F1 Macro']:.6f}")
print(f"  Balanced Accuracy: {selected_metrics['Balanced Accuracy']:.6f}")

print("\nFiles verified:")
for name, path in files_to_check.items():
    print(f"{name}: {'YES' if exists(path) else 'NO'}")
