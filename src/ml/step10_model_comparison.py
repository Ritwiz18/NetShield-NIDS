import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             classification_report, confusion_matrix, balanced_accuracy_score)
from sklearn.ensemble import ExtraTreesClassifier
import joblib
import matplotlib.pyplot as plt
from imblearn.over_sampling import SMOTE

# ==================================================
# STEP 10.1: LOAD AND PREPARE DATA
# ==================================================
DATASET_PATH = r"D:\\7th sem project\\data\\processed\\cleaned_dataset.csv"
df = pd.read_csv(DATASET_PATH)

# Separate features and target
X = df.drop(columns=['Label'])
y = df['Label']

# Encode target
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# Train/test split (same as previous steps)
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.20, random_state=42, stratify=y_encoded
)

# SMOTE mapping (only for minority classes with fewer samples than target)
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

# Determine sampling_strategy for SMOTE
sampling_strategy = {}
unique, counts = np.unique(y_train, return_counts=True)
for cls, cnt in zip(unique, counts):
    if cls in smote_target_counts:
        target = smote_target_counts[cls]
        if cnt < target:
            sampling_strategy[cls] = target
# Apply SMOTE only on training data
if sampling_strategy:
    smote = SMOTE(sampling_strategy=sampling_strategy, random_state=42)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
else:
    X_train_resampled, y_train_resampled = X_train, y_train

# Standard scaling (fit on resampled training data only)
scaler = StandardScaler()
X_train_resampled_scaled = scaler.fit_transform(X_train_resampled)
X_test_scaled = scaler.transform(X_test)

# ==================================================
# STEP 10.2: LOAD EXISTING RANDOM FOREST
# ==================================================
rf_model_path = r"D:\\7th sem project\\models\\random_forest_model.pkl"
if not os.path.exists(rf_model_path):
    raise FileNotFoundError(f"Random Forest model not found at {rf_model_path}")
random_forest = joblib.load(rf_model_path)
# Predict with RF
rf_pred = random_forest.predict(X_test_scaled)

# Evaluation helper
def evaluate_model(y_true, y_pred):
    return {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision_weighted': precision_score(y_true, y_pred, average='weighted', zero_division=0),
        'recall_weighted': recall_score(y_true, y_pred, average='weighted', zero_division=0),
        'f1_weighted': f1_score(y_true, y_pred, average='weighted', zero_division=0),
        'precision_macro': precision_score(y_true, y_pred, average='macro', zero_division=0),
        'recall_macro': recall_score(y_true, y_pred, average='macro', zero_division=0),
        'f1_macro': f1_score(y_true, y_pred, average='macro', zero_division=0),
        'balanced_accuracy': balanced_accuracy_score(y_true, y_pred)
    }

rf_metrics = evaluate_model(y_test, rf_pred)
rf_report = classification_report(y_test, rf_pred, zero_division=0)
rf_cm = confusion_matrix(y_test, rf_pred)

# ==================================================
# STEP 10.3: TRAIN EXTRA TREES
# ==================================================
print("Training Extra Trees. This may take some time...")
extra_trees = ExtraTreesClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced'
)
extra_trees.fit(X_train_resampled_scaled, y_train_resampled)
# Save Extra Trees model
extra_model_path = r"D:\7th sem project\extra_trees_model.pkl"
joblib.dump(extra_trees, extra_model_path)

# Predict with Extra Trees
et_pred = extra_trees.predict(X_test_scaled)

et_metrics = evaluate_model(y_test, et_pred)
et_report = classification_report(y_test, et_pred, zero_division=0)
et_cm = confusion_matrix(y_test, et_pred)

# ==================================================
# STEP 10.4: SAVE EXTRA TREES CONFUSION MATRIX
# ==================================================
plt.figure(figsize=(8,6))
plt.imshow(et_cm, interpolation='nearest', cmap=plt.cm.Blues)
plt.title('Extra Trees Confusion Matrix')
plt.colorbar()
class_names = label_encoder.classes_
plt.xticks(np.arange(len(class_names)), class_names, rotation=45, ha='right')
plt.yticks(np.arange(len(class_names)), class_names)
plt.ylabel('True label')
plt.xlabel('Predicted label')
plt.tight_layout()
conf_mat_path = r"D:\7th sem project\results\extra_trees_confusion_matrix.png"
plt.savefig(conf_mat_path)
plt.close()

# ==================================================
# STEP 10.5: MODEL COMPARISON TABLE
# ==================================================
comparison_df = pd.DataFrame({
    'Model': ['Random Forest', 'Extra Trees'],
    'Accuracy': [rf_metrics['accuracy'], et_metrics['accuracy']],
    'Precision Weighted': [rf_metrics['precision_weighted'], et_metrics['precision_weighted']],
    'Recall Weighted': [rf_metrics['recall_weighted'], et_metrics['recall_weighted']],
    'F1 Weighted': [rf_metrics['f1_weighted'], et_metrics['f1_weighted']],
    'Precision Macro': [rf_metrics['precision_macro'], et_metrics['precision_macro']],
    'Recall Macro': [rf_metrics['recall_macro'], et_metrics['recall_macro']],
    'F1 Macro': [rf_metrics['f1_macro'], et_metrics['f1_macro']],
    'Balanced Accuracy': [rf_metrics['balanced_accuracy'], et_metrics['balanced_accuracy']]
})

comparison_csv_path = r"D:\7th sem project\results\model_comparison.csv"
comparison_df.to_csv(comparison_csv_path, index=False)

# ==================================================
# STEP 10.6: VISUAL COMPARISON
# ==================================================
metrics_to_plot = ['F1 Weighted', 'F1 Macro', 'Balanced Accuracy']
fig, ax = plt.subplots(figsize=(8,5))
indices = np.arange(len(comparison_df))
bar_width = 0.2
for i, metric in enumerate(metrics_to_plot):
    ax.bar(indices + i*bar_width, comparison_df[metric], bar_width, label=metric)
ax.set_xlabel('Model')
ax.set_ylabel('Score')
ax.set_title('Model Comparison')
ax.set_xticks(indices + bar_width)
ax.set_xticklabels(comparison_df['Model'])
ax.legend()
plt.tight_layout()
visual_path = r"D:\7th sem project\results\model_comparison.png"
plt.savefig(visual_path)
plt.close()

# ==================================================
# STEP 10.8: FINAL VERIFICATION OUTPUT
# ==================================================
print(f"""========================================
STEP 10 COMPLETED
========================================
Random Forest evaluated: YES
Extra Trees trained: YES
Extra Trees evaluated: YES
Model comparison completed: YES

Random Forest:
F1 Weighted: {rf_metrics['f1_weighted']:.6f}
F1 Macro: {rf_metrics['f1_macro']:.6f}
Balanced Accuracy: {rf_metrics['balanced_accuracy']:.6f}

Extra Trees:
F1 Weighted: {et_metrics['f1_weighted']:.6f}
F1 Macro: {et_metrics['f1_macro']:.6f}
Balanced Accuracy: {et_metrics['balanced_accuracy']:.6f}

Best model based on weighted F1:
{'Extra Trees' if et_metrics['f1_weighted'] > rf_metrics['f1_weighted'] else 'Random Forest'}
Best model based on macro F1:
{'Extra Trees' if et_metrics['f1_macro'] > rf_metrics['f1_macro'] else 'Random Forest'}

Files saved:
results\model_comparison.csv
results\model_comparison.png
results\extra_trees_confusion_matrix.png
extra_trees_model.pkl
""")
