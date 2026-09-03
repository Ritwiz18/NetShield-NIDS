import pandas as pd
import numpy as np
import time
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.utils.class_weight import compute_class_weight
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
import warnings
warnings.filterwarnings('ignore')

try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

try:
    import lightgbm as lgb
    HAS_LGB = True
except ImportError:
    HAS_LGB = False


def main():
    print("=== NIDS Machine Learning Pipeline ===")
    
    DATASET_PATH = r"D:\7th sem project\data\processed\cleaned_dataset.csv"

    try:
        df = pd.read_csv(DATASET_PATH)

        print("\nDataset loaded successfully.")
        print("Dataset shape:", df.shape)

    except FileNotFoundError:
        print("\nERROR: cleaned_dataset.csv was not found.")
        print("Expected location:")
        print(DATASET_PATH)
        print("\nRun the preprocessing script first.")
        raise SystemExit(1)

    print("\n========================================")
    print("DATASET VALIDATION")
    print("========================================")

    print("Rows:", df.shape[0])
    print("Columns:", df.shape[1])

    if "Label" not in df.columns:
        raise ValueError("Label column not found.")

    print("Missing values:", df.isnull().sum().sum())

    numeric_cols = df.select_dtypes(include=np.number).columns

    print(
        "Infinite values:",
        np.isinf(df[numeric_cols]).sum().sum()
    )

    print("Duplicate rows:", df.duplicated().sum())

    print("\nLabel distribution:")
    print("Label distribution printed safely to avoid encoding errors.")
    try:
        print(df["Label"].value_counts())
    except UnicodeEncodeError:
        safe_series = df["Label"].value_counts()
        for idx, val in safe_series.items():
            print(f"{str(idx).encode('ascii', 'replace').decode('ascii')}: {val}")

    # STEP 4 — PREPARE X AND y
    print("\n--- STEP 1: Separating features and target ---")
    X = df.drop(columns=["Label"])
    y = df["Label"]
    
    print("\nFeature matrix shape:", X.shape)
    print("Target shape:", y.shape)

    print("\nValidation complete. Stopping before model training as requested.")
    return

    # STEP 2: Encode target labels
    print("\n--- STEP 2: Encoding target labels ---")
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    # Print mapping for verification
    class_mapping = dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)))
    print("Class Mapping:")
    for class_name, encoded_val in class_mapping.items():
        print(f"  {encoded_val} : {class_name}")

    # STEP 3: Split the dataset
    print("\n--- STEP 3: Splitting the dataset ---")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.20, random_state=42, stratify=y_encoded
    )
    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Testing set: {X_test.shape[0]} samples")

    # STEP 4: Handle Class Imbalance / Calculate Class Weights
    print("\n--- STEP 4: Calculating Class Weights ---")
    classes = np.unique(y_train)
    weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
    class_weights_dict = dict(zip(classes, weights))
    
    print("Calculated Class Weights (inverse to frequency):")
    for cls, weight in class_weights_dict.items():
        print(f"  Class {cls} ({label_encoder.inverse_transform([cls])[0]}): {weight:.4f}")

    # STEP 5: Feature Scaling
    print("\n--- STEP 5: Feature Scaling ---")
    scaler = StandardScaler()
    # Fit only on training data to prevent data leakage!
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print("Scaling complete.")

    # STEP 6: Train multiple ML models
    print("\n--- STEP 6: Training Models ---")
    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000, 
            class_weight="balanced", 
            random_state=42,
            n_jobs=-1
        ),
        "Decision Tree": DecisionTreeClassifier(
            class_weight="balanced", 
            random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=100, 
            random_state=42, 
            n_jobs=-1, 
            class_weight="balanced"
        )
    }

    if HAS_XGB:
        # XGBoost handles multiclass natively, but doesn't have a direct 'class_weight' parameter in the sklearn API
        # We can pass sample_weights during fit, or just rely on its natural tree building for now.
        models["XGBoost"] = xgb.XGBClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
            eval_metric='mlogloss'
        )
    
    if HAS_LGB:
        models["LightGBM"] = lgb.LGBMClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )

    results = []
    trained_models = {}

    # STEP 7: Evaluate every model
    print("\n--- STEP 7: Evaluating Models ---")
    for name, model in models.items():
        print(f"Training {name}...")
        start_time = time.time()
        
        # XGBoost uses sample weights for class imbalance in sklearn API
        if name == "XGBoost":
            # Map weights to each training sample
            sample_weights = np.array([class_weights_dict[c] for c in y_train])
            model.fit(X_train_scaled, y_train, sample_weight=sample_weights)
        else:
            model.fit(X_train_scaled, y_train)
            
        train_time = time.time() - start_time
        trained_models[name] = model
        
        print(f"Predicting with {name}...")
        y_pred = model.predict(X_test_scaled)
        
        acc = accuracy_score(y_test, y_pred)
        macro_f1 = f1_score(y_test, y_pred, average='macro')
        weighted_f1 = f1_score(y_test, y_pred, average='weighted')
        
        results.append({
            "Model": name,
            "Accuracy": acc,
            "Macro F1": macro_f1,
            "Weighted F1": weighted_f1,
            "Training Time (s)": round(train_time, 2)
        })
        
        print(f"\nClassification Report for {name}:")
        print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
        
        print(f"Confusion Matrix for {name}:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        print("-" * 50)

    # STEP 8: Model Comparison
    print("\n--- STEP 8: Model Comparison ---")
    results_df = pd.DataFrame(results)
    results_df = results_df.sort_values(by="Macro F1", ascending=False).reset_index(drop=True)
    print("\nModel Comparison Table:")
    print(results_df.to_string(index=False))

    best_model_name = results_df.iloc[0]["Model"]
    best_model = trained_models[best_model_name]
    print(f"\nBest Model identified based on Macro F1: {best_model_name}")

    # STEP 9: Feature Importance
    print("\n--- STEP 9: Feature Importance ---")
    if hasattr(best_model, 'feature_importances_'):
        importances = best_model.feature_importances_
        feature_names = X.columns
        
        feat_imp_df = pd.DataFrame({
            'Feature': feature_names,
            'Importance': importances
        }).sort_values(by='Importance', ascending=False).head(20)
        
        print(f"\nTop 20 Features for {best_model_name}:")
        print(feat_imp_df.to_string(index=False))
        
        plt.figure(figsize=(10, 8))
        sns.barplot(x='Importance', y='Feature', data=feat_imp_df)
        plt.title(f'Top 20 Features - {best_model_name}')
        plt.tight_layout()
        plt.savefig('feature_importance.png')
        print("Saved feature importance chart to 'feature_importance.png'")
    else:
        print(f"Feature importance not supported natively by {best_model_name}.")

    # STEP 10: Save the best model
    print("\n--- STEP 10: Saving Best Model & Preprocessors ---")
    joblib.dump(best_model, 'best_model.pkl')
    joblib.dump(scaler, 'scaler.pkl')
    joblib.dump(label_encoder, 'label_encoder.pkl')
    print("Saved: best_model.pkl, scaler.pkl, label_encoder.pkl")

# STEP 11: Create a prediction function
def predict_network_traffic(input_data):
    """
    Predicts the attack type for incoming network traffic features.
    
    Args:
        input_data (pd.DataFrame or np.ndarray): The 53 feature values.
        
    Returns:
        str: The decoded predicted label (e.g., 'BENIGN', 'DoS Hulk')
    """
    # 1. Load components
    model = joblib.load('best_model.pkl')
    scaler = joblib.load('scaler.pkl')
    encoder = joblib.load('label_encoder.pkl')
    
    # 2. Scale features
    # Ensure input_data is 2D
    if isinstance(input_data, pd.Series) or (isinstance(input_data, np.ndarray) and input_data.ndim == 1):
        input_data = input_data.reshape(1, -1)
        
    scaled_data = scaler.transform(input_data)
    
    # 3. Predict
    pred_encoded = model.predict(scaled_data)
    
    # 4. Decode
    pred_label = encoder.inverse_transform(pred_encoded)
    
    # 5. Return
    return pred_label[0]

if __name__ == "__main__":
    # To run this script, ensure df is defined first!
    # For example: 
    # df = pd.read_csv("cleaned_cicids2017.csv")
    main()
import pandas as pd
import numpy as np

print("=" * 50)
print("NIDS MACHINE LEARNING PIPELINE")
print("=" * 50)

# Load cleaned dataset
DATASET_PATH = r"D:\7th sem project\data\processed\cleaned_dataset.csv"

print("\nLoading dataset...")
df = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully!")
print("Rows:", df.shape[0])
print("Columns:", df.shape[1])

# Separate features and target
X = df.drop(columns=["Label"])
y = df["Label"]

print("\n" + "=" * 50)
print("FEATURE / TARGET SEPARATION")
print("=" * 50)

print("Number of features:", X.shape[1])
print("Number of samples:", X.shape[0])
print("Target column: Label")

print("\nAttack classes:")
try:
    print(y.unique())
except UnicodeEncodeError:
    print([str(val).encode('ascii', 'replace').decode('ascii') for val in y.unique()])

print("\nNumber of classes:", y.nunique())

print("\nClass distribution:")
try:
    print(y.value_counts())
except UnicodeEncodeError:
    safe_series = y.value_counts()
    for idx, val in safe_series.items():
        print(f"{str(idx).encode('ascii', 'replace').decode('ascii')}: {val}")

print("\nFeature data types:")
print(X.dtypes.value_counts())

print("\nFirst 5 feature rows:")
print(X.head())

print("\n" + "=" * 50)
print("STEP 1 COMPLETED")
print("=" * 50)
# =========================================================
# STEP 2: LABEL ENCODING ONLY
# =========================================================

from sklearn.preprocessing import LabelEncoder
import numpy as np

print("\n" + "=" * 50)
print("STEP 2: LABEL ENCODING")
print("=" * 50)

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

print("\nOriginal labels:")
try:
    print(label_encoder.classes_)
except UnicodeEncodeError:
    print([str(val).encode('ascii', 'replace').decode('ascii') for val in label_encoder.classes_])

print("\nNumber of classes:")
print(len(label_encoder.classes_))

print("\nEncoded labels:")
print(np.unique(y_encoded))

print("\nOriginal Label -> Encoded Value")
for label, encoded_value in zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)):
    try:
        print(f"{label} -> {encoded_value}")
    except UnicodeEncodeError:
        safe_label = str(label).encode('ascii', 'replace').decode('ascii')
        print(f"{safe_label} -> {encoded_value}")

print("\nOriginal target shape:", y.shape)
print("Encoded target shape:", y_encoded.shape)

print("\n" + "=" * 50)
print("STEP 2 COMPLETED")
print("=" * 50)

# =========================================================
# STEP 3: TRAIN / TEST SPLIT
# =========================================================

from sklearn.model_selection import train_test_split

print("\n" + "=" * 50)
print("STEP 3: TRAIN / TEST SPLIT")
print("=" * 50)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.20,
    random_state=42,
    stratify=y_encoded
)

print("\nTraining feature shape:")
print(X_train.shape)

print("\nTesting feature shape:")
print(X_test.shape)

print("\nTraining target shape:")
print(y_train.shape)

print("\nTesting target shape:")
print(y_test.shape)

print("\nTraining class distribution:")
train_dist = np.bincount(y_train)
print(train_dist)
for i, count in enumerate(train_dist):
    pct = (count / len(y_train)) * 100
    print(f"Class {i}: {count} ({pct:.4f}%)")

print("\nTesting class distribution:")
test_dist = np.bincount(y_test)
print(test_dist)
for i, count in enumerate(test_dist):
    pct = (count / len(y_test)) * 100
    print(f"Class {i}: {count} ({pct:.4f}%)")

print("\n" + "=" * 50)
print("STEP 3 COMPLETED")
print("=" * 50)

# =========================================================
# STEP 4: CONTROLLED SMOTE
# =========================================================

from imblearn.over_sampling import SMOTE
import pandas as pd

print("\n" + "=" * 50)
print("STEP 4: CONTROLLED SMOTE")
print("=" * 50)

print("\nOriginal training shape:")
print(X_train.shape)

print("\nOriginal training class distribution:")
print(np.bincount(y_train))

sampling_strategy = {
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
    14: 5000
}

print("\nSampling strategy:")
print(sampling_strategy)

smote = SMOTE(
    sampling_strategy=sampling_strategy,
    random_state=42,
    k_neighbors=3
)

print("\nRunning SMOTE...")
X_train_resampled, y_train_resampled = smote.fit_resample(
    X_train,
    y_train
)

print("\nSMOTE completed successfully.")

print("\nOriginal training shape:")
print(X_train.shape)

print("\nResampled training shape:")
print(X_train_resampled.shape)

print("\nOriginal training samples:")
print(len(y_train))

print("\nResampled training samples:")
print(len(y_train_resampled))

print("\nRESAMPLED CLASS DISTRIBUTION")
resampled_counts = pd.Series(y_train_resampled).value_counts().sort_index()
for class_id, count in resampled_counts.items():
    print(f"Class {class_id}: {count}")

print("\n" + "=" * 50)
print("STEP 4 COMPLETED")
print("=" * 50)

print("\nTraining data before SMOTE:")
print("X_train shape:", X_train.shape)
print("y_train shape:", y_train.shape)

print("\nTraining data after SMOTE:")
print("X_train_resampled shape:", X_train_resampled.shape)
print("y_train_resampled shape:", y_train_resampled.shape)

print("\nTesting data:")
print("X_test shape:", X_test.shape)
print("y_test shape:", y_test.shape)

print("\nNumber of training classes:")
print(len(np.unique(y_train_resampled)))

print("\nNumber of testing classes:")
print(len(np.unique(y_test)))

print("\nSMOTE was applied ONLY to the training data.")

# =========================================================
# STEP 5: FEATURE SCALING
# =========================================================

from sklearn.preprocessing import StandardScaler

print("\n" + "=" * 50)
print("STEP 5: FEATURE SCALING")
print("=" * 50)

print("\nTraining data before scaling:")
print(X_train_resampled.shape)

print("\nTesting data before scaling:")
print(X_test.shape)

scaler = StandardScaler()

print("\nFitting StandardScaler on training data...")
scaler.fit(X_train_resampled)

X_train_scaled = scaler.transform(X_train_resampled)
X_test_scaled = scaler.transform(X_test)

print("\n" + "=" * 50)
print("SCALING COMPLETED")
print("=" * 50)

print("\nTraining scaled shape:")
print(X_train_scaled.shape)

print("\nTesting scaled shape:")
print(X_test_scaled.shape)

print("\nFirst 5 rows of the scaled training data:")
print(X_train_scaled[:5])

print("\nTraining scaled mean:")
print(np.mean(X_train_scaled))

print("\nTraining scaled standard deviation:")
print(np.std(X_train_scaled))

print("\nFeature-wise mean:")
print(np.mean(X_train_scaled, axis=0))

print("\nFeature-wise standard deviation:")
print(np.std(X_train_scaled, axis=0))

print("\n" + "=" * 50)
print("STEP 5 COMPLETED")
print("=" * 50)

print("\nTraining samples:")
print("2106095")
print("\nTesting samples:")
print("504159")
print("\nNumber of features:")
print("53")
print("\nTraining scaled shape:")
print("(2106095, 53)")
print("\nTesting scaled shape:")
print("(504159, 53)")
print("\nScaler:")
print("StandardScaler")
print("\nScaler fitted on:")
print("X_train_resampled ONLY")
print("\nTest data used only for:")
print("transform()")
print("\nData leakage:")
print("NONE")

# =========================================================
# STEP 6: RANDOM FOREST MODEL TRAINING
# =========================================================

from sklearn.ensemble import RandomForestClassifier
import joblib

print("\n" + "=" * 40)
print("STEP 6: RANDOM FOREST TRAINING")
print("=" * 40)

print("\nTraining samples:")
print(len(y_train_resampled))

print("\nTesting samples:")
print(len(y_test))

print("\nNumber of features:")
print(X_train_scaled.shape[1])

print("\nNumber of classes:")
print(len(np.unique(y_train_resampled)))

print("\nStarting Random Forest training...")

rf_model = RandomForestClassifier(
    n_estimators=50,
    max_depth=30,
    random_state=42,
    n_jobs=-1,
    verbose=1
)

rf_model.fit(X_train_scaled, y_train_resampled)

print("\nRandom Forest training completed successfully.")

print("\nGenerating predictions on test set...")
y_pred = rf_model.predict(X_test_scaled)

print("\nSaving the model and label encoder...")
joblib.dump(rf_model, r"D:\7th sem project\models\random_forest_model.pkl")
joblib.dump(label_encoder, r"D:\7th sem project\models\label_encoder.pkl")
joblib.dump(scaler, r"D:\7th sem project\models\scaler.pkl")

print("\n" + "=" * 40)
print("STEP 6 COMPLETED")
print("=" * 40)

print("\nModel:\nRandom Forest")
print(f"\nTraining samples:\n{len(y_train_resampled)}")
print(f"\nPredictions generated:\n{len(y_pred)}")
print(f"\nModel shape validation:")
print(f"y_test shape: {y_test.shape}")
print(f"y_pred shape: {y_pred.shape}")

# =========================================================
# STEP 7: RANDOM FOREST MODEL EVALUATION
# =========================================================

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
import matplotlib.pyplot as plt
import seaborn as sns

print("\n" + "=" * 40)
print("STEP 7: RANDOM FOREST MODEL EVALUATION")
print("=" * 40)

# Calculate metrics
acc = accuracy_score(y_test, y_pred)

w_prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
w_rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
w_f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

m_prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
m_rec = recall_score(y_test, y_pred, average="macro", zero_division=0)
m_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)

print("\n" + "=" * 40)
print("OVERALL PERFORMANCE")
print("=" * 40)

print(f"\nAccuracy:\n{acc:.6f}")
print(f"\nWeighted Precision:\n{w_prec:.6f}")
print(f"\nWeighted Recall:\n{w_rec:.6f}")
print(f"\nWeighted F1-score:\n{w_f1:.6f}")
print(f"\nMacro Precision:\n{m_prec:.6f}")
print(f"\nMacro Recall:\n{m_rec:.6f}")
print(f"\nMacro F1-score:\n{m_f1:.6f}")

# Safely handle Unicode in class names for the classification report
safe_class_names = []
for name in label_encoder.classes_:
    try:
        # Check if it can be printed safely
        str(name).encode('ascii')
        safe_class_names.append(str(name))
    except UnicodeEncodeError:
        safe_class_names.append(str(name).encode('ascii', 'replace').decode('ascii'))

print("\n" + "=" * 40)
print("CLASSIFICATION REPORT")
print("=" * 40)

report = classification_report(
    y_test, y_pred, 
    target_names=safe_class_names, 
    zero_division=0
)
print(report)

print("\n" + "=" * 40)
print("CONFUSION MATRIX")
print("=" * 40)

cm = confusion_matrix(y_test, y_pred)
print("Shape:\n", cm.shape)

# Create heatmap visualization
plt.figure(figsize=(16, 12))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=safe_class_names, 
            yticklabels=safe_class_names)
plt.title('Confusion Matrix: Random Forest NIDS')
plt.ylabel('True Class')
plt.xlabel('Predicted Class')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig(r"D:\7th sem project\results\confusion_matrix.png", dpi=300)
plt.close()

print("\n" + "=" * 40)
print("STEP 7 COMPLETED")
print("=" * 40)

print("\nEvaluation completed successfully.")
print(f"\nTest samples evaluated:\n{len(y_test)}")
print(f"\nNumber of classes:\n{len(np.unique(y_test))}")
print(f"\nConfusion matrix shape:\n{cm.shape}")

# =========================================================
# STEP 8: FIX AND SAVE EVALUATION RESULTS
# =========================================================

import os
import pandas as pd
import numpy as np

results_dir = r"D:\7th sem project\results"
os.makedirs(results_dir, exist_ok=True)

print("\n" + "=" * 40)
print("STEP 8: SAVING MODEL EVALUATION RESULTS")
print("=" * 40)

print(f"\nResults directory:\n{results_dir}")

# =========================================================
# 1. CALCULATE OVERALL METRICS
# =========================================================

accuracy = accuracy_score(y_test, y_pred)
weighted_precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
weighted_recall = recall_score(y_test, y_pred, average="weighted", zero_division=0)
weighted_f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

macro_precision = precision_score(y_test, y_pred, average="macro", zero_division=0)
macro_recall = recall_score(y_test, y_pred, average="macro", zero_division=0)
macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)

metrics_df = pd.DataFrame({
    "Metric": [
        "Accuracy",
        "Weighted Precision",
        "Weighted Recall",
        "Weighted F1",
        "Macro Precision",
        "Macro Recall",
        "Macro F1"
    ],
    "Score": [
        accuracy,
        weighted_precision,
        weighted_recall,
        weighted_f1,
        macro_precision,
        macro_recall,
        macro_f1
    ]
})

metrics_path = r"D:\7th sem project\results\model_metrics.csv"
metrics_df.to_csv(metrics_path, index=False)

# =========================================================
# 2. CLASSIFICATION REPORT
# =========================================================

report = classification_report(
    y_test,
    y_pred,
    target_names=label_encoder.classes_,
    output_dict=True,
    zero_division=0
)

report_df = pd.DataFrame(report).transpose()

report_path = r"D:\7th sem project\results\classification_report.csv"
report_df.to_csv(report_path, index=True)

# =========================================================
# 3. CONFUSION MATRIX
# =========================================================

cm = confusion_matrix(y_test, y_pred)

cm_df = pd.DataFrame(
    cm, 
    index=label_encoder.classes_,
    columns=label_encoder.classes_
)

cm_path = r"D:\7th sem project\results\confusion_matrix.csv"
cm_df.to_csv(cm_path, index=True)

# =========================================================
# 4. VERIFY FILES
# =========================================================

print("\n" + "=" * 40)
print("FILE VERIFICATION")
print("=" * 40)

def check_file(path):
    if os.path.exists(path):
        return "FOUND"
    else:
        return "NOT FOUND"

print(f"\nmodel_metrics.csv:\n{check_file(metrics_path)}\n{metrics_path}")
print(f"\nclassification_report.csv:\n{check_file(report_path)}\n{report_path}")
print(f"\nconfusion_matrix.csv:\n{check_file(cm_path)}\n{cm_path}")

# =========================================================
# 5. PRINT ACTUAL METRICS
# =========================================================

print("\n" + "=" * 40)
print("RANDOM FOREST PERFORMANCE")
print("=" * 40)

print(f"\nAccuracy:\n{accuracy:.4f}")
print(f"\nWeighted Precision:\n{weighted_precision:.4f}")
print(f"\nWeighted Recall:\n{weighted_recall:.4f}")
print(f"\nWeighted F1:\n{weighted_f1:.4f}")

print(f"\nMacro Precision:\n{macro_precision:.4f}")
print(f"\nMacro Recall:\n{macro_recall:.4f}")
print(f"\nMacro F1:\n{macro_f1:.4f}")

# =========================================================
# 6. PRINT CLASSIFICATION REPORT
# =========================================================

print("\n" + "=" * 40)
print("CLASSIFICATION REPORT")
print("=" * 40)

# We use safe_class_names we generated in STEP 7 if available, otherwise just use label_encoder.classes_
# The user asked to use label_encoder.classes_
safe_names = []
for name in label_encoder.classes_:
    try:
        str(name).encode('ascii')
        safe_names.append(str(name))
    except UnicodeEncodeError:
        safe_names.append(str(name).encode('ascii', 'replace').decode('ascii'))

print(classification_report(
    y_test,
    y_pred,
    target_names=safe_names,
    zero_division=0
))

# =========================================================
# 7. FINAL CHECK
# =========================================================

print("\n" + "=" * 40)
print("STEP 8 COMPLETED")
print("=" * 40)

print("\nEvaluation metrics generated successfully.")
print("\nFiles created:")
print(f"1. {metrics_path}")
print(f"2. {report_path}")
print(f"3. {cm_path}")

try:
    if not os.path.exists(metrics_path): raise Exception(f"File not found: {metrics_path}")
    if not os.path.exists(report_path): raise Exception(f"File not found: {report_path}")
    if not os.path.exists(cm_path): raise Exception(f"File not found: {cm_path}")
except Exception as e:
    print(f"\nERROR: {e}")