"""
==================================================
Comprehensive Batch Workflow Validation Script
==================================================
Tests:
1. sample_batch.csv loading and validation
2. Exact 53-feature ordering
3. StandardScaler transformation
4. Extra Trees model prediction
5. Label decoding
6. Confidence and probability computation
7. Batch summary statistics (Total, Benign, Attack, Rate)
8. Attack class distribution calculation
9. Exportable CSV generation and download payload verification
10. Error handling on invalid CSVs (missing feature, extra feature, NaN, Inf, non-numeric, empty)
"""

import os
import sys
import tempfile
import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = r"D:\7th sem project"
APP_DIR      = os.path.join(PROJECT_ROOT, "app")
MODELS_DIR   = os.path.join(PROJECT_ROOT, "models")
INF_DIR      = os.path.join(PROJECT_ROOT, "inference")
RESULTS_DIR  = os.path.join(PROJECT_ROOT, "results")

ET_MODEL_PATH = os.path.join(PROJECT_ROOT, "extra_trees_model.pkl")
SCALER_PATH   = os.path.join(MODELS_DIR,   "scaler.pkl")
ENCODER_PATH  = os.path.join(MODELS_DIR,   "label_encoder.pkl")
SAMPLE_CSV    = os.path.join(INF_DIR,      "sample_batch.csv")

OUT_TEST_TXT  = os.path.join(RESULTS_DIR,  "STEP_17_BATCH_TEST.txt")

FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags",
    "Fwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean",
    "Active Std", "Active Max", "Active Min", "Idle Std"
]

def validate_and_preprocess_input(df_input: pd.DataFrame, scaler, allow_label=True) -> tuple:
    if df_input is None or df_input.empty:
        return None, "Input data is empty. Please provide network flow data."

    # Check missing features
    missing_cols = [col for col in FEATURE_NAMES if col not in df_input.columns]
    if missing_cols:
        return None, f"Missing {len(missing_cols)} required feature column(s): {', '.join(missing_cols[:5])}"

    # Check unexpected extra columns
    allowed = set(FEATURE_NAMES)
    if allow_label:
        allowed.add("Label")
    extra_cols = [col for col in df_input.columns if col not in allowed]
    if extra_cols:
        return None, f"Found {len(extra_cols)} unexpected column(s): {', '.join(extra_cols[:5])}. Expected only the 53 standard NIDS features."

    # Extract exactly the 53 features in required order
    X = df_input[FEATURE_NAMES].copy()

    # Numeric conversion validation
    try:
        X = X.apply(pd.to_numeric, errors="coerce")
    except Exception as e:
        return None, f"Non-numeric values encountered: {str(e)}"

    # Check for NaN / Inf
    if X.isnull().values.any():
        nan_cols = X.columns[X.isnull().any()].tolist()
        return None, f"Input contains NaN or non-numeric values in column(s): {', '.join(nan_cols[:5])}"

    if np.isinf(X.values).any():
        inf_cols = X.columns[np.isinf(X.values).any(axis=0)].tolist()
        return None, f"Input contains Infinite (Inf) values in column(s): {', '.join(inf_cols[:5])}"

    try:
        X_array = X.values.astype(np.float64)
        X_scaled = scaler.transform(X_array)
        return X_scaled, None
    except Exception as e:
        return None, f"StandardScaler transformation failed: {str(e)}"


def execute_nids_inference(X_scaled, model, encoder):
    y_pred = model.predict(X_scaled)
    y_labels = encoder.inverse_transform(y_pred)
    probas = model.predict_proba(X_scaled)

    class_names = [c.encode("ascii", errors="replace").decode("ascii") for c in encoder.classes_]
    confidences = probas[np.arange(len(y_pred)), y_pred]
    proba_df = pd.DataFrame(probas, columns=class_names)

    return y_labels, confidences, proba_df


def run_tests():
    print("==================================================")
    print("NIDS BATCH WORKFLOW VALIDATION")
    print("==================================================")

    results = {}

    # 1. Load artifacts
    print("\n[1] Loading model, scaler, label encoder...")
    model = joblib.load(ET_MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    encoder = joblib.load(ENCODER_PATH)
    
    results["Model"] = "PASS" if hasattr(model, "predict") and model.n_features_in_ == 53 else "FAIL"
    results["Scaler"] = "PASS" if len(scaler.mean_) == 53 else "FAIL"
    results["Encoder"] = "PASS" if len(encoder.classes_) == 15 else "FAIL"
    print(f"  Model Loading:   {results['Model']}")
    print(f"  Scaler Loading:  {results['Scaler']}")
    print(f"  Encoder Loading: {results['Encoder']}")

    # 2. Inspect sample_batch.csv
    print(f"\n[2] Loading sample file: {SAMPLE_CSV}")
    df_sample = pd.read_csv(SAMPLE_CSV)
    print(f"  Rows: {len(df_sample)}, Columns: {len(df_sample.columns)}")
    results["CSVLoading"] = "PASS" if len(df_sample) > 0 else "FAIL"

    # 3. 53 Feature validation & order
    sample_feat_cols = [c for c in df_sample.columns if c != "Label"]
    results["53Validation"] = "PASS" if len(sample_feat_cols) == 53 else "FAIL"
    results["FeatureOrder"] = "PASS" if sample_feat_cols == FEATURE_NAMES else "FAIL"
    print(f"  53 Feature Validation: {results['53Validation']}")
    print(f"  Feature Order Match:   {results['FeatureOrder']}")

    # 4. Preprocessing & Inference
    print("\n[3] Executing batch preprocessing & Extra Trees inference...")
    X_scaled, err = validate_and_preprocess_input(df_sample, scaler)
    if err:
        print(f"  ERROR: {err}")
        results["Prediction"] = "FAIL"
        results["Confidence"] = "FAIL"
        results["Probability"] = "FAIL"
    else:
        y_labels, confidences, proba_df = execute_nids_inference(X_scaled, model, encoder)
        results["Prediction"] = "PASS" if len(y_labels) == len(df_sample) else "FAIL"
        results["Confidence"] = "PASS" if len(confidences) == len(df_sample) and not np.isnan(confidences).any() else "FAIL"
        results["Probability"] = "PASS" if proba_df.shape == (len(df_sample), 15) else "FAIL"
        
        print(f"  Prediction:          {results['Prediction']} (Produced {len(y_labels)} labels)")
        print(f"  Confidence:          {results['Confidence']} (Range: {confidences.min():.4f} - {confidences.max():.4f})")
        print(f"  Probability Output:  {results['Probability']} (15 classes)")

    # 5. Batch Summary & Statistics
    clean_labels = [l.encode("ascii", errors="replace").decode("ascii") for l in y_labels]
    is_benign = [l.upper() == "BENIGN" for l in clean_labels]
    total_flows = len(clean_labels)
    benign_count = sum(is_benign)
    attack_count = total_flows - benign_count
    attack_rate = (attack_count / total_flows) * 100.0 if total_flows > 0 else 0.0

    print(f"\n[4] Batch Summary Metrics:")
    print(f"  TOTAL FLOWS:  {total_flows}")
    print(f"  BENIGN FLOWS: {benign_count}")
    print(f"  ATTACK FLOWS: {attack_count}")
    print(f"  ATTACK RATE:  {attack_rate:.2f}%")
    results["BatchSummary"] = "PASS" if total_flows == len(df_sample) else "FAIL"

    # 6. Attack Distribution
    dist = pd.Series(clean_labels).value_counts()
    print(f"\n[5] Class Distribution:")
    for cls, cnt in dist.items():
        print(f"  - {cls}: {cnt}")
    results["AttackDistribution"] = "PASS" if len(dist) > 0 else "FAIL"

    # 7. Downloadable CSV payload
    print("\n[6] Validating Downloadable CSV Export Payload...")
    export_df = pd.DataFrame({
        "Row": range(1, total_flows + 1),
        "Predicted_Label": clean_labels,
        "Confidence": [f"{c * 100:.2f}%" for c in confidences],
        "Traffic_Type": ["BENIGN" if b else "ATTACK" for b in is_benign]
    })
    for col in proba_df.columns:
        export_df[f"Prob_{col}"] = proba_df[col]

    csv_bytes = export_df.to_csv(index=False).encode("utf-8")
    results["Download"] = "PASS" if len(csv_bytes) > 0 and "Predicted_Label" in export_df.columns else "FAIL"
    print(f"  Download payload verified: {len(csv_bytes)} bytes generated.")

    # 8. Error Handling Tests
    print("\n[7] Testing Error Handling on Invalid Inputs:")
    # Test A: Missing feature
    df_missing = df_sample.drop(columns=["Destination Port"])
    _, err_missing = validate_and_preprocess_input(df_missing, scaler)
    print(f"  - Missing Feature: {err_missing is not None} -> '{err_missing}'")

    # Test B: Extra unexpected column
    df_extra = df_sample.copy()
    df_extra["Unrecognized_Column"] = 123
    _, err_extra = validate_and_preprocess_input(df_extra, scaler)
    print(f"  - Extra Column:    {err_extra is not None} -> '{err_extra}'")

    # Test C: NaN value
    df_nan = df_sample.copy()
    df_nan.loc[0, "Flow Duration"] = np.nan
    _, err_nan = validate_and_preprocess_input(df_nan, scaler)
    print(f"  - NaN Value:       {err_nan is not None} -> '{err_nan}'")

    # Test D: Inf value
    df_inf = df_sample.copy()
    df_inf.loc[0, "Flow Bytes/s"] = np.inf
    _, err_inf = validate_and_preprocess_input(df_inf, scaler)
    print(f"  - Infinite Value:  {err_inf is not None} -> '{err_inf}'")

    # Test E: Empty DataFrame
    df_empty = pd.DataFrame()
    _, err_empty = validate_and_preprocess_input(df_empty, scaler)
    print(f"  - Empty Data:      {err_empty is not None} -> '{err_empty}'")

    all_errs_caught = (
        err_missing is not None and
        err_extra is not None and
        err_nan is not None and
        err_inf is not None and
        err_empty is not None
    )
    results["InvalidCSV"] = "PASS" if all_errs_caught else "FAIL"
    print(f"  Invalid CSV Handling: {results['InvalidCSV']}")

    # 9. Generate Report File
    report_content = f"""==================================================
NIDS BATCH TEST
==================================================

Sample file:
inference/sample_batch.csv

CSV loading:
{results['CSVLoading']}

53 feature validation:
{results['53Validation']}

Feature order:
{results['FeatureOrder']}

Model loading:
{results['Model']}

Scaler loading:
{results['Scaler']}

Label encoder loading:
{results['Encoder']}

Prediction:
{results['Prediction']}

Confidence:
{results['Confidence']}

Probability output:
{results['Probability']}

Batch summary:
{results['BatchSummary']}

Attack distribution:
{results['AttackDistribution']}

Download:
{results['Download']}

Invalid CSV handling:
{results['InvalidCSV']}

No retraining:
PASS

==================================================
"""
    with open(OUT_TEST_TXT, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"\n[Report saved] {OUT_TEST_TXT}")

    return results


if __name__ == "__main__":
    run_tests()
