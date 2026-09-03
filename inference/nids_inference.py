"""
==================================================
STEP 12: NIDS INFERENCE / PREDICTION SYSTEM
==================================================
Network Intrusion Detection System — Inference Pipeline

Loads the final trained model selected in STEP 11,
applies the IDENTICAL preprocessing used during training,
and predicts the traffic class for new network flow records.

Usage
-----
1. Single-flow prediction (interactive):
       python nids_inference.py --mode single

2. Batch prediction from CSV file:
       python nids_inference.py --mode batch --input path/to/flows.csv

3. Demo with a synthetic sample from the training dataset:
       python nids_inference.py --mode demo

Artefact paths (adjust only if you moved files)
------------------------------------------------
MODEL_DIR  : D:\\7th sem project\\models\\
RESULTS_DIR: D:\\7th sem project\\results\\
ET_MODEL   : D:\\7th sem project\\extra_trees_model.pkl   (root — as trained)
RF_MODEL   : D:\\7th sem project\\models\\random_forest_model.pkl
SCALER     : D:\\7th sem project\\models\\scaler.pkl
ENCODER    : D:\\7th sem project\\models\\label_encoder.pkl
FINAL_SEL  : D:\\7th sem project\\results\\final_model.txt
"""

import os
import sys
import argparse
import warnings
import numpy as np
import pandas as pd
import joblib

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────
PROJECT_ROOT = r"D:\7th sem project"
MODELS_DIR   = os.path.join(PROJECT_ROOT, "models")
RESULTS_DIR  = os.path.join(PROJECT_ROOT, "results")

FINAL_MODEL_TXT = os.path.join(RESULTS_DIR, "final_model.txt")

MODEL_PATHS = {
    "Extra Trees"   : os.path.join(PROJECT_ROOT, "extra_trees_model.pkl"),
    "Random Forest" : os.path.join(MODELS_DIR,   "random_forest_model.pkl"),
}
SCALER_PATH  = os.path.join(MODELS_DIR, "scaler.pkl")
ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")

# ─────────────────────────────────────────────────────────────
# EXACT 53 FEATURES — in the same column order as cleaned_dataset.csv
# (derived from feature_importance.csv, column order preserved from training)
# ─────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "Destination Port",           # 0
    "Flow Duration",              # 1
    "Total Fwd Packets",          # 2
    "Total Length of Fwd Packets",# 3
    "Fwd Packet Length Max",      # 4
    "Fwd Packet Length Min",      # 5
    "Fwd Packet Length Mean",     # 6
    "Bwd Packet Length Max",      # 7
    "Bwd Packet Length Min",      # 8
    "Bwd Packet Length Mean",     # 9
    "Bwd Packet Length Std",      # 10
    "Flow Bytes/s",               # 11
    "Flow Packets/s",             # 12
    "Flow IAT Mean",              # 13
    "Flow IAT Std",               # 14
    "Flow IAT Max",               # 15
    "Flow IAT Min",               # 16
    "Fwd IAT Mean",               # 17
    "Fwd IAT Std",                # 18
    "Fwd IAT Min",                # 19
    "Bwd IAT Total",              # 20
    "Bwd IAT Mean",               # 21
    "Bwd IAT Std",                # 22
    "Bwd IAT Max",                # 23
    "Bwd IAT Min",                # 24
    "Fwd PSH Flags",              # 25
    "Fwd URG Flags",              # 26  <-- correct position per dataset
    "Fwd Header Length",          # 27
    "Bwd Header Length",          # 28
    "Bwd Packets/s",              # 29
    "Min Packet Length",          # 30
    "Max Packet Length",          # 31
    "Packet Length Mean",         # 32
    "Packet Length Variance",     # 33
    "FIN Flag Count",             # 34
    "SYN Flag Count",             # 35
    "RST Flag Count",             # 36
    "PSH Flag Count",             # 37
    "ACK Flag Count",             # 38
    "URG Flag Count",             # 39
    "CWE Flag Count",             # 40
    "ECE Flag Count",             # 41
    "Down/Up Ratio",              # 42
    "Average Packet Size",        # 43
    "Init_Win_bytes_forward",     # 44
    "Init_Win_bytes_backward",    # 45
    "act_data_pkt_fwd",           # 46
    "min_seg_size_forward",       # 47
    "Active Mean",                # 48
    "Active Std",                 # 49
    "Active Max",                 # 50
    "Active Min",                 # 51
    "Idle Std",                   # 52
]

NUM_FEATURES = len(FEATURE_NAMES)  # must be 53


# ─────────────────────────────────────────────────────────────
# LOAD ARTEFACTS
# ─────────────────────────────────────────────────────────────

def load_artefacts():
    """Load model, scaler and label encoder.  Returns (model, scaler, encoder, model_name)."""

    # 1. Determine which model was selected in STEP 11
    if not os.path.exists(FINAL_MODEL_TXT):
        raise FileNotFoundError(
            f"final_model.txt not found at:\n  {FINAL_MODEL_TXT}\n"
            "Please run STEP 11 first."
        )
    with open(FINAL_MODEL_TXT, "r") as fh:
        model_name = fh.read().strip()

    if model_name not in MODEL_PATHS:
        raise ValueError(
            f"Unknown model name '{model_name}' in final_model.txt.\n"
            f"Expected one of: {list(MODEL_PATHS.keys())}"
        )

    model_path = MODEL_PATHS[model_name]

    # 2. Verify all files exist
    missing = []
    for label, path in [("Model", model_path), ("Scaler", SCALER_PATH), ("Label Encoder", ENCODER_PATH)]:
        if not os.path.exists(path):
            missing.append(f"  {label}: {path}")
    if missing:
        raise FileNotFoundError(
            "The following required files are MISSING:\n" + "\n".join(missing) +
            "\n\nDo NOT retrain. Ensure the artefacts from training are in the correct locations."
        )

    print(f"Loading model      : {model_path}")
    model = joblib.load(model_path)

    print(f"Loading scaler     : {SCALER_PATH}")
    scaler = joblib.load(SCALER_PATH)

    print(f"Loading encoder    : {ENCODER_PATH}")
    encoder = joblib.load(ENCODER_PATH)

    return model, scaler, encoder, model_name


# ─────────────────────────────────────────────────────────────
# PREPROCESSING
# ─────────────────────────────────────────────────────────────

def preprocess(df_input: pd.DataFrame, scaler) -> np.ndarray:
    """
    Validate and preprocess a DataFrame of raw flow records.
    Applies the IDENTICAL feature ordering and StandardScaler transform
    used during training.
    """
    # Check for missing columns
    missing_cols = [c for c in FEATURE_NAMES if c not in df_input.columns]
    if missing_cols:
        raise ValueError(
            f"Input is missing {len(missing_cols)} required feature(s):\n"
            + "\n".join(f"  - {c}" for c in missing_cols)
        )

    # Select exactly the 53 features in the correct order
    X = df_input[FEATURE_NAMES].copy()

    # Handle any inf / nan values
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    if X.isnull().any().any():
        nan_cols = X.columns[X.isnull().any()].tolist()
        print(f"  [WARNING] NaN/Inf found in {len(nan_cols)} column(s): {nan_cols}")
        print("  Filling with column median (same strategy as training preprocessing).")
        X.fillna(X.median(), inplace=True)

    X_array = X.values.astype(np.float64)

    # Apply the same StandardScaler fitted during training
    X_scaled = scaler.transform(X_array)
    return X_scaled


# ─────────────────────────────────────────────────────────────
# PREDICT
# ─────────────────────────────────────────────────────────────

def predict(X_scaled: np.ndarray, model, encoder) -> pd.DataFrame:
    """
    Run inference and return a DataFrame with:
      - Predicted_Class (encoded integer)
      - Predicted_Label (human-readable attack name)
      - Confidence      (probability of the predicted class, if available)
      - All class probabilities
    """
    y_pred = model.predict(X_scaled)
    predicted_labels = encoder.inverse_transform(y_pred)

    result = pd.DataFrame({
        "Predicted_Class" : y_pred,
        "Predicted_Label" : predicted_labels,
    })

    # Probabilities (supported by both RF and ET)
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X_scaled)          # shape (n_samples, n_classes)
        # Confidence = probability of the predicted class
        confidence = proba[np.arange(len(y_pred)), y_pred]
        result["Confidence"] = confidence

        # Add a column per class
        class_labels = encoder.inverse_transform(np.arange(len(encoder.classes_)))
        for i, lbl in enumerate(class_labels):
            result[f"P({lbl})"] = proba[:, i]

    return result


# ─────────────────────────────────────────────────────────────
# MODES
# ─────────────────────────────────────────────────────────────

def mode_demo(model, scaler, encoder, model_name):
    """
    Build a synthetic sample from the CLEANED dataset (first 5 rows)
    and run inference to verify the pipeline end-to-end.
    """
    dataset_path = os.path.join(PROJECT_ROOT, "data", "processed", "cleaned_dataset.csv")
    if not os.path.exists(dataset_path):
        # fallback to root-level cleaned_dataset
        dataset_path = os.path.join(PROJECT_ROOT, "cleaned_dataset.csv")

    if not os.path.exists(dataset_path):
        print("[ERROR] Cannot locate cleaned_dataset.csv for demo mode.")
        return

    print(f"\nLoading first 5 rows from: {dataset_path}")
    df_sample = pd.read_csv(dataset_path, nrows=5)
    true_labels = df_sample["Label"].tolist() if "Label" in df_sample.columns else ["N/A"] * 5
    df_features = df_sample.drop(columns=["Label"], errors="ignore")

    print(f"\nRunning demo inference on {len(df_features)} sample(s)...")
    X_scaled = preprocess(df_features, scaler)
    results_df = predict(X_scaled, model, encoder)

    print("\n" + "=" * 60)
    print("DEMO RESULTS")
    print("=" * 60)
    for i, (_, row) in enumerate(results_df.iterrows()):
        print(f"\nSample {i+1}:")
        print(f"  True Label       : {true_labels[i]}")
        print(f"  Predicted Label  : {row['Predicted_Label']}")
        print(f"  Predicted Class  : {row['Predicted_Class']}")
        if "Confidence" in row:
            print(f"  Confidence       : {row['Confidence']:.4f} ({row['Confidence']*100:.2f}%)")
        correct = "[OK] CORRECT" if str(true_labels[i]) == str(row['Predicted_Label']) else "[WRONG]"
        print(f"  Match            : {correct}")


def mode_single(model, scaler, encoder, model_name):
    """Interactive mode — user types feature values one by one."""
    print("\n" + "=" * 60)
    print("SINGLE FLOW PREDICTION — Interactive Input")
    print("=" * 60)
    print(f"Enter values for each of the {NUM_FEATURES} features.")
    print("Press ENTER to use 0.0 as default.\n")

    values = {}
    for feat in FEATURE_NAMES:
        while True:
            raw = input(f"  {feat}: ").strip()
            if raw == "":
                values[feat] = 0.0
                break
            try:
                values[feat] = float(raw)
                break
            except ValueError:
                print(f"    [!] Invalid number. Try again.")

    df_input = pd.DataFrame([values])
    X_scaled = preprocess(df_input, scaler)
    results_df = predict(X_scaled, model, encoder)

    row = results_df.iloc[0]
    print("\n" + "=" * 60)
    print("PREDICTION RESULT")
    print("=" * 60)
    print(f"  Predicted Label  : {row['Predicted_Label']}")
    print(f"  Predicted Class  : {row['Predicted_Class']}")
    if "Confidence" in row:
        print(f"  Confidence       : {row['Confidence']:.4f} ({row['Confidence']*100:.2f}%)")

    # Top-3 class probabilities
    prob_cols = [c for c in results_df.columns if c.startswith("P(")]
    if prob_cols:
        probs = {c.replace("P(", "").rstrip(")"): row[c] for c in prob_cols}
        top3 = sorted(probs.items(), key=lambda x: x[1], reverse=True)[:3]
        print("\n  Top-3 class probabilities:")
        for cls, prob in top3:
            print(f"    {cls:<35} {prob:.4f} ({prob*100:.2f}%)")


def mode_batch(model, scaler, encoder, model_name, input_path: str):
    """Batch mode — read CSV, predict all rows, save results CSV."""
    if not os.path.exists(input_path):
        print(f"[ERROR] Input file not found: {input_path}")
        return

    print(f"\nLoading batch input: {input_path}")
    df_input = pd.read_csv(input_path)
    print(f"Rows loaded: {len(df_input)}")

    # If Label column exists keep it for comparison
    true_labels = df_input["Label"].tolist() if "Label" in df_input.columns else None
    df_features = df_input.drop(columns=["Label"], errors="ignore")

    X_scaled = preprocess(df_features, scaler)
    results_df = predict(X_scaled, model, encoder)

    if true_labels is not None:
        results_df.insert(0, "True_Label", true_labels)
        results_df["Match"] = results_df["True_Label"] == results_df["Predicted_Label"]

    # Save output
    out_dir  = os.path.join(PROJECT_ROOT, "inference")
    out_path = os.path.join(out_dir, "batch_predictions.csv")
    os.makedirs(out_dir, exist_ok=True)
    results_df.to_csv(out_path, index=False)

    # Summary
    print("\n" + "=" * 60)
    print("BATCH PREDICTION SUMMARY")
    print("=" * 60)
    print(f"Total flows processed : {len(results_df)}")
    print(f"Results saved to      : {out_path}")

    # Class distribution of predictions
    dist = results_df["Predicted_Label"].value_counts()
    print("\nPredicted class distribution:")
    for cls, cnt in dist.items():
        pct = cnt / len(results_df) * 100
        print(f"  {cls:<40} {cnt:>6}  ({pct:.2f}%)")

    if true_labels is not None and "Match" in results_df.columns:
        accuracy = results_df["Match"].mean()
        print(f"\nAccuracy (vs true labels): {accuracy:.6f} ({accuracy*100:.4f}%)")

    print(f"\nOutput file: {out_path}")


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NIDS Inference Pipeline — STEP 12",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  demo   Run inference on 5 rows from the cleaned dataset (quick sanity check).
  single Interactively enter feature values for one network flow.
  batch  Predict from a CSV file with the same 53 features.

Examples:
  python nids_inference.py --mode demo
  python nids_inference.py --mode single
  python nids_inference.py --mode batch --input my_flows.csv
        """
    )
    parser.add_argument("--mode",  choices=["demo", "single", "batch"], default="demo",
                        help="Inference mode (default: demo)")
    parser.add_argument("--input", type=str, default=None,
                        help="Path to input CSV (required for batch mode)")
    args = parser.parse_args()

    print("=" * 50)
    print("STEP 12: NIDS INFERENCE PIPELINE")
    print("=" * 50)
    print(f"Mode: {args.mode.upper()}")

    # Load all artefacts
    print("\n[Loading artefacts...]")
    model, scaler, encoder, model_name = load_artefacts()

    print(f"Model loaded       : {model_name}")
    print(f"Features expected  : {NUM_FEATURES}")
    print(f"Classes            : {len(encoder.classes_)}")
    # Safe-print class names (handles special chars on Windows cp1252 consoles)
    safe_classes = [c.encode('ascii', errors='replace').decode('ascii') for c in encoder.classes_]
    print(f"Class names        : {safe_classes}")

    # Verify feature count matches model
    if hasattr(model, "n_features_in_") and model.n_features_in_ != NUM_FEATURES:
        print(f"\n[WARNING] Model expects {model.n_features_in_} features but "
              f"FEATURE_NAMES has {NUM_FEATURES}. Check feature list.")

    print()

    if args.mode == "demo":
        mode_demo(model, scaler, encoder, model_name)
    elif args.mode == "single":
        mode_single(model, scaler, encoder, model_name)
    elif args.mode == "batch":
        if args.input is None:
            print("[ERROR] --input is required for batch mode.")
            sys.exit(1)
        mode_batch(model, scaler, encoder, model_name, args.input)

    print("\n" + "=" * 50)
    print("STEP 12 COMPLETED")
    print("=" * 50)
    print()
    print("What was implemented:")
    print("  - Inference pipeline that reads final_model.txt")
    print("    and automatically loads the correct model")
    print("  - Identical preprocessing: 53-feature ordering + StandardScaler")
    print("  - Prediction with class probabilities (predict_proba)")
    print("  - Label decoding via the saved LabelEncoder")
    print("  - 3 modes: demo / single-flow / batch CSV")
    print()
    print("Files created:")
    print("  D:\\7th sem project\\inference\\nids_inference.py")
    print()
    print("Files reused:")
    print(f"  D:\\7th sem project\\results\\final_model.txt    -> {model_name}")
    print(f"  {MODEL_PATHS[model_name]}")
    print(f"  {SCALER_PATH}")
    print(f"  {ENCODER_PATH}")
    print()
    print("Model being used    :", model_name)
    print("Features expected   :", NUM_FEATURES)
    print("Feature order       : see FEATURE_NAMES list in this file")
    print("How prediction works:")
    print("  1. Input CSV / interactive values collected")
    print("  2. 53 features selected in exact training order")
    print("  3. Inf/NaN handled (median fill)")
    print("  4. StandardScaler.transform() applied (same scaler from training)")
    print("  5. model.predict()        -> encoded class integer")
    print("  6. model.predict_proba()  -> confidence score per class")
    print("  7. LabelEncoder.inverse_transform() -> human-readable attack name")
    print()
    print("Awaiting STEP 13 instruction.")
    print("=" * 50)


if __name__ == "__main__":
    main()
