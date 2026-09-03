import os
import sys
import json
import pandas as pd
import numpy as np
import joblib
from pathlib import Path

# ==== Configuration ====
PROJECT_ROOT = Path(r"D:\\7th sem project")
RESULTS_DIR = PROJECT_ROOT / "results"
DATASET_PATH = PROJECT_ROOT / "cleaned_dataset.csv"
RF_MODEL_PATH = PROJECT_ROOT / "random_forest_model.pkl"
ET_MODEL_PATH = PROJECT_ROOT / "extra_trees_model.pkl"
SCALER_PATH = PROJECT_ROOT / "scaler.pkl"
LABEL_ENCODER_PATH = PROJECT_ROOT / "label_encoder.pkl"
FINAL_MODEL_TXT = RESULTS_DIR / "final_model.txt"

# ==== Feature list (exact order) ====
FEATURE_NAMES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Std",
]

# ==== Label mapping (as created in STEP 2) ====
LABEL_MAP = {
    "BENIGN": 0,
    "Bot": 1,
    "DDoS": 2,
    "DoS GoldenEye": 3,
    "DoS Hulk": 4,
    "DoS Slowhttptest": 5,
    "DoS slowloris": 6,
    "FTP-Patator": 7,
    "Heartbleed": 8,
    "Infiltration": 9,
    "PortScan": 10,
    "SSH-Patator": 11,
    "Web Attack � Brute Force": 12,
    "Web Attack � Sql Injection": 13,
    "Web Attack � XSS": 14,
}
REVERSE_LABEL_MAP = {v: k for k, v in LABEL_MAP.items()}

def load_selected_model():
    if not FINAL_MODEL_TXT.exists():
        raise FileNotFoundError(f"Final model indicator not found at {FINAL_MODEL_TXT}")
    selected = FINAL_MODEL_TXT.read_text().strip()
    if selected == "Random Forest":
        model_path = RF_MODEL_PATH
    elif selected == "Extra Trees":
        model_path = ET_MODEL_PATH
    else:
        raise ValueError(f"Unknown model name '{selected}' in {FINAL_MODEL_TXT}")
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found at {model_path}")
    return joblib.load(model_path), selected

def load_scaler():
    if not SCALER_PATH.exists():
        raise FileNotFoundError(f"Scaler file not found at {SCALER_PATH}")
    return joblib.load(SCALER_PATH)

def validate_features(df):
    missing = set(FEATURE_NAMES) - set(df.columns)
    extra = set(df.columns) - set(FEATURE_NAMES)
    if missing:
        raise ValueError(f"Missing required features: {sorted(missing)}")
    if extra:
        raise ValueError(f"Unexpected extra features: {sorted(extra)}")
    return df[FEATURE_NAMES]

def clean_input(df):
    if df.isnull().any().any():
        raise ValueError("Input contains NaN values.")
    if np.isinf(df.values).any():
        raise ValueError("Input contains infinite values.")
    return df

def predict_flow(flow_data, model, scaler):
    if isinstance(flow_data, dict):
        df = pd.DataFrame([flow_data])
    elif isinstance(flow_data, pd.Series):
        df = flow_data.to_frame().T
    elif isinstance(flow_data, pd.DataFrame):
        df = flow_data.copy()
    else:
        raise TypeError("flow_data must be dict, pandas Series, or DataFrame")
    df = validate_features(df)
    df = clean_input(df)
    X_scaled = scaler.transform(df)
    pred_enc = model.predict(X_scaled)[0]
    pred_label = REVERSE_LABEL_MAP.get(pred_enc, "UNKNOWN")
    is_attack = pred_label != "BENIGN"
    confidence = None
    if hasattr(model, "predict_proba"):
        try:
            probas = model.predict_proba(X_scaled)[0]
            confidence = float(probas[pred_enc] * 100)
        except Exception:
            confidence = None
    return {"prediction": pred_label, "is_attack": is_attack, "confidence": confidence}

def run_batch_test():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    sample_df = df.sample(n=10, random_state=42).reset_index(drop=True)
    actual_labels = sample_df["Label"].tolist()
    features_df = sample_df.drop(columns=["Label"])
    features_df = validate_features(features_df)
    features_df = clean_input(features_df)
    model, selected_name = load_selected_model()
    scaler = load_scaler()
    X_scaled = scaler.transform(features_df)
    pred_enc = model.predict(X_scaled)
    preds = [REVERSE_LABEL_MAP.get(enc, "UNKNOWN") for enc in pred_enc]
    confidences = []
    if hasattr(model, "predict_proba"):
        probas = model.predict_proba(X_scaled)
        for enc, prob_vec in zip(pred_enc, probas):
            confidences.append(float(prob_vec[enc] * 100))
    else:
        confidences = [None] * len(preds)
    results = pd.DataFrame({
        "Sample": range(1, 11),
        "Actual": actual_labels,
        "Predicted": preds,
        "Correct": [act == pred for act, pred in zip(actual_labels, preds)],
        "Confidence": confidences,
    })
    out_path = RESULTS_DIR / "inference_test_results.csv"
    results.to_csv(out_path, index=False)
    print("\n========================================")
    print("NIDS INFERENCE TEST")
    print("========================================")
    for _, row in results.iterrows():
        correct_str = "YES" if row["Correct"] else "NO"
        conf_str = f"{row['Confidence']:.2f}%" if row['Confidence'] is not None else "Not available"
        print(f"Sample {int(row['Sample'])}\n  Actual   : {row['Actual']}\n  Predicted: {row['Predicted']}\n  Correct  : {correct_str}\n  Confidence: {conf_str}\n")
    print(f"Results saved to: {out_path}")

if __name__ == "__main__":
    try:
        model, selected_name = load_selected_model()
        scaler = load_scaler()
        print(f"Loaded model: {selected_name}\n")
        run_batch_test()
        # Demo single‑flow prediction using first row of dataset
        demo_df = pd.read_csv(DATASET_PATH).drop(columns=["Label"]).head(1)
        demo_features = demo_df.iloc[0].to_dict()
        result = predict_flow(demo_features, model, scaler)
        print("\n=== Single Flow Prediction Demo ===")
        print(f"Prediction : {result['prediction']}")
        print(f"Is attack  : {result['is_attack']}")
        if result['confidence'] is not None:
            print(f"Confidence : {result['confidence']:.2f}%")
        else:
            print("Confidence : Not available for this model")
    except Exception as e:
        print(f"Error during inference execution: {e}")
        sys.exit(1)
