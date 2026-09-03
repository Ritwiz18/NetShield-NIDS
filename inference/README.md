# STEP 12 — NIDS Inference Pipeline

## Overview
This folder contains the inference pipeline for the NIDS project.
It loads the **final trained model** selected in STEP 11 (Extra Trees) along with
the saved **StandardScaler** and **LabelEncoder** to classify new network flow records.

---

## Required Artefacts

| File | Location | Purpose |
|------|----------|---------|
| `final_model.txt` | `results/` | Identifies which model won (Extra Trees / Random Forest) |
| `extra_trees_model.pkl` | project root | The selected model |
| `scaler.pkl` | `models/` | StandardScaler fitted on SMOTE-resampled training data |
| `label_encoder.pkl` | `models/` | Maps class integers ↔ attack names |

---

## Usage

```bash
# Quick sanity check (uses first 5 rows of cleaned_dataset.csv)
python inference/nids_inference.py --mode demo

# Predict from a CSV file
python inference/nids_inference.py --mode batch --input inference/sample_batch.csv

# Interactive single-flow prediction
python inference/nids_inference.py --mode single
```

---

## Input Format

Your CSV must contain these **53 columns** (order matters):

```
Destination Port, Flow Duration, Total Fwd Packets,
Total Length of Fwd Packets, Fwd Packet Length Max,
Fwd Packet Length Min, Fwd Packet Length Mean,
Bwd Packet Length Max, Bwd Packet Length Min,
Bwd Packet Length Mean, Bwd Packet Length Std,
Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std,
Flow IAT Max, Flow IAT Min, Fwd IAT Mean, Fwd IAT Std,
Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std,
Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Fwd Header Length,
Bwd Header Length, Bwd Packets/s, Min Packet Length,
Max Packet Length, Packet Length Mean, Packet Length Variance,
FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count,
ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count,
Down/Up Ratio, Average Packet Size, Init_Win_bytes_forward,
Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward,
Active Mean, Active Std, Active Max, Active Min, Idle Std,
Fwd URG Flags
```

A `Label` column is **optional** — if present it is used to compute accuracy.

---

## Output

**Batch mode** saves `inference/batch_predictions.csv` with:
- `True_Label` (if Label column provided)
- `Predicted_Label`
- `Predicted_Class`
- `Confidence` (probability of the predicted class)
- `P(<class>)` — one probability column per attack class

---

## 15 Supported Classes

| ID | Label |
|----|-------|
| 0 | BENIGN |
| 1 | Bot |
| 2 | DDoS |
| 3 | DoS GoldenEye |
| 4 | DoS Hulk |
| 5 | DoS Slowhttptest |
| 6 | DoS slowloris |
| 7 | FTP-Patator |
| 8 | Heartbleed |
| 9 | Infiltration |
| 10 | PortScan |
| 11 | SSH-Patator |
| 12 | Web Attack – Brute Force |
| 13 | Web Attack – Sql Injection |
| 14 | Web Attack – XSS |
