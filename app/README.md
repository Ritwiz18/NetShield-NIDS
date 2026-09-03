# Network Intrusion Detection System — Web Dashboard

Professional, Machine Learning-based Network Intrusion Detection System (NIDS) web interface built with **Streamlit**.

## Overview
This interactive dashboard classifies network flows in real time or via batch CSV files using the trained **Extra Trees** model, **StandardScaler**, and **LabelEncoder**.

- **Model:** Extra Trees Classifier (`extra_trees_model.pkl`)
- **Features:** 53 Network Flow Features (in strict training column order)
- **Target Classes:** 15 Intrusions / Benign Traffic
- **Preprocessing:** StandardScaler (`models/scaler.pkl`)

---

## How to Start the Application

1. Open PowerShell or Command Prompt.
2. Navigate to the project root directory:
```bash
cd /d "D:\7th sem project"
```
3. Launch the Streamlit dashboard:
```bash
streamlit run app/app.py
```
4. The dashboard will automatically open in your default browser at `http://localhost:8501`.

---

## Dashboard Usage Guide

### 1. Single Flow Mode
- **Navigation:** Select `1. Single Flow` in the sidebar control panel.
- **Data Input:** Enter values across the 8 organized feature groups (Flow Information, Forward/Backward Packet Information, IATs, TCP Flags, Window/Segment, Active/Idle).
- **Presets:** Quick-load buttons available for **BENIGN** and **DDoS** network traffic patterns.
- **Run Prediction:** Click `RUN NIDS PREDICTION`.
- **Output:** Displays prominent intrusion alerts (**NORMAL TRAFFIC DETECTED** vs **POTENTIAL ATTACK DETECTED**), confidence percentage, and horizontal probability distributions for all 15 classes.

### 2. Batch CSV Mode
- **Navigation:** Select `2. Batch CSV` in the sidebar control panel.
- **Upload CSV:** Upload any network flow CSV containing the required 53 features (or click `Use Sample Batch`).
- **Run Prediction:** Click `RUN BATCH NIDS PREDICTION`.
- **Summary Metrics:** Real-time calculation of **TOTAL FLOWS**, **BENIGN FLOWS**, **ATTACK FLOWS**, and **ATTACK RATE (%)**.
- **Visualizations:** Visual charts showing Benign vs Attack ratio and attack category distribution.
- **Export:** Download comprehensive predictions and per-class probabilities via the `DOWNLOAD PREDICTIONS (CSV)` button.
